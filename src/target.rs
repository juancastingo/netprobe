use anyhow::{anyhow, Result};
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub raw_input: String,
    pub host: String,
    pub port: u16,
    pub is_tls: bool,
    pub path: String,
    pub query: Option<String>,
    pub is_ip: bool,
    pub ip_literal: Option<IpAddr>,
}

struct ParsedHostParts {
    host: String,
    port: Option<u16>,
    path: Option<String>,
    query: Option<String>,
}

impl Target {
    pub fn parse(input: &str, force_no_tls: bool) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Target cannot be empty"));
        }

        // If user input already looks like a URL with scheme
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let parsed_url =
                Url::parse(trimmed).map_err(|e| anyhow!("Invalid URL format: {}", e))?;
            let host_str = parsed_url
                .host_str()
                .ok_or_else(|| anyhow!("URL missing host"))?
                .to_string();

            let is_tls = if force_no_tls {
                false
            } else {
                parsed_url.scheme() == "https"
            };

            let port = parsed_url.port().unwrap_or(if is_tls { 443 } else { 80 });
            let is_ip = host_str.parse::<IpAddr>().is_ok();
            let ip_literal = host_str.parse::<IpAddr>().ok();
            let path = if parsed_url.path().is_empty() {
                "/".to_string()
            } else {
                parsed_url.path().to_string()
            };
            let query = parsed_url.query().map(|q| q.to_string());

            return Ok(Self {
                raw_input: input.to_string(),
                host: host_str,
                port,
                is_tls,
                path,
                query,
                is_ip,
                ip_literal,
            });
        }

        // Check if it's an IP literal or host with port like "127.0.0.1:8080" or "example.com:8443"
        // Handle IPv6 bracket notation "[::1]:8080"
        let parts = parse_host_port_path(trimmed)?;

        let ip_literal = parts.host.parse::<IpAddr>().ok();
        let is_ip = ip_literal.is_some();

        let is_tls = if force_no_tls {
            false
        } else {
            // Default to TLS unless port 80 or explicitly non-TLS
            parts.port != Some(80)
        };

        let default_port = if is_tls { 443 } else { 80 };
        let port = parts.port.unwrap_or(default_port);

        let path = parts.path.unwrap_or_else(|| "/".to_string());

        Ok(Self {
            raw_input: input.to_string(),
            host: parts.host,
            port,
            is_tls,
            path,
            query: parts.query,
            is_ip,
            ip_literal,
        })
    }

    pub fn full_url(&self) -> String {
        let scheme = if self.is_tls { "https" } else { "http" };
        let default_port = if self.is_tls { 443 } else { 80 };
        let host_formatted = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        let mut out = if self.port == default_port {
            format!("{}://{}{}", scheme, host_formatted, self.path)
        } else {
            format!("{}://{}:{}{}", scheme, host_formatted, self.port, self.path)
        };

        if let Some(ref q) = self.query {
            out.push('?');
            out.push_str(q);
        }
        out
    }
}

fn parse_host_port_path(input: &str) -> Result<ParsedHostParts> {
    // Separate path/query if present, e.g. "example.com/api/test?v=1"
    let (host_port_part, path_and_query) = match input.find('/') {
        Some(idx) => {
            let (hp, pq) = input.split_at(idx);
            (hp, Some(pq))
        }
        None => (input, None),
    };

    let (path_part, query_part) = if let Some(pq) = path_and_query {
        match pq.find('?') {
            Some(q_idx) => {
                let (p, q) = pq.split_at(q_idx);
                (Some(p.to_string()), Some(q[1..].to_string()))
            }
            None => (Some(pq.to_string()), None),
        }
    } else {
        (None, None)
    };

    // Parse host and port
    if host_port_part.starts_with('[') {
        // IPv6 bracketed: [::1] or [::1]:8080
        if let Some(close_bracket) = host_port_part.find(']') {
            let host = host_port_part[1..close_bracket].to_string();
            let after_bracket = &host_port_part[close_bracket + 1..];
            let port = if let Some(colon_idx) = after_bracket.find(':') {
                let port_str = &after_bracket[colon_idx + 1..];
                Some(
                    port_str
                        .parse::<u16>()
                        .map_err(|_| anyhow!("Invalid port number: {}", port_str))?,
                )
            } else {
                None
            };
            return Ok(ParsedHostParts {
                host,
                port,
                path: path_part,
                query: query_part,
            });
        } else {
            return Err(anyhow!("Unclosed IPv6 bracket in target"));
        }
    }

    if let Some(colon_idx) = host_port_part.rfind(':') {
        let (h, p_str) = host_port_part.split_at(colon_idx);
        let port_candidate = &p_str[1..];
        if let Ok(port) = port_candidate.parse::<u16>() {
            return Ok(ParsedHostParts {
                host: h.to_string(),
                port: Some(port),
                path: path_part,
                query: query_part,
            });
        }
    }

    Ok(ParsedHostParts {
        host: host_port_part.to_string(),
        port: None,
        path: path_part,
        query: query_part,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_only() {
        let t = Target::parse("example.com", false).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert!(t.is_tls);
        assert_eq!(t.path, "/");
        assert!(!t.is_ip);
    }

    #[test]
    fn test_parse_domain_with_port() {
        let t = Target::parse("example.com:8443", false).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8443);
        assert!(t.is_tls);
    }

    #[test]
    fn test_parse_http_url() {
        let t = Target::parse("http://example.com/api?debug=true", false).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 80);
        assert!(!t.is_tls);
        assert_eq!(t.path, "/api");
        assert_eq!(t.query, Some("debug=true".to_string()));
    }

    #[test]
    fn test_parse_ipv4_literal() {
        let t = Target::parse("1.1.1.1:80", false).unwrap();
        assert_eq!(t.host, "1.1.1.1");
        assert_eq!(t.port, 80);
        assert!(!t.is_tls);
        assert!(t.is_ip);
    }

    #[test]
    fn test_parse_ipv6_bracketed() {
        let t = Target::parse("[::1]:3000/health", false).unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 3000);
        assert_eq!(t.path, "/health");
        assert!(t.is_ip);
    }
}
