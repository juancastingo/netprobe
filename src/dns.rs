use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::lookup_host;

use crate::report::DnsStageReport;
use crate::target::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamilyPreference {
    Any,
    Ipv4Only,
    Ipv6Only,
}

pub struct DnsResolution {
    pub report: DnsStageReport,
    pub selected_ip: IpAddr,
    pub selected_socket_addr: SocketAddr,
}

pub async fn resolve_target(target: &Target, ip_pref: IpFamilyPreference) -> Result<DnsResolution> {
    // If the target is already an IP address, we don't need network DNS lookup
    if let Some(ip) = target.ip_literal {
        let is_match = match ip_pref {
            IpFamilyPreference::Any => true,
            IpFamilyPreference::Ipv4Only => ip.is_ipv4(),
            IpFamilyPreference::Ipv6Only => ip.is_ipv6(),
        };

        if !is_match {
            return Err(anyhow!(
                "Target IP {} does not match requested IP family constraint",
                ip
            ));
        }

        let socket_addr = SocketAddr::new(ip, target.port);
        let ipv4_list = if ip.is_ipv4() {
            vec![ip.to_string()]
        } else {
            vec![]
        };
        let ipv6_list = if ip.is_ipv6() {
            vec![ip.to_string()]
        } else {
            vec![]
        };

        let report = DnsStageReport {
            duration_ms: 0.0,
            resolved_ipv4: ipv4_list,
            resolved_ipv6: ipv6_list,
            selected_ip: Some(ip.to_string()),
            success: true,
            error: None,
        };

        return Ok(DnsResolution {
            report,
            selected_ip: ip,
            selected_socket_addr: socket_addr,
        });
    }

    let start = Instant::now();
    let host_port = format!("{}:{}", target.host, target.port);

    let addrs_result = lookup_host(&host_port).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let addrs = match addrs_result {
        Ok(iter) => iter.collect::<Vec<SocketAddr>>(),
        Err(e) => {
            return Err(anyhow!(
                "DNS resolution failed for '{}': {}",
                target.host,
                e
            ));
        }
    };

    if addrs.is_empty() {
        return Err(anyhow!("No IP addresses found for host '{}'", target.host));
    }

    let mut ipv4_addrs = Vec::new();
    let mut ipv6_addrs = Vec::new();

    for sa in &addrs {
        match sa.ip() {
            IpAddr::V4(v4) => {
                let s = v4.to_string();
                if !ipv4_addrs.contains(&s) {
                    ipv4_addrs.push(s);
                }
            }
            IpAddr::V6(v6) => {
                let s = v6.to_string();
                if !ipv6_addrs.contains(&s) {
                    ipv6_addrs.push(s);
                }
            }
        }
    }

    let filtered: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|sa| match ip_pref {
            IpFamilyPreference::Any => true,
            IpFamilyPreference::Ipv4Only => sa.is_ipv4(),
            IpFamilyPreference::Ipv6Only => sa.is_ipv6(),
        })
        .collect();

    if filtered.is_empty() {
        let msg = match ip_pref {
            IpFamilyPreference::Ipv4Only => {
                format!("No IPv4 (A) records resolved for '{}'", target.host)
            }
            IpFamilyPreference::Ipv6Only => {
                format!("No IPv6 (AAAA) records resolved for '{}'", target.host)
            }
            IpFamilyPreference::Any => format!("No IP records found for '{}'", target.host),
        };
        return Err(anyhow!(msg));
    }

    let selected_socket_addr = filtered[0];
    let selected_ip = selected_socket_addr.ip();

    let report = DnsStageReport {
        duration_ms: (elapsed_ms * 100.0).round() / 100.0,
        resolved_ipv4: ipv4_addrs,
        resolved_ipv6: ipv6_addrs,
        selected_ip: Some(selected_ip.to_string()),
        success: true,
        error: None,
    };

    Ok(DnsResolution {
        report,
        selected_ip,
        selected_socket_addr,
    })
}
