use crate::report::DiagnosisReport;

pub fn analyze_failure(failed_stage: &str, error_message: &str) -> DiagnosisReport {
    let err_lower = error_message.to_lowercase();

    match failed_stage {
        "DNS" => {
            if err_lower.contains("no address found")
                || err_lower.contains("failed to lookup")
                || err_lower.contains("name or service not known")
                || err_lower.contains("not found")
            {
                DiagnosisReport {
                    failed_stage: "DNS Resolution".to_string(),
                    summary: "The target hostname could not be resolved by your DNS resolver.".to_string(),
                    root_cause: "The domain name does not exist (NXDOMAIN), has expired DNS records, or is misspelled.".to_string(),
                    remediation: vec![
                        "Verify that the domain spelling is correct.".to_string(),
                        "Check if the domain's DNS A/AAAA records are active using `dig` or `nslookup`.".to_string(),
                        "Test using an alternate DNS resolver like Cloudflare (1.1.1.1) or Google (8.8.8.8).".to_string(),
                    ],
                }
            } else if err_lower.contains("timed out") {
                DiagnosisReport {
                    failed_stage: "DNS Resolution".to_string(),
                    summary: "DNS query timed out before receiving a response from the configured nameserver.".to_string(),
                    root_cause: "Configured DNS server is unreachable or port 53 (UDP/TCP) is blocked by firewall.".to_string(),
                    remediation: vec![
                        "Check local network connectivity and default gateway.".to_string(),
                        "Verify `/etc/resolv.conf` or system DNS settings.".to_string(),
                    ],
                }
            } else if err_lower.contains("ip family") {
                DiagnosisReport {
                    failed_stage: "DNS Resolution".to_string(),
                    summary: "Host has no IP records matching the requested address family (-4 or -6).".to_string(),
                    root_cause: "You forced IPv4 or IPv6, but the domain does not publish records for that protocol.".to_string(),
                    remediation: vec![
                        "Run without `-4` or `-6` to allow resolving any available address family.".to_string(),
                    ],
                }
            } else {
                DiagnosisReport {
                    failed_stage: "DNS Resolution".to_string(),
                    summary: "DNS resolution encountered an error.".to_string(),
                    root_cause: error_message.to_string(),
                    remediation: vec!["Check network connection and DNS configuration.".to_string()],
                }
            }
        }
        "TCP" => {
            if err_lower.contains("connection refused") {
                DiagnosisReport {
                    failed_stage: "TCP Connection".to_string(),
                    summary: "The target host actively rejected the connection (RST packet received).".to_string(),
                    root_cause: "No service is listening on the target port, or the service is bound strictly to `127.0.0.1` instead of `0.0.0.0`.".to_string(),
                    remediation: vec![
                        "Confirm that the target service process is running and listening on the expected port.".to_string(),
                        "Check if the server is bound strictly to localhost (`127.0.0.1`) rather than public interfaces (`0.0.0.0`).".to_string(),
                        "Verify that you specified the correct port number.".to_string(),
                    ],
                }
            } else if err_lower.contains("timed out") {
                DiagnosisReport {
                    failed_stage: "TCP Connection".to_string(),
                    summary: "TCP SYN packet timed out without receiving a SYN-ACK acknowledgment.".to_string(),
                    root_cause: "A firewall (cloud security group, iptables, or network router) is silently dropping traffic on this port, or the destination IP is unreachable.".to_string(),
                    remediation: vec![
                        "Check cloud firewall / security group rules (e.g. AWS Security Groups, UFW) allowing inbound traffic on this port.".to_string(),
                        "Verify routing between client and target host.".to_string(),
                        "Increase timeout using `--timeout` if connecting across high-latency links.".to_string(),
                    ],
                }
            } else if err_lower.contains("network unreachable")
                || err_lower.contains("host unreachable")
            {
                DiagnosisReport {
                    failed_stage: "TCP Connection".to_string(),
                    summary: "No network route exists to reach the target IP address.".to_string(),
                    root_cause:
                        "Local network interface is down or routing table has no default gateway."
                            .to_string(),
                    remediation: vec![
                        "Verify local network interface status and IP assignment.".to_string(),
                        "Check default gateway routes using `ip route` or `netstat -rn`."
                            .to_string(),
                    ],
                }
            } else {
                DiagnosisReport {
                    failed_stage: "TCP Connection".to_string(),
                    summary: "TCP handshake could not be established.".to_string(),
                    root_cause: error_message.to_string(),
                    remediation: vec!["Verify network routing and firewall settings.".to_string()],
                }
            }
        }
        "TLS" => {
            if err_lower.contains("expired") || err_lower.contains("not valid") {
                DiagnosisReport {
                    failed_stage: "TLS / SSL Handshake".to_string(),
                    summary: "The remote server presented an expired or not-yet-valid certificate.".to_string(),
                    root_cause: "The TLS certificate expired or the local/remote system clock is drifted.".to_string(),
                    remediation: vec![
                        "Renew the SSL/TLS certificate for the domain (e.g. `certbot renew`).".to_string(),
                        "Check the current system clock on your local machine.".to_string(),
                        "Use `-k` / `--insecure` to temporarily bypass verification if testing in non-production.".to_string(),
                    ],
                }
            } else if err_lower.contains("unrecognized name")
                || err_lower.contains("name mismatch")
                || err_lower.contains("server name")
            {
                DiagnosisReport {
                    failed_stage: "TLS / SSL Handshake".to_string(),
                    summary: "The certificate does not match the requested hostname.".to_string(),
                    root_cause: "The domain name you connected to is not listed in the certificate's Subject Alternative Names (SANs).".to_string(),
                    remediation: vec![
                        "Verify the domain name used in the request.".to_string(),
                        "Check the SAN entries on the certificate to see valid hostnames.".to_string(),
                        "Use `-k` / `--insecure` if accessing by raw IP or development alias.".to_string(),
                    ],
                }
            } else if err_lower.contains("unknown issuer")
                || err_lower.contains("invalid cert")
                || err_lower.contains("untrusted")
            {
                DiagnosisReport {
                    failed_stage: "TLS / SSL Handshake".to_string(),
                    summary: "The certificate authority (CA) is not trusted by the WebPKI trust store.".to_string(),
                    root_cause: "The server uses a self-signed certificate, an internal corporate CA, or is missing intermediate certificates in the bundle.".to_string(),
                    remediation: vec![
                        "Ensure the server config includes the full certificate chain (including intermediate CAs).".to_string(),
                        "Use `-k` / `--insecure` if testing self-signed certificates in staging/development.".to_string(),
                    ],
                }
            } else {
                DiagnosisReport {
                    failed_stage: "TLS / SSL Handshake".to_string(),
                    summary: "TLS handshake negotiation failed.".to_string(),
                    root_cause: error_message.to_string(),
                    remediation: vec![
                        "Verify that the remote port actually speaks TLS/HTTPS (not plain HTTP).".to_string(),
                        "Check for TLS version or cipher suite incompatibilities.".to_string(),
                        "Test with `--insecure` to isolate certificate verification errors from TLS protocol errors.".to_string(),
                    ],
                }
            }
        }
        "HTTP" => {
            if err_lower.contains("502 bad gateway") {
                DiagnosisReport {
                    failed_stage: "HTTP Request".to_string(),
                    summary: "Server returned HTTP 502 Bad Gateway.".to_string(),
                    root_cause: "The reverse proxy (Nginx, Envoy, Cloudflare, ALB) connected to the endpoint, but the upstream application backend is down or returned an invalid response.".to_string(),
                    remediation: vec![
                        "Check backend application logs and process status on the server.".to_string(),
                        "Verify the upstream proxy configuration (target host, port, socket).".to_string(),
                    ],
                }
            } else if err_lower.contains("504 gateway timeout") {
                DiagnosisReport {
                    failed_stage: "HTTP Request".to_string(),
                    summary: "Server returned HTTP 504 Gateway Timeout.".to_string(),
                    root_cause: "The reverse proxy reached the upstream application, but the application took longer to respond than the proxy's read timeout.".to_string(),
                    remediation: vec![
                        "Check for slow database queries or hangs in the backend service.".to_string(),
                        "Increase proxy timeout or optimize backend request handling.".to_string(),
                    ],
                }
            } else if err_lower.contains("503 service unavailable") {
                DiagnosisReport {
                    failed_stage: "HTTP Request".to_string(),
                    summary: "Server returned HTTP 503 Service Unavailable.".to_string(),
                    root_cause: "The server is currently overloaded or undergoing scheduled maintenance.".to_string(),
                    remediation: vec![
                        "Inspect application resource utilization (CPU, memory, database connection pool).".to_string(),
                        "Check if a maintenance window is active.".to_string(),
                    ],
                }
            } else if err_lower.contains("404 not found") {
                DiagnosisReport {
                    failed_stage: "HTTP Request".to_string(),
                    summary: "The requested path was not found on the server.".to_string(),
                    root_cause: "The HTTP URL path or route is not registered on the web server."
                        .to_string(),
                    remediation: vec![
                        "Verify that the URL path and query parameters are spelled correctly."
                            .to_string(),
                    ],
                }
            } else if err_lower.contains("401 unauthorized") || err_lower.contains("403 forbidden")
            {
                DiagnosisReport {
                    failed_stage: "HTTP Request".to_string(),
                    summary: "Authentication or authorization failure.".to_string(),
                    root_cause: "The endpoint requires valid credentials or your client IP is blocked by an access control list.".to_string(),
                    remediation: vec![
                        "Provide credentials via custom headers (`-H \"Authorization: Bearer <token>\"`).".to_string(),
                        "Verify client permissions on the API or resource.".to_string(),
                    ],
                }
            } else {
                DiagnosisReport {
                    failed_stage: "HTTP Request".to_string(),
                    summary: "HTTP stage failed.".to_string(),
                    root_cause: error_message.to_string(),
                    remediation: vec![
                        "Inspect server application logs for error details.".to_string()
                    ],
                }
            }
        }
        _ => DiagnosisReport {
            failed_stage: failed_stage.to_string(),
            summary: "Diagnostic probe failed.".to_string(),
            root_cause: error_message.to_string(),
            remediation: vec!["Review the command parameters and server status.".to_string()],
        },
    }
}
