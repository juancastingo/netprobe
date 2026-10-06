use crate::report::ProbeReport;
use colored::*;

pub fn print_report(report: &ProbeReport, as_json: bool) {
    if as_json {
        let json_str = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
        println!("{}", json_str);
        return;
    }

    println!();
    println!("{}", "═".repeat(64).cyan());
    println!(
        " {} {}",
        "⚡ NetProbe Diagnostics:".bold().white(),
        report.target.full_url.bold().cyan()
    );
    println!("{}", "═".repeat(64).cyan());

    // Target Overview
    println!(
        " Target Host:   {} (Port: {})",
        report.target.host.bold(),
        report.target.port.to_string().yellow()
    );
    println!(
        " Protocol:      {}",
        if report.target.is_tls {
            "HTTPS / TLS".green()
        } else {
            "Plain HTTP".yellow()
        }
    );
    println!(" Timestamp:     {}", report.timestamp.dimmed());
    println!("{}", "─".repeat(64).cyan());

    // Stages Summary
    println!("{}", " STAGE WATERFALL:".bold());

    let mut stages = Vec::new();
    if let Some(ref dns) = report.dns {
        stages.push((
            "1. DNS Resolution",
            dns.duration_ms,
            dns.success,
            dns.error.as_deref(),
        ));
    }
    if let Some(ref tcp) = report.tcp {
        stages.push((
            "2. TCP Handshake",
            tcp.duration_ms,
            tcp.success,
            tcp.error.as_deref(),
        ));
    }
    if let Some(ref tls) = report.tls {
        stages.push((
            "3. TLS Handshake",
            tls.duration_ms,
            tls.success,
            tls.error.as_deref(),
        ));
    }
    if let Some(ref http) = report.http {
        stages.push((
            "4. HTTP Response",
            http.duration_ms,
            http.success,
            http.error.as_deref(),
        ));
    }

    let max_dur = stages
        .iter()
        .map(|(_, dur, _, _)| *dur)
        .fold(0.0f64, |a, b| a.max(b))
        .max(1.0);

    for (name, dur, success, err) in &stages {
        let status_mark = if *success {
            "✓".bold().green()
        } else {
            "✗".bold().red()
        };

        let bar_width = ((*dur / max_dur) * 20.0).round() as usize;
        let bar = "█".repeat(bar_width.clamp(1, 20));

        let dur_str = format!("{:>7.2} ms", dur);
        println!(
            "  {} {:<18} {} {:<20} {}",
            status_mark,
            name.bold(),
            dur_str.yellow(),
            bar.cyan(),
            if *success {
                "".normal()
            } else {
                format!("(FAILED: {})", err.unwrap_or("error")).red()
            }
        );
    }

    let total_str = format!("{:>7.2} ms", report.total_duration_ms);
    println!(
        "    {:<18} {}",
        "Total Latency:".bold(),
        total_str.bold().green()
    );
    println!("{}", "─".repeat(64).cyan());

    // Detailed Stage Breakdown
    println!("{}", " STAGE DETAILS:".bold());

    // DNS details
    if let Some(ref dns) = report.dns {
        if dns.success {
            let mut ips = Vec::new();
            if !dns.resolved_ipv4.is_empty() {
                ips.push(format!("IPv4: {}", dns.resolved_ipv4.join(", ")));
            }
            if !dns.resolved_ipv6.is_empty() {
                ips.push(format!("IPv6: {}", dns.resolved_ipv6.join(", ")));
            }
            let selected = dns.selected_ip.as_deref().unwrap_or("none");
            println!(
                "  • DNS:  Selected {}  [{}]",
                selected.bold().green(),
                ips.join(" | ")
            );
        }
    }

    // TCP details
    if let Some(ref tcp) = report.tcp {
        if tcp.success {
            let local = tcp.local_addr.as_deref().unwrap_or("unknown");
            println!(
                "  • TCP:  Connected to {} (Local: {})",
                tcp.remote_addr.bold().green(),
                local.dimmed()
            );
        }
    }

    // TLS details
    if let Some(ref tls) = report.tls {
        if tls.success {
            let proto = tls.protocol_version.as_deref().unwrap_or("Unknown");
            let cipher = tls.cipher_suite.as_deref().unwrap_or("Unknown");
            let alpn = tls.alpn_negotiated.as_deref().unwrap_or("none");
            println!(
                "  • TLS:  {} | Cipher: {} | ALPN: {}",
                proto.bold().green(),
                cipher.dimmed(),
                alpn.yellow()
            );

            if let Some(ref cert) = tls.peer_certificate {
                let subject = cert.subject_cn.as_deref().unwrap_or("None");
                let issuer = cert
                    .issuer_org
                    .as_deref()
                    .or(cert.issuer_cn.as_deref())
                    .unwrap_or("Unknown");

                let days_colored = if cert.is_expired {
                    format!("EXPIRED ({} days ago)", -cert.days_until_expiration)
                        .bold()
                        .red()
                } else if cert.days_until_expiration < 14 {
                    format!("{} days (EXPIRES SOON)", cert.days_until_expiration)
                        .bold()
                        .yellow()
                } else {
                    format!("{} days remaining", cert.days_until_expiration).green()
                };

                println!(
                    "    Cert: Subject: {}, Issuer: {}",
                    subject.bold(),
                    issuer.dimmed()
                );
                println!(
                    "    Valid: {} to {} [{}]",
                    cert.not_before.dimmed(),
                    cert.not_after.dimmed(),
                    days_colored
                );
            }
        }
    }

    // HTTP details
    if let Some(ref http) = report.http {
        let status_color = if http.status_code < 300 {
            http.status_code.to_string().bold().green()
        } else if http.status_code < 400 {
            http.status_code.to_string().bold().yellow()
        } else {
            http.status_code.to_string().bold().red()
        };

        let ttfb_str = format!("{:.2} ms", http.ttfb_ms);
        println!(
            "  • HTTP: {} {} (TTFB: {})",
            status_color,
            http.status_text.bold(),
            ttfb_str.yellow()
        );

        if let Some(ref loc) = http.redirect_location {
            println!("    Redirect Location: {}", loc.bold().yellow());
        }

        if let Some(len) = http.content_length {
            println!("    Content Length:    {} bytes", len.to_string().dimmed());
        }
    }

    // Diagnostics / Remediation Box if failure occurred
    if let Some(ref diag) = report.diagnosis {
        println!("{}", "─".repeat(64).red());
        println!(
            " {} {}",
            "❌ DIAGNOSTIC FAILURE:".bold().red(),
            diag.failed_stage.bold().white()
        );
        println!(" Summary:    {}", diag.summary.yellow());
        println!(" Root Cause: {}", diag.root_cause.white());
        println!(" Remediation Actions:");
        for rem in &diag.remediation {
            println!("   {} {}", "→".cyan(), rem);
        }
    }

    println!("{}", "═".repeat(64).cyan());
    println!();
}
