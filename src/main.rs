use clap::Parser;
use std::process::exit;
use std::time::Duration;

use netprobe::cli::CliArgs;
use netprobe::{print_report, run_probe, IpFamilyPreference, MaxStage, ProbeOptions};

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    let ip_preference = if args.ipv4 {
        IpFamilyPreference::Ipv4Only
    } else if args.ipv6 {
        IpFamilyPreference::Ipv6Only
    } else {
        IpFamilyPreference::Any
    };

    let max_stage = if args.dns_only {
        MaxStage::DnsOnly
    } else if args.tcp_only {
        MaxStage::TcpOnly
    } else if args.tls_only {
        MaxStage::TlsOnly
    } else {
        MaxStage::FullHttp
    };

    let mut custom_headers = Vec::new();
    for h in &args.headers {
        if let Some((k, v)) = h.split_once(':') {
            custom_headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            eprintln!(
                "Warning: ignoring malformed header '{}' (must be 'Name: Value')",
                h
            );
        }
    }

    let options = ProbeOptions {
        ip_preference,
        force_no_tls: args.no_tls,
        insecure_tls: args.insecure,
        http_method: args.method,
        custom_headers,
        connect_timeout: Duration::from_millis(args.connect_timeout),
        total_timeout: Duration::from_millis(args.timeout),
        max_stage,
    };

    let report = run_probe(&args.target, options).await;
    let is_success = report.success;

    print_report(&report, args.json);

    if !is_success {
        exit(1);
    }
}
