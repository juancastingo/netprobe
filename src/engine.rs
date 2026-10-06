use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::diagnosis::analyze_failure;
use crate::dns::{resolve_target, IpFamilyPreference};
use crate::http::{execute_http_probe, HttpRequestOptions, StreamWrapper};
use crate::report::{ProbeReport, TargetReport};
use crate::target::Target;
use crate::tcp::connect_tcp;
use crate::tls::establish_tls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxStage {
    DnsOnly,
    TcpOnly,
    TlsOnly,
    FullHttp,
}

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub ip_preference: IpFamilyPreference,
    pub force_no_tls: bool,
    pub insecure_tls: bool,
    pub http_method: String,
    pub custom_headers: Vec<(String, String)>,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub max_stage: MaxStage,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            ip_preference: IpFamilyPreference::Any,
            force_no_tls: false,
            insecure_tls: false,
            http_method: "GET".to_string(),
            custom_headers: Vec::new(),
            connect_timeout: Duration::from_millis(5000),
            total_timeout: Duration::from_millis(15000),
            max_stage: MaxStage::FullHttp,
        }
    }
}

pub async fn run_probe(target_input: &str, options: ProbeOptions) -> ProbeReport {
    let overall_start = Instant::now();

    let target_parsed = Target::parse(target_input, options.force_no_tls);
    let target = match target_parsed {
        Ok(t) => t,
        Err(e) => {
            let err_msg = e.to_string();
            let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
            return ProbeReport {
                target: TargetReport {
                    input: target_input.to_string(),
                    host: "".to_string(),
                    port: 0,
                    is_tls: false,
                    path: "".to_string(),
                    full_url: target_input.to_string(),
                },
                timestamp: current_timestamp(),
                total_duration_ms: (total_ms * 100.0).round() / 100.0,
                success: false,
                dns: None,
                tcp: None,
                tls: None,
                http: None,
                diagnosis: Some(analyze_failure("Input", &err_msg)),
            };
        }
    };

    let target_report = TargetReport {
        input: target.raw_input.clone(),
        host: target.host.clone(),
        port: target.port,
        is_tls: target.is_tls,
        path: target.path.clone(),
        full_url: target.full_url(),
    };

    // Stage 1: DNS
    let dns_start = Instant::now();
    let dns_result = resolve_target(&target, options.ip_preference).await;
    let dns_elapsed_ms = (dns_start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    let (dns_report, selected_socket_addr) = match dns_result {
        Ok(res) => (res.report, res.selected_socket_addr),
        Err(e) => {
            let err_msg = e.to_string();
            let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
            return ProbeReport {
                target: target_report,
                timestamp: current_timestamp(),
                total_duration_ms: (total_ms * 100.0).round() / 100.0,
                success: false,
                dns: Some(crate::report::DnsStageReport {
                    duration_ms: dns_elapsed_ms,
                    resolved_ipv4: vec![],
                    resolved_ipv6: vec![],
                    selected_ip: None,
                    success: false,
                    error: Some(err_msg.clone()),
                }),
                tcp: None,
                tls: None,
                http: None,
                diagnosis: Some(analyze_failure("DNS", &err_msg)),
            };
        }
    };

    if options.max_stage == MaxStage::DnsOnly {
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        return ProbeReport {
            target: target_report,
            timestamp: current_timestamp(),
            total_duration_ms: (total_ms * 100.0).round() / 100.0,
            success: true,
            dns: Some(dns_report),
            tcp: None,
            tls: None,
            http: None,
            diagnosis: None,
        };
    }

    // Stage 2: TCP
    let tcp_start = Instant::now();
    let tcp_result = connect_tcp(selected_socket_addr, options.connect_timeout).await;
    let tcp_elapsed_ms = (tcp_start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    let (tcp_stream, tcp_report) = match tcp_result {
        Ok(c) => (c.stream, c.report),
        Err(e) => {
            let err_msg = e.to_string();
            let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
            return ProbeReport {
                target: target_report,
                timestamp: current_timestamp(),
                total_duration_ms: (total_ms * 100.0).round() / 100.0,
                success: false,
                dns: Some(dns_report),
                tcp: Some(crate::report::TcpStageReport {
                    duration_ms: tcp_elapsed_ms,
                    remote_addr: selected_socket_addr.to_string(),
                    local_addr: None,
                    success: false,
                    error: Some(err_msg.clone()),
                }),
                tls: None,
                http: None,
                diagnosis: Some(analyze_failure("TCP", &err_msg)),
            };
        }
    };

    if options.max_stage == MaxStage::TcpOnly {
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        return ProbeReport {
            target: target_report,
            timestamp: current_timestamp(),
            total_duration_ms: (total_ms * 100.0).round() / 100.0,
            success: true,
            dns: Some(dns_report),
            tcp: Some(tcp_report),
            tls: None,
            http: None,
            diagnosis: None,
        };
    }

    // Stage 3: TLS (if HTTPS)
    let tls_start = Instant::now();
    let (stream_wrapper, tls_report) = if target.is_tls {
        let tls_result = establish_tls(
            tcp_stream,
            &target.host,
            options.insecure_tls,
            options.connect_timeout,
        )
        .await;

        let tls_elapsed_ms = (tls_start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

        match tls_result {
            Ok(tls_conn) => (
                StreamWrapper::Tls(Box::new(tls_conn.stream)),
                Some(tls_conn.report),
            ),
            Err(e) => {
                let err_msg = e.to_string();
                let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
                return ProbeReport {
                    target: target_report,
                    timestamp: current_timestamp(),
                    total_duration_ms: (total_ms * 100.0).round() / 100.0,
                    success: false,
                    dns: Some(dns_report),
                    tcp: Some(tcp_report),
                    tls: Some(crate::report::TlsStageReport {
                        duration_ms: tls_elapsed_ms,
                        protocol_version: None,
                        cipher_suite: None,
                        alpn_negotiated: None,
                        peer_certificate: None,
                        success: false,
                        error: Some(err_msg.clone()),
                    }),
                    http: None,
                    diagnosis: Some(analyze_failure("TLS", &err_msg)),
                };
            }
        }
    } else {
        (StreamWrapper::Plain(tcp_stream), None)
    };

    if options.max_stage == MaxStage::TlsOnly {
        let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
        return ProbeReport {
            target: target_report,
            timestamp: current_timestamp(),
            total_duration_ms: (total_ms * 100.0).round() / 100.0,
            success: true,
            dns: Some(dns_report),
            tcp: Some(tcp_report),
            tls: tls_report,
            http: None,
            diagnosis: None,
        };
    }

    // Stage 4: HTTP
    let http_req_options = HttpRequestOptions {
        method: options.http_method,
        custom_headers: options.custom_headers,
        request_timeout: options.total_timeout,
    };

    let http_start = Instant::now();
    let http_result = execute_http_probe(stream_wrapper, &target, http_req_options).await;
    let http_elapsed_ms = (http_start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    let http_report = match http_result {
        Ok(r) => r,
        Err(e) => {
            let err_msg = e.to_string();
            let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
            return ProbeReport {
                target: target_report,
                timestamp: current_timestamp(),
                total_duration_ms: (total_ms * 100.0).round() / 100.0,
                success: false,
                dns: Some(dns_report),
                tcp: Some(tcp_report),
                tls: tls_report,
                http: Some(crate::report::HttpStageReport {
                    duration_ms: http_elapsed_ms,
                    ttfb_ms: 0.0,
                    status_code: 0,
                    status_text: "".to_string(),
                    http_version: "".to_string(),
                    headers: vec![],
                    content_length: None,
                    body_preview: None,
                    redirect_location: None,
                    success: false,
                    error: Some(err_msg.clone()),
                }),
                diagnosis: Some(analyze_failure("HTTP", &err_msg)),
            };
        }
    };

    let is_overall_success = http_report.success;
    let diagnosis = if !is_overall_success {
        http_report
            .error
            .as_deref()
            .map(|err| analyze_failure("HTTP", err))
    } else {
        None
    };

    let total_ms = overall_start.elapsed().as_secs_f64() * 1000.0;
    ProbeReport {
        target: target_report,
        timestamp: current_timestamp(),
        total_duration_ms: (total_ms * 100.0).round() / 100.0,
        success: is_overall_success,
        dns: Some(dns_report),
        tcp: Some(tcp_report),
        tls: tls_report,
        http: Some(http_report),
        diagnosis,
    }
}

fn current_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}
