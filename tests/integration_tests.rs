use netprobe::diagnosis::analyze_failure;
use netprobe::engine::{run_probe, MaxStage, ProbeOptions};
use netprobe::target::Target;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_target_parsing_variations() {
    let t1 = Target::parse("api.github.com", false).unwrap();
    assert_eq!(t1.host, "api.github.com");
    assert_eq!(t1.port, 443);
    assert!(t1.is_tls);
    assert_eq!(t1.path, "/");

    let t2 = Target::parse("http://localhost:8080/health?v=1", false).unwrap();
    assert_eq!(t2.host, "localhost");
    assert_eq!(t2.port, 8080);
    assert!(!t2.is_tls);
    assert_eq!(t2.path, "/health");
    assert_eq!(t2.query.as_deref(), Some("v=1"));

    let t3 = Target::parse("127.0.0.1:9000", true).unwrap();
    assert_eq!(t3.host, "127.0.0.1");
    assert_eq!(t3.port, 9000);
    assert!(!t3.is_tls);
    assert!(t3.is_ip);

    let t4 = Target::parse("[::1]:8080", false).unwrap();
    assert_eq!(t4.host, "::1");
    assert_eq!(t4.port, 8080);
    assert!(t4.is_ip);
}

#[test]
fn test_diagnosis_analyzer() {
    let dns_diag = analyze_failure(
        "DNS",
        "failed to lookup address information: Name or service not known",
    );
    assert_eq!(dns_diag.failed_stage, "DNS Resolution");
    assert!(dns_diag.remediation.iter().any(|r| r.contains("spelling")));

    let tcp_diag = analyze_failure("TCP", "Connection refused (os error 111)");
    assert_eq!(tcp_diag.failed_stage, "TCP Connection");
    assert!(tcp_diag.remediation.iter().any(|r| r.contains("listening")));

    let tls_diag = analyze_failure("TLS", "certificate expired on 2026-01-01");
    assert_eq!(tls_diag.failed_stage, "TLS / SSL Handshake");
    assert!(tls_diag.remediation.iter().any(|r| r.contains("Renew")));

    let http_diag = analyze_failure("HTTP", "502 Bad Gateway");
    assert_eq!(http_diag.failed_stage, "HTTP Request");
    assert!(http_diag.remediation.iter().any(|r| r.contains("upstream")));
}

#[tokio::test]
async fn test_tcp_and_http_local_mock_server() {
    // Start a mock HTTP server on a random local port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    let target_str = format!("http://127.0.0.1:{}/test", local_port);
    let options = ProbeOptions {
        connect_timeout: Duration::from_millis(2000),
        total_timeout: Duration::from_millis(3000),
        ..Default::default()
    };

    let report = run_probe(&target_str, options).await;
    assert!(
        report.success,
        "Probe should succeed against mock HTTP server"
    );
    assert!(report.dns.is_some());
    assert!(report.tcp.is_some());
    assert!(report.http.is_some());

    let http = report.http.unwrap();
    assert_eq!(http.status_code, 200);
    assert_eq!(http.status_text, "OK");
    assert!(http.body_preview.unwrap().contains("{\"status\":\"ok\"}"));
}

#[tokio::test]
async fn test_tcp_connection_refused_diagnosis() {
    // Port 1 is reserved and closed on localhost
    let target_str = "http://127.0.0.1:1";
    let options = ProbeOptions {
        connect_timeout: Duration::from_millis(500),
        total_timeout: Duration::from_millis(1000),
        ..Default::default()
    };

    let report = run_probe(target_str, options).await;
    assert!(!report.success);
    assert!(report.tcp.is_some());
    assert!(!report.tcp.unwrap().success);
    assert!(report.diagnosis.is_some());

    let diag = report.diagnosis.unwrap();
    assert!(
        diag.root_cause.to_lowercase().contains("refused")
            || diag.root_cause.to_lowercase().contains("service")
            || diag.root_cause.to_lowercase().contains("firewall")
            || diag.root_cause.to_lowercase().contains("timed out")
    );
}

#[tokio::test]
async fn test_dns_resolution_failure_diagnosis() {
    let target_str = "https://this-domain-definitely-does-not-exist-123456789.xyz";
    let options = ProbeOptions {
        connect_timeout: Duration::from_millis(1000),
        total_timeout: Duration::from_millis(2000),
        ..Default::default()
    };

    let report = run_probe(target_str, options).await;
    assert!(!report.success);
    assert!(report.dns.is_some());
    assert!(!report.dns.unwrap().success);
    assert!(report.diagnosis.is_some());

    let diag = report.diagnosis.unwrap();
    assert_eq!(diag.failed_stage, "DNS Resolution");
}

#[tokio::test]
async fn test_json_serialization() {
    let target_str = "http://127.0.0.1:65534";
    let options = ProbeOptions {
        connect_timeout: Duration::from_millis(200),
        max_stage: MaxStage::TcpOnly,
        ..Default::default()
    };

    let report = run_probe(target_str, options).await;
    let json_output = serde_json::to_string(&report);
    assert!(json_output.is_ok());
    let serialized = json_output.unwrap();
    assert!(serialized.contains("\"target\""));
    assert!(serialized.contains("\"total_duration_ms\""));
}
