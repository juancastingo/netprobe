use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub target: TargetReport,
    pub timestamp: String,
    pub total_duration_ms: f64,
    pub success: bool,
    pub dns: Option<DnsStageReport>,
    pub tcp: Option<TcpStageReport>,
    pub tls: Option<TlsStageReport>,
    pub http: Option<HttpStageReport>,
    pub diagnosis: Option<DiagnosisReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetReport {
    pub input: String,
    pub host: String,
    pub port: u16,
    pub is_tls: bool,
    pub path: String,
    pub full_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStageReport {
    pub duration_ms: f64,
    pub resolved_ipv4: Vec<String>,
    pub resolved_ipv6: Vec<String>,
    pub selected_ip: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStageReport {
    pub duration_ms: f64,
    pub remote_addr: String,
    pub local_addr: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsStageReport {
    pub duration_ms: f64,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn_negotiated: Option<String>,
    pub peer_certificate: Option<CertificateInfo>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiration: i64,
    pub is_expired: bool,
    pub subject_alt_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpStageReport {
    pub duration_ms: f64,
    pub ttfb_ms: f64,
    pub status_code: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub body_preview: Option<String>,
    pub redirect_location: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisReport {
    pub failed_stage: String,
    pub summary: String,
    pub root_cause: String,
    pub remediation: Vec<String>,
}
