use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::report::{CertificateInfo, TlsStageReport};

#[derive(Debug)]
struct DangerNoVerifyServerCert {
    supported_algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl DangerNoVerifyServerCert {
    fn new() -> Self {
        Self {
            supported_algorithms: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for DangerNoVerifyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}

pub struct TlsConnection {
    pub stream: TlsStream<TcpStream>,
    pub report: TlsStageReport,
}

pub async fn establish_tls(
    tcp_stream: TcpStream,
    host: &str,
    insecure: bool,
    tls_timeout: Duration,
) -> Result<TlsConnection> {
    // Ensure ring crypto provider is installed as process default
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_config = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerNoVerifyServerCert::new()))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow!("Invalid server name for TLS: {}", e))?;

    let start = Instant::now();
    let tls_handshake_future = connector.connect(server_name, tcp_stream);

    let tls_stream = match timeout(tls_timeout, tls_handshake_future).await {
        Ok(res) => match res {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow!("TLS handshake with '{}' failed: {}", host, e));
            }
        },
        Err(_) => {
            return Err(anyhow!(
                "TLS handshake with '{}' timed out after {}ms",
                host,
                tls_timeout.as_millis()
            ));
        }
    };

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let (_, client_conn) = tls_stream.get_ref();

    let protocol_version = client_conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        other => format!("{:?}", other),
    });

    let cipher_suite = client_conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    let alpn_negotiated = client_conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());

    let peer_certificate = client_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert_der| parse_certificate_info(cert_der.as_ref()));

    let report = TlsStageReport {
        duration_ms: (elapsed_ms * 100.0).round() / 100.0,
        protocol_version,
        cipher_suite,
        alpn_negotiated,
        peer_certificate,
        success: true,
        error: None,
    };

    Ok(TlsConnection {
        stream: tls_stream,
        report,
    })
}

fn parse_certificate_info(der: &[u8]) -> Option<CertificateInfo> {
    let (_, x509) = parse_x509_certificate(der).ok()?;

    let subject_cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));

    let issuer_cn = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));

    let issuer_org = x509
        .issuer()
        .iter_organization()
        .next()
        .and_then(|o| o.as_str().ok().map(|s| s.to_string()));

    let not_before = x509.validity().not_before.to_datetime().to_string();
    let not_after = x509.validity().not_after.to_datetime().to_string();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let not_after_ts = x509.validity().not_after.timestamp();
    let remaining_seconds = not_after_ts - now_ts;
    let days_until_expiration = remaining_seconds / 86400;
    let is_expired = remaining_seconds < 0;

    let mut subject_alt_names = Vec::new();
    if let Ok(Some(ext)) = x509.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    subject_alt_names.push(dns.to_string());
                }
                GeneralName::IPAddress(ip) if ip.len() == 4 => {
                    subject_alt_names.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                }
                _ => {}
            }
        }
    }

    Some(CertificateInfo {
        subject_cn,
        issuer_cn,
        issuer_org,
        not_before,
        not_after,
        days_until_expiration,
        is_expired,
        subject_alt_names,
    })
}
