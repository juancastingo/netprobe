use anyhow::{anyhow, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

use crate::report::HttpStageReport;
use crate::target::Target;

pub enum StreamWrapper {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for StreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamWrapper::Plain(s) => Pin::new(s).poll_read(cx, buf),
            StreamWrapper::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            StreamWrapper::Plain(s) => Pin::new(s).poll_write(cx, buf),
            StreamWrapper::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamWrapper::Plain(s) => Pin::new(s).poll_flush(cx),
            StreamWrapper::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamWrapper::Plain(s) => Pin::new(s).poll_shutdown(cx),
            StreamWrapper::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

pub struct HttpRequestOptions {
    pub method: String,
    pub custom_headers: Vec<(String, String)>,
    pub request_timeout: Duration,
}

pub async fn execute_http_probe(
    mut stream: StreamWrapper,
    target: &Target,
    options: HttpRequestOptions,
) -> Result<HttpStageReport> {
    // Build path and query
    let mut request_uri = target.path.clone();
    if let Some(ref q) = target.query {
        request_uri.push('?');
        request_uri.push_str(q);
    }

    // Host header
    let host_header =
        if (target.is_tls && target.port == 443) || (!target.is_tls && target.port == 80) {
            target.host.clone()
        } else {
            format!("{}:{}", target.host, target.port)
        };

    let mut req_raw = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NetProbe/{}\r\nAccept: */*\r\nConnection: close\r\n",
        options.method.to_uppercase(),
        request_uri,
        host_header,
        env!("CARGO_PKG_VERSION")
    );

    for (k, v) in &options.custom_headers {
        req_raw.push_str(&format!("{}: {}\r\n", k, v));
    }
    req_raw.push_str("\r\n");

    let req_future = async {
        let start = Instant::now();
        stream
            .write_all(req_raw.as_bytes())
            .await
            .map_err(|e| anyhow!("Failed to send HTTP request: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| anyhow!("Failed to flush HTTP request: {}", e))?;

        let mut response_bytes = Vec::with_capacity(16384);
        let mut buf = [0u8; 4096];

        // Measure TTFB
        let first_read = stream
            .read(&mut buf)
            .await
            .map_err(|e| anyhow!("Failed waiting for HTTP response (TTFB): {}", e))?;

        if first_read == 0 {
            return Err(anyhow!(
                "Remote server closed connection before sending HTTP response"
            ));
        }

        let ttfb_ms = start.elapsed().as_secs_f64() * 1000.0;
        response_bytes.extend_from_slice(&buf[..first_read]);

        // Continue reading remainder up to 64KB for inspection
        let max_read = 65536;
        while response_bytes.len() < max_read {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => response_bytes.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        let total_duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        Ok((response_bytes, ttfb_ms, total_duration_ms))
    };

    let (response_bytes, ttfb_ms, total_duration_ms) =
        match timeout(options.request_timeout, req_future).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(anyhow!(
                    "HTTP request timed out after {}ms",
                    options.request_timeout.as_millis()
                ));
            }
        };

    // Parse response headers with httparse
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers_buf);

    let parsed_status = resp
        .parse(&response_bytes)
        .map_err(|e| anyhow!("Failed to parse HTTP response: {}", e))?;

    let body_offset = match parsed_status {
        httparse::Status::Complete(offset) => offset,
        httparse::Status::Partial => {
            return Err(anyhow!("Incomplete HTTP response headers received"));
        }
    };

    let status_code = resp.code.unwrap_or(0);
    let status_text = resp.reason.unwrap_or("").to_string();
    let http_version = match resp.version {
        Some(1) => "HTTP/1.1".to_string(),
        Some(0) => "HTTP/1.0".to_string(),
        _ => "HTTP/?".to_string(),
    };

    let mut headers = Vec::new();
    let mut redirect_location = None;
    let mut content_length = None;

    for header in resp.headers.iter() {
        let name = header.name.to_string();
        let value = String::from_utf8_lossy(header.value).to_string();

        if name.eq_ignore_ascii_case("location") {
            redirect_location = Some(value.clone());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if let Ok(len) = value.parse::<usize>() {
                content_length = Some(len);
            }
        }
        headers.push((name, value));
    }

    let body_bytes = &response_bytes[body_offset..];
    let body_preview = if !body_bytes.is_empty() {
        let preview_len = body_bytes.len().min(512);
        let preview_str = String::from_utf8_lossy(&body_bytes[..preview_len])
            .chars()
            .take(250)
            .collect::<String>();
        Some(preview_str)
    } else {
        None
    };

    let is_success_status = status_code < 400;

    Ok(HttpStageReport {
        duration_ms: (total_duration_ms * 100.0).round() / 100.0,
        ttfb_ms: (ttfb_ms * 100.0).round() / 100.0,
        status_code,
        status_text,
        http_version,
        headers,
        content_length: content_length.or(Some(body_bytes.len())),
        body_preview,
        redirect_location,
        success: is_success_status,
        error: if is_success_status {
            None
        } else {
            Some(format!(
                "HTTP {} {}",
                status_code,
                resp.reason.unwrap_or("")
            ))
        },
    })
}
