use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::report::TcpStageReport;

pub struct TcpConnection {
    pub stream: TcpStream,
    pub report: TcpStageReport,
}

pub async fn connect_tcp(addr: SocketAddr, connect_timeout: Duration) -> Result<TcpConnection> {
    let start = Instant::now();

    let connect_future = TcpStream::connect(addr);
    let stream = match timeout(connect_timeout, connect_future).await {
        Ok(res) => match res {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow!("TCP connection to {} failed: {}", addr, e));
            }
        },
        Err(_) => {
            return Err(anyhow!(
                "TCP connection to {} timed out after {}ms",
                addr,
                connect_timeout.as_millis()
            ));
        }
    };

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let local_addr = stream.local_addr().ok().map(|a| a.to_string());
    let remote_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| addr.to_string());

    let report = TcpStageReport {
        duration_ms: (elapsed_ms * 100.0).round() / 100.0,
        remote_addr,
        local_addr,
        success: true,
        error: None,
    };

    Ok(TcpConnection { stream, report })
}
