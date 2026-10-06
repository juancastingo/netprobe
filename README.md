# ⚡ NetProbe

[![CI](https://github.com/juancastingo/netprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/juancastingo/netprobe/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/netprobe.svg)](https://crates.io/crates/netprobe)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/juancastingo/netprobe)

**NetProbe** is a fast, transparent network diagnostics CLI and Rust library that breaks down end-to-end connectivity into distinct, measurable stages:

$$\text{DNS Resolution} \longrightarrow \text{TCP Handshake} \longrightarrow \text{TLS Handshake} \longrightarrow \text{HTTP TTFB \& Response}$$

Whenever an error occurs—whether it's an NXDOMAIN record, a firewall silently dropping SYN packets, an expired or untrusted SSL certificate, or an upstream `502 Bad Gateway`—**NetProbe pinpoint the exact layer of failure** and provides actionable root-cause analysis and remediation steps.

---

## 📸 Terminal Preview

```text
════════════════════════════════════════════════════════════════
 ⚡ NetProbe Diagnostics: https://example.com/
════════════════════════════════════════════════════════════════
 Target Host:   example.com (Port: 443)
 Protocol:      HTTPS / TLS
 Timestamp:     1791286908
────────────────────────────────────────────────────────────────
 STAGE WATERFALL:
  ✓ 1. DNS Resolution    82.66 ms ████████████████████ 
  ✓ 2. TCP Handshake      2.84 ms █                    
  ✓ 3. TLS Handshake      8.93 ms ██                   
  ✓ 4. HTTP Response     52.54 ms █████████████        
    Total Latency:      147.14 ms
────────────────────────────────────────────────────────────────
 STAGE DETAILS:
  • DNS:  Selected 104.20.23.154  [IPv4: 104.20.23.154, 172.66.147.243 | IPv6: 2606:4700:10::6814:179a]
  • TCP:  Connected to 104.20.23.154:443 (Local: 192.168.1.25:49172)
  • TLS:  TLSv1.3 | Cipher: TLS13_AES_256_GCM_SHA384 | ALPN: none
    Cert: Subject: example.com, Issuer: SSL Corporation
    Valid: 2026-09-26 to 2026-12-25 [80 days remaining]
  • HTTP: 200 OK (TTFB: 52.39 ms)
    Content Length:    589 bytes
════════════════════════════════════════════════════════════════
```

### Automatic Failure Root-Cause Analysis

If any layer fails, NetProbe delivers a clear diagnostic verdict:

```text
────────────────────────────────────────────────────────────────
 ❌ DIAGNOSTIC FAILURE: TLS / SSL Handshake
 Summary:    The certificate authority (CA) is not trusted by the WebPKI trust store.
 Root Cause: The server uses a self-signed certificate or missing intermediate CAs.
 Remediation Actions:
   → Ensure the server config includes the full certificate chain.
   → Use `-k` / `--insecure` if testing self-signed certificates in staging/development.
════════════════════════════════════════════════════════════════
```

---

## ✨ Key Features

- **Single-Command Multi-Layer Audit**: Sequentially validates DNS, TCP, TLS, and HTTP in a single shot.
- **Stage Latency Waterfall**: Visually compare DNS lookup time vs. network roundtrip (TCP) vs. cryptographic negotiation (TLS) vs. application processing time (TTFB).
- **Intelligent Target Parsing**: Accepts URLs (`https://api.domain.com/v1/health`), bare hostnames (`github.com`), host-port pairs (`example.com:8443`), and raw IPv4/IPv6 literals (`1.1.1.1:80`, `[::1]:3000`).
- **Deep Certificate Inspection**: Extracts SANs, Issuer, Common Name, validity ranges, and alerts when expiration is imminent.
- **Root-Cause Analysis Engine**: Analyzes socket error codes, TLS alerts, and HTTP status codes to give plain-English explanations and next steps.
- **Automation & CI Friendly**:
  - Full `--json` flag output.
  - Standard exit codes (`0` on success, `1` on failure) for automated smoke tests or deployment health gates.
- **Pure Rust, Zero C-Library Dependencies**: Powered by `tokio`, `rustls`, and `webpki-roots`—runs anywhere without needing OpenSSL installed.

---

## 🚀 Installation

### Using Cargo
```bash
cargo install netprobe
```

### From Pre-compiled GitHub Releases
Download pre-built standalone binaries for Linux, macOS, and Windows from the [Releases](https://github.com/juancastingo/netprobe/releases) page.

### From Source
```bash
git clone https://github.com/juancastingo/netprobe.git
cd netprobe
cargo build --release
./target/release/netprobe --version
```

---

## 📖 Usage Examples

### 1. Basic Diagnostics
```bash
netprobe api.github.com
```

### 2. Custom Port and Path
```bash
netprobe https://internal.example.corp:8443/healthz
```

### 3. Machine-Readable JSON for CI/CD Pipelines
```bash
netprobe example.com --json | jq .
```

### 4. Force IPv4 or IPv6
```bash
netprobe google.com -4
netprobe google.com -6
```

### 5. Insecure / Self-Signed Testing (Staging/Dev)
```bash
netprobe https://192.168.1.50:9443 -k
```

### 6. Custom HTTP Method & Headers
```bash
netprobe https://httpbin.org/post -m POST -H "Authorization: Bearer token123"
```

### 7. Run Specific Diagnostics Only
```bash
# DNS resolution only
netprobe example.com --dns-only

# Check TCP port reachability only
netprobe db.internal.net:5432 --tcp-only

# Verify TLS certificate without sending HTTP request
netprobe badssl.com --tls-only
```

---

## ⚙️ CLI Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `<TARGET>` | | *(required)* | Target host, IP, or URL to diagnose |
| `--ipv4` | `-4` | | Force IPv4 resolution and connection only |
| `--ipv6` | `-6` | | Force IPv6 resolution and connection only |
| `--insecure` | `-k` | `false` | Allow self-signed or invalid TLS certificates |
| `--no-tls` | | `false` | Force plain unencrypted HTTP connection |
| `--method` | `-m` | `GET` | HTTP method to execute |
| `--header` | `-H` | | Custom HTTP header (can be repeated) |
| `--connect-timeout` | | `5000` | Connection timeout in milliseconds |
| `--timeout` | | `15000` | Total request timeout in milliseconds |
| `--dns-only` | | `false` | Stop after DNS resolution stage |
| `--tcp-only` | | `false` | Stop after TCP connection stage |
| `--tls-only` | | `false` | Stop after TLS handshake stage |
| `--json` | | `false` | Output full diagnostic report in JSON format |

---

## 📦 Using NetProbe as a Rust Library

NetProbe can also be embedded directly in your Rust applications:

```toml
[dependencies]
netprobe = "0.1"
```

```rust
use netprobe::{run_probe, ProbeOptions, MaxStage};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let options = ProbeOptions {
        connect_timeout: Duration::from_millis(3000),
        total_timeout: Duration::from_millis(5000),
        max_stage: MaxStage::FullHttp,
        ..Default::default()
    };

    let report = run_probe("https://api.github.com", options).await;
    if report.success {
        println!("API is reachable! Total latency: {:.2}ms", report.total_duration_ms);
    } else if let Some(diag) = report.diagnosis {
        eprintln!("Connectivity check failed at {}: {}", diag.failed_stage, diag.summary);
    }
}
```

---

## 🛠️ Development & Testing

```bash
# Run unit and integration tests
cargo test

# Check code formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets -- -D warnings
```

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE) or the Apache 2.0 license at your option.
