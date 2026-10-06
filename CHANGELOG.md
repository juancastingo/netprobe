# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-06

### Added
- Initial release of **NetProbe** CLI and Rust library.
- Diagnostic pipeline measuring DNS resolution, TCP connection handshake, TLS negotiation, and HTTP response (TTFB & transfer).
- Per-stage latency waterfall with ASCII bar chart visualization.
- Rich X.509 certificate inspection (Common Name, Issuer Organization, Validity dates, SANs, days remaining).
- Diagnostic rule engine offering root-cause explanations and remediation actions for DNS, TCP, TLS, and HTTP errors.
- Support for URLs, hostnames, host:port, and IPv4/IPv6 literals.
- Configurable flags: `--ipv4`, `--ipv6`, `--insecure`, `--method`, `--header`, `--dns-only`, `--tcp-only`, `--tls-only`.
- Full `--json` machine-readable output format.
- Cross-platform support for Linux, macOS, and Windows.
- GitHub Actions CI matrix and multi-platform release workflows.
