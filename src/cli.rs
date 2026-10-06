use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "netprobe",
    author = "Juan Castiñeira <juancastingo@gmail.com>",
    version,
    about = "Single-command network diagnostics: DNS → TCP → TLS → HTTP with latency waterfall and root-cause analysis.",
    long_about = "NetProbe is a transparent network diagnostic tool that tests every layer of connectivity (DNS resolution, TCP connection, TLS handshake, and HTTP response), isolates the exact point of failure, and provides clear, actionable remediation guidance."
)]
pub struct CliArgs {
    /// Target host, IP, or URL to diagnose (e.g. example.com, https://api.github.com, 1.1.1.1:80)
    #[arg(value_name = "TARGET")]
    pub target: String,

    /// Force IPv4 resolution and connection only
    #[arg(short = '4', long = "ipv4", conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Force IPv6 resolution and connection only
    #[arg(short = '6', long = "ipv6", conflicts_with = "ipv4")]
    pub ipv6: bool,

    /// Allow insecure / self-signed TLS certificates (disable certificate verification)
    #[arg(short = 'k', long = "insecure")]
    pub insecure: bool,

    /// Force plain HTTP even if port is 443
    #[arg(long = "no-tls")]
    pub no_tls: bool,

    /// HTTP method to use (e.g. GET, HEAD, POST)
    #[arg(short = 'm', long = "method", default_value = "GET")]
    pub method: String,

    /// Custom HTTP header in 'Name: Value' format (can be specified multiple times)
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,

    /// Connection timeout in milliseconds
    #[arg(long = "connect-timeout", default_value = "5000")]
    pub connect_timeout: u64,

    /// Total request timeout in milliseconds
    #[arg(long = "timeout", default_value = "15000")]
    pub timeout: u64,

    /// Run only DNS resolution stage
    #[arg(long = "dns-only", conflicts_with_all = ["tcp_only", "tls_only"])]
    pub dns_only: bool,

    /// Run only up to TCP handshake stage
    #[arg(long = "tcp-only", conflicts_with_all = ["dns_only", "tls_only"])]
    pub tcp_only: bool,

    /// Run only up to TLS handshake stage
    #[arg(long = "tls-only", conflicts_with_all = ["dns_only", "tcp_only"])]
    pub tls_only: bool,

    /// Output full diagnostic report as structured JSON
    #[arg(long = "json")]
    pub json: bool,
}
