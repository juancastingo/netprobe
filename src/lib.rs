pub mod cli;
pub mod diagnosis;
pub mod dns;
pub mod engine;
pub mod http;
pub mod printer;
pub mod report;
pub mod target;
pub mod tcp;
pub mod tls;

pub use dns::IpFamilyPreference;
pub use engine::{run_probe, MaxStage, ProbeOptions};
pub use printer::print_report;
pub use report::ProbeReport;
pub use target::Target;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
