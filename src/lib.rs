//! RsScan - Network Vulnerability Scanner
//!
//! A high-performance network vulnerability scanner written in Rust.
//!
//! ## Features
//!
//! - **Network Scanning**: Fast port discovery with SYN/Connect methods
//! - **CVE Matching**: NVD database integration with version matching
//! - **Active Testing**: YAML-based vulnerability probes
//! - **Agent Mode**: Endpoint software inventory collection
//! - **REST API**: Axum-based API server
//!
//! ## Quick Start
//!
//! ```bash
//! # Sync CVE database
//! rsscan sync --days 30
//!
//! # Scan a target
//! rsscan scan 192.168.1.0/24
//!
//! # Run active tests
//! rsscan test 192.168.1.1 --all
//! ```

pub mod discovery;
pub mod vulndb;
pub mod agent;
pub mod api;
pub mod plugins;

pub use discovery::{Host, ScanResult, NetworkDiscovery, PortScanner, ServiceDetector, ServiceInfo, ParsedVersion, SynScanner, ScanMethod};
pub use vulndb::{Vulnerability, VulnMatch, CveDatabase, VulnerabilityScanner, SyncSource, SyncStats};
pub use agent::{Software, SoftwareCollector, VulnAgent};
