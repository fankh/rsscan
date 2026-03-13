//! Network Discovery Module
//!
//! High-performance async port scanning and service detection.
//!
//! Supports two scan methods:
//! - **TCP Connect**: Works without privileges, 5-6 packets per port
//! - **SYN Scan**: Requires root/admin, 2 packets per port (masscan-style)

mod scanner;
mod service;
mod models;
mod syn_scanner;

pub use scanner::PortScanner;
pub use service::ServiceDetector;
pub use models::{Host, ScanResult, ServiceInfo, ParsedVersion};
pub use syn_scanner::{SynScanner, SynScannerConfig, ScanMethod, SynScanResult};

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use ipnetwork::IpNetwork;
use tracing::{info, debug, warn};

/// Main network discovery orchestrator
pub struct NetworkDiscovery {
    port_scanner: PortScanner,
    syn_scanner: SynScanner,
    service_detector: ServiceDetector,
    scan_method: ScanMethod,
}

impl NetworkDiscovery {
    pub fn new() -> Self {
        Self {
            port_scanner: PortScanner::new(),
            syn_scanner: SynScanner::new(),
            service_detector: ServiceDetector::new(),
            scan_method: ScanMethod::Auto,
        }
    }

    pub fn with_config(
        port_timeout_ms: u64,
        service_timeout_ms: u64,
        max_concurrent: usize,
    ) -> Self {
        Self {
            port_scanner: PortScanner::with_config(port_timeout_ms, max_concurrent),
            syn_scanner: SynScanner::with_config(SynScannerConfig {
                timeout_ms: port_timeout_ms,
                rate_limit: max_concurrent as u32 * 2,
                ..Default::default()
            }),
            service_detector: ServiceDetector::with_timeout(service_timeout_ms),
            scan_method: ScanMethod::Auto,
        }
    }

    /// Set the scan method
    pub fn with_scan_method(mut self, method: ScanMethod) -> Self {
        self.scan_method = method;
        self
    }

    /// Get current scan method
    pub fn scan_method(&self) -> ScanMethod {
        self.scan_method
    }

    /// Check if SYN scanning is available (has privileges)
    pub fn syn_available() -> bool {
        SynScanner::check_privileges()
    }

    /// Discover hosts and services on a target
    pub async fn discover(
        &self,
        target: &str,
        ports: Option<Vec<u16>>,
        detect_services: bool,
    ) -> Result<ScanResult> {
        let start = Instant::now();
        let ports = ports.unwrap_or_else(|| PortScanner::TOP_PORTS.to_vec());

        let mut result = ScanResult {
            target: target.to_string(),
            hosts: Vec::new(),
            scan_start: chrono::Utc::now(),
            scan_end: None,
            total_hosts: 0,
            total_open_ports: 0,
        };

        // Check if target is a network or single host
        if let Ok(network) = target.parse::<IpNetwork>() {
            // Scan network
            for ip in network.iter() {
                if let Some(host) = self.scan_single_host(ip, &ports, detect_services).await? {
                    result.total_open_ports += host.open_ports.len();
                    result.hosts.push(host);
                    info!("Found host: {} with {} open ports", ip, result.hosts.last().unwrap().open_ports.len());
                }
            }
        } else {
            // Single host - resolve hostname if needed
            let ip: IpAddr = if let Ok(ip) = target.parse() {
                ip
            } else {
                // Resolve hostname
                let ips = dns_lookup::lookup_host(target)?;
                ips.into_iter().next().ok_or_else(|| anyhow::anyhow!("Could not resolve hostname"))?
            };

            if let Some(host) = self.scan_single_host(ip, &ports, detect_services).await? {
                result.total_open_ports = host.open_ports.len();
                result.hosts.push(host);
            }
        }

        result.total_hosts = result.hosts.len();
        result.scan_end = Some(chrono::Utc::now());

        info!(
            "Scan complete: {} hosts, {} open ports in {:?}",
            result.total_hosts,
            result.total_open_ports,
            start.elapsed()
        );

        Ok(result)
    }

    async fn scan_single_host(
        &self,
        ip: IpAddr,
        ports: &[u16],
        detect_services: bool,
    ) -> Result<Option<Host>> {
        // Select scan method
        let open_ports = match self.scan_method {
            ScanMethod::Connect => {
                debug!("Using TCP connect scan for {}", ip);
                self.port_scanner.scan_host(ip, ports).await?
            }
            ScanMethod::Syn => {
                debug!("Using SYN scan for {}", ip);
                if let IpAddr::V4(ipv4) = ip {
                    self.syn_scanner.scan(ipv4, ports).await?.open_ports
                } else {
                    warn!("SYN scan only supports IPv4, falling back to connect");
                    self.port_scanner.scan_host(ip, ports).await?
                }
            }
            ScanMethod::Auto => {
                // Try SYN first if we have privileges and it's IPv4
                if let IpAddr::V4(ipv4) = ip {
                    if SynScanner::check_privileges() {
                        debug!("Auto: Using SYN scan for {} (has privileges)", ip);
                        match self.syn_scanner.scan(ipv4, ports).await {
                            Ok(result) => result.open_ports,
                            Err(e) => {
                                warn!("SYN scan failed: {}, falling back to connect", e);
                                self.port_scanner.scan_host(ip, ports).await?
                            }
                        }
                    } else {
                        debug!("Auto: Using connect scan for {} (no privileges)", ip);
                        self.port_scanner.scan_host(ip, ports).await?
                    }
                } else {
                    debug!("Auto: Using connect scan for {} (IPv6)", ip);
                    self.port_scanner.scan_host(ip, ports).await?
                }
            }
        };

        if open_ports.is_empty() {
            return Ok(None);
        }

        let mut host = Host {
            ip,
            hostname: None,
            open_ports: open_ports.clone(),
            services: std::collections::HashMap::new(),
            discovered_at: chrono::Utc::now(),
        };

        // Try reverse DNS
        if let Ok(hostname) = dns_lookup::lookup_addr(&ip) {
            host.hostname = Some(hostname);
        }

        // Detect services (always uses TCP connect for banner grabbing)
        if detect_services {
            for port in &open_ports {
                debug!("Detecting service on {}:{}", ip, port);
                if let Ok(service) = self.service_detector.detect(ip, *port).await {
                    host.services.insert(*port, service);
                }
            }
        }

        Ok(Some(host))
    }
}

impl Default for NetworkDiscovery {
    fn default() -> Self {
        Self::new()
    }
}
