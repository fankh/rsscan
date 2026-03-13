//! Endpoint Agent Module
//!
//! Cross-platform software inventory collection and reporting.

mod collector;
mod models;

pub use collector::SoftwareCollector;
pub use models::{Software, SoftwareType, AgentConfig};

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn, error};

/// Vulnerability scanning agent
pub struct VulnAgent {
    config: AgentConfig,
    collector: SoftwareCollector,
    client: Client,
    agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    hostname: String,
    os_type: String,
    os_version: String,
    agent_version: String,
    ip_addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    agent_id: String,
}

#[derive(Debug, Serialize)]
struct InventoryRequest {
    hostname: String,
    collected_at: String,
    software: Vec<SoftwareReport>,
}

#[derive(Debug, Serialize)]
struct SoftwareReport {
    name: String,
    version: String,
    publisher: Option<String>,
    install_path: Option<String>,
    #[serde(rename = "type")]
    software_type: String,
}

#[derive(Debug, Deserialize)]
struct InventoryResponse {
    status: String,
    vulnerabilities_found: usize,
    vulnerabilities: Vec<VulnerabilityInfo>,
}

#[derive(Debug, Deserialize)]
struct VulnerabilityInfo {
    cve_id: String,
    severity: String,
    software: String,
    version: String,
}

impl VulnAgent {
    pub fn new(config: AgentConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            collector: SoftwareCollector::new(),
            client,
            agent_id: None,
        }
    }

    /// Register agent with central server
    pub async fn register(&mut self) -> Result<()> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let request = RegisterRequest {
            hostname,
            os_type: std::env::consts::OS.to_string(),
            os_version: os_info::get().version().to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            ip_addresses: self.get_ip_addresses(),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/agents/register", self.config.server_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let data: RegisterResponse = response.json().await?;
            self.agent_id = Some(data.agent_id.clone());
            info!("Agent registered: {}", data.agent_id);
            Ok(())
        } else {
            anyhow::bail!("Registration failed: {}", response.status())
        }
    }

    /// Collect and report software inventory
    pub async fn collect_and_report(&mut self) -> Result<()> {
        // Register if not already
        if self.agent_id.is_none() {
            self.register().await?;
        }

        let agent_id = self.agent_id.as_ref().unwrap();

        // Collect software
        info!("Collecting software inventory...");
        let software = self.collector.collect_all();
        info!("Found {} software items", software.len());

        // Prepare report
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let request = InventoryRequest {
            hostname,
            collected_at: chrono::Utc::now().to_rfc3339(),
            software: software
                .iter()
                .map(|s| SoftwareReport {
                    name: s.name.clone(),
                    version: s.version.clone(),
                    publisher: s.publisher.clone(),
                    install_path: s.install_path.clone(),
                    software_type: format!("{:?}", s.software_type).to_lowercase(),
                })
                .collect(),
        };

        // Submit to server
        let response = self
            .client
            .post(format!(
                "{}/api/v1/agents/{}/inventory",
                self.config.server_url, agent_id
            ))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            let data: InventoryResponse = response.json().await?;
            info!(
                "Inventory submitted. Vulnerabilities found: {}",
                data.vulnerabilities_found
            );

            if data.vulnerabilities_found > 0 {
                warn!("Vulnerabilities detected:");
                for v in data.vulnerabilities.iter().take(10) {
                    warn!(
                        "  {} [{}] {} {}",
                        v.cve_id, v.severity, v.software, v.version
                    );
                }
            }
            Ok(())
        } else {
            anyhow::bail!("Inventory submission failed: {}", response.status())
        }
    }

    /// Run agent as daemon
    pub async fn run_daemon(&mut self) -> Result<()> {
        info!(
            "Starting agent daemon (interval: {}s)",
            self.config.scan_interval.as_secs()
        );

        loop {
            if let Err(e) = self.collect_and_report().await {
                error!("Collection failed: {}", e);
            }

            tokio::time::sleep(self.config.scan_interval).await;
        }
    }

    fn get_ip_addresses(&self) -> Vec<String> {
        let mut ips = Vec::new();

        if let Ok(hostname) = hostname::get() {
            if let Ok(addrs) = dns_lookup::lookup_host(&hostname.to_string_lossy()) {
                for addr in addrs {
                    if !addr.is_loopback() {
                        ips.push(addr.to_string());
                    }
                }
            }
        }

        ips
    }
}
