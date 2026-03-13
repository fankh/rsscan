//! Vulnerability data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Vulnerability severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// CVE vulnerability record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub description: String,
    pub product: String,
    pub vendor: Option<String>,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
    pub references: Vec<String>,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}

/// Vulnerability match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnMatch {
    pub host: IpAddr,
    pub port: u16,
    pub service: String,
    pub version: String,
    pub vulnerability: Vulnerability,
    pub confidence: Confidence,
}

/// Match confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,   // Exact product and version match
    Medium, // Product match with version
    Low,    // Only service type match
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "high"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::Low => write!(f, "low"),
        }
    }
}

/// Vulnerability report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub hosts_affected: usize,
    pub by_host: std::collections::HashMap<String, Vec<VulnMatch>>,
}

impl VulnReport {
    pub fn new() -> Self {
        Self {
            total_vulnerabilities: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            hosts_affected: 0,
            by_host: std::collections::HashMap::new(),
        }
    }

    pub fn add_match(&mut self, m: VulnMatch) {
        self.total_vulnerabilities += 1;
        match m.vulnerability.severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
        }

        let host_key = m.host.to_string();
        self.by_host.entry(host_key).or_default().push(m);
        self.hosts_affected = self.by_host.len();
    }
}

impl Default for VulnReport {
    fn default() -> Self {
        Self::new()
    }
}
