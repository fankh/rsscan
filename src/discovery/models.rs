//! Discovery data models for RsScan

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::net::IpAddr;

/// Discovered host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub services: HashMap<u16, ServiceInfo>,
    pub discovered_at: DateTime<Utc>,
}

/// Service information from banner grabbing - JSON serializable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Port number
    pub port: u16,
    /// Port state (open, closed, filtered)
    pub state: PortState,
    /// Service name (ssh, http, smb, etc.)
    pub service: String,
    /// Protocol version (e.g., "2.0", "SMB 3.1.1")
    pub version: Option<String>,
    /// Raw banner text (for text-based protocols)
    pub banner: Option<String>,
    /// Product name (e.g., "OpenSSH", "nginx", "Samba")
    pub product: Option<String>,
    /// Operating system hint from banner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Parsed version with OS/distro info separated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed_version: Option<ParsedVersion>,
    /// Protocol-specific metadata (JSON object)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, JsonValue>,
    /// Detection confidence (0.0 - 1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Detection method used
    #[serde(default = "default_method")]
    pub method: String,
}

fn default_confidence() -> f32 {
    0.0
}

fn default_method() -> String {
    "unknown".to_string()
}

/// Parsed version information with OS/distro suffix separated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedVersion {
    /// Raw version string (e.g., "8.9p1 Ubuntu-3ubuntu0.6")
    pub raw: String,
    /// Core upstream version (e.g., "8.9p1")
    pub core: String,
    /// Major version number
    pub major: Option<u32>,
    /// Minor version number
    pub minor: Option<u32>,
    /// Patch version number
    pub patch: Option<u32>,
    /// Version suffix (e.g., "p1", "rc1", "beta2")
    pub suffix: Option<String>,
    /// OS/Distro name (e.g., "Ubuntu", "Debian", "RHEL")
    pub distro: Option<String>,
    /// Distro-specific version/patch level (e.g., "3ubuntu0.6", "0ubuntu0.22.04.1")
    pub distro_version: Option<String>,
    /// Whether this version likely has backported patches
    pub has_backport: bool,
}

/// Port state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Complete scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub hosts: Vec<Host>,
    pub scan_start: DateTime<Utc>,
    pub scan_end: Option<DateTime<Utc>>,
    pub total_hosts: usize,
    pub total_open_ports: usize,
}

impl ScanResult {
    /// Get scan duration
    pub fn duration(&self) -> Option<chrono::Duration> {
        self.scan_end.map(|end| end - self.scan_start)
    }
}

impl ServiceInfo {
    pub fn unknown(port: u16) -> Self {
        Self {
            port,
            state: PortState::Open,
            service: "unknown".to_string(),
            version: None,
            banner: None,
            product: None,
            os: None,
            parsed_version: None,
            metadata: HashMap::new(),
            confidence: 0.0,
            method: "unknown".to_string(),
        }
    }

    /// Create a new ServiceInfo with service name
    pub fn new(port: u16, service: &str) -> Self {
        Self {
            port,
            state: PortState::Open,
            service: service.to_string(),
            version: None,
            banner: None,
            product: None,
            os: None,
            parsed_version: None,
            metadata: HashMap::new(),
            confidence: 0.0,
            method: "probe".to_string(),
        }
    }

    /// Set metadata value
    pub fn set_metadata<T: Serialize>(&mut self, key: &str, value: T) {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.metadata.insert(key.to_string(), json_value);
        }
    }

    /// Get metadata value
    pub fn get_metadata<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.metadata.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Convert to pretty JSON string
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Builder: set version
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    /// Builder: set product
    pub fn with_product(mut self, product: &str) -> Self {
        self.product = Some(product.to_string());
        self
    }

    /// Builder: set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    /// Builder: set method
    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }
}

impl ParsedVersion {
    /// Parse a version string and extract components
    pub fn parse(raw: &str) -> Self {
        let mut parsed = ParsedVersion {
            raw: raw.to_string(),
            core: String::new(),
            major: None,
            minor: None,
            patch: None,
            suffix: None,
            distro: None,
            distro_version: None,
            has_backport: false,
        };

        // Detect distro patterns
        let distro_patterns = [
            (r"(?i)ubuntu[_-]?(\d+ubuntu[\d.]+)", "Ubuntu"),
            (r"(?i)debian[_-]?([\d.]+(?:deb\d+u\d+)?)", "Debian"),
            (r"(?i)(\d+\.el\d+(?:_\d+)?(?:\.[^.\s]+)?)", "RHEL"),
            (r"(?i)(\d+\.fc\d+)", "Fedora"),
            (r"(?i)(\d+\.amzn\d+)", "Amazon Linux"),
            (r"(?i)(\d+\.suse[\d.]*)", "SUSE"),
            (r"(?i)alpine[_-]?([\d.]+)", "Alpine"),
        ];

        let mut work_str = raw.to_string();

        for (pattern, distro_name) in &distro_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(&work_str) {
                    parsed.distro = Some(distro_name.to_string());
                    if let Some(m) = caps.get(1) {
                        parsed.distro_version = Some(m.as_str().to_string());
                    }
                    parsed.has_backport = true;
                    // Remove distro part from work string
                    work_str = re.replace(&work_str, "").to_string();
                    break;
                }
            }
        }

        // Also check for distro names in parentheses or after space
        let distro_names = [
            ("Ubuntu", r"\(Ubuntu\)|\bUbuntu\b"),
            ("Debian", r"\(Debian\)|\bDebian\b"),
            ("RHEL", r"\(Red Hat\)|\bRHEL\b|\bCentOS\b|\bRocky\b|\bAlmaLinux\b"),
            ("Fedora", r"\(Fedora\)|\bFedora\b"),
            ("Alpine", r"\(Alpine\)|\bAlpine\b"),
        ];

        if parsed.distro.is_none() {
            for (name, pattern) in &distro_names {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(raw) {
                        parsed.distro = Some(name.to_string());
                        break;
                    }
                }
            }
        }

        // Extract core version (e.g., "8.9p1", "2.4.52", "8.0.35")
        // Pattern: major.minor[.patch][suffix]
        if let Ok(re) = regex::Regex::new(r"(\d+)\.(\d+)(?:\.(\d+))?([a-zA-Z]\w*)?") {
            if let Some(caps) = re.captures(&work_str) {
                parsed.major = caps.get(1).and_then(|m| m.as_str().parse().ok());
                parsed.minor = caps.get(2).and_then(|m| m.as_str().parse().ok());
                parsed.patch = caps.get(3).and_then(|m| m.as_str().parse().ok());
                parsed.suffix = caps.get(4).map(|m| m.as_str().to_string());

                // Build core version string
                let mut core = format!("{}.{}",
                    parsed.major.unwrap_or(0),
                    parsed.minor.unwrap_or(0)
                );
                if let Some(p) = parsed.patch {
                    core.push_str(&format!(".{}", p));
                }
                if let Some(ref s) = parsed.suffix {
                    core.push_str(s);
                }
                parsed.core = core;
            }
        }

        // If no core version found, use cleaned raw string
        if parsed.core.is_empty() {
            parsed.core = work_str.trim().to_string();
        }

        parsed
    }

    /// Get version for CVE matching (core version without distro suffix)
    pub fn cve_version(&self) -> &str {
        &self.core
    }

    /// Check if version might have backported security patches
    pub fn may_have_backport(&self) -> bool {
        self.has_backport || self.distro.is_some()
    }
}
