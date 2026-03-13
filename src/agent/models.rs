//! Agent data models

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Agent configuration
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub server_url: String,
    pub api_key: String,
    pub scan_interval: Duration,
    pub hostname: Option<String>,
}

impl AgentConfig {
    pub fn new(server_url: String, api_key: String) -> Self {
        Self {
            server_url,
            api_key,
            scan_interval: Duration::from_secs(3600),
            hostname: None,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.scan_interval = interval;
        self
    }
}

/// Software type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SoftwareType {
    WindowsProgram,
    WindowsService,
    DebPackage,
    RpmPackage,
    SnapPackage,
    Flatpak,
    MacosApp,
    Homebrew,
    PythonPackage,
    NpmPackage,
    Unknown,
}

/// Installed software record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    pub install_path: Option<String>,
    pub install_date: Option<String>,
    pub software_type: SoftwareType,
}

impl Software {
    pub fn new(name: String, version: String, software_type: SoftwareType) -> Self {
        Self {
            name,
            version,
            publisher: None,
            install_path: None,
            install_date: None,
            software_type,
        }
    }
}
