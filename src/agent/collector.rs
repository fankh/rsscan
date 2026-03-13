//! Cross-platform software collector

use super::models::{Software, SoftwareType};
use std::process::Command;
use tracing::{debug, warn};

/// Collects installed software across platforms
pub struct SoftwareCollector {
    os_type: String,
}

impl SoftwareCollector {
    pub fn new() -> Self {
        Self {
            os_type: std::env::consts::OS.to_string(),
        }
    }

    /// Collect all installed software
    pub fn collect_all(&self) -> Vec<Software> {
        let mut software = Vec::new();

        match self.os_type.as_str() {
            "windows" => software.extend(self.collect_windows()),
            "linux" => software.extend(self.collect_linux()),
            "macos" => software.extend(self.collect_macos()),
            _ => warn!("Unsupported OS: {}", self.os_type),
        }

        // Cross-platform package managers
        software.extend(self.collect_python_packages());
        software.extend(self.collect_npm_packages());

        software
    }

    #[cfg(target_os = "windows")]
    fn collect_windows(&self) -> Vec<Software> {
        let mut software = Vec::new();

        // Collect from Windows Registry
        use winreg::enums::*;
        use winreg::RegKey;

        let paths = [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ];

        for (hive, path) in &paths {
            if let Ok(key) = RegKey::predef(*hive).open_subkey(path) {
                for subkey_name in key.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(subkey) = key.open_subkey(&subkey_name) {
                        let name: Result<String, _> = subkey.get_value("DisplayName");
                        if let Ok(name) = name {
                            let version: String = subkey
                                .get_value("DisplayVersion")
                                .unwrap_or_else(|_| "unknown".to_string());

                            let mut sw = Software::new(
                                name,
                                version,
                                SoftwareType::WindowsProgram,
                            );

                            sw.publisher = subkey.get_value("Publisher").ok();
                            sw.install_path = subkey.get_value("InstallLocation").ok();
                            sw.install_date = subkey.get_value("InstallDate").ok();

                            software.push(sw);
                        }
                    }
                }
            }
        }

        // Collect Windows services
        if let Ok(output) = Command::new("powershell")
            .args([
                "-Command",
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | ConvertTo-Json",
            ])
            .output()
        {
            if output.status.success() {
                if let Ok(services) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
                    for svc in services {
                        if let (Some(name), Some(display)) = (
                            svc.get("DisplayName").and_then(|v| v.as_str()),
                            svc.get("Name").and_then(|v| v.as_str()),
                        ) {
                            software.push(Software::new(
                                name.to_string(),
                                "running".to_string(),
                                SoftwareType::WindowsService,
                            ));
                        }
                    }
                }
            }
        }

        software
    }

    #[cfg(not(target_os = "windows"))]
    fn collect_windows(&self) -> Vec<Software> {
        Vec::new()
    }

    fn collect_linux(&self) -> Vec<Software> {
        let mut software = Vec::new();

        // Debian/Ubuntu (dpkg)
        if let Ok(output) = Command::new("dpkg-query")
            .args(["-W", "-f", "${Package}|${Version}|${Status}\n"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("installed") {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() >= 2 {
                            software.push(Software::new(
                                parts[0].to_string(),
                                parts[1].to_string(),
                                SoftwareType::DebPackage,
                            ));
                        }
                    }
                }
            }
        }

        // RHEL/CentOS (rpm)
        if let Ok(output) = Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}\n"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 2 {
                        software.push(Software::new(
                            parts[0].to_string(),
                            parts[1].to_string(),
                            SoftwareType::RpmPackage,
                        ));
                    }
                }
            }
        }

        // Snap packages
        if let Ok(output) = Command::new("snap")
            .args(["list", "--color=never"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        software.push(Software::new(
                            parts[0].to_string(),
                            parts[1].to_string(),
                            SoftwareType::SnapPackage,
                        ));
                    }
                }
            }
        }

        // Flatpak
        if let Ok(output) = Command::new("flatpak")
            .args(["list", "--columns=application,version"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    software.push(Software::new(
                        parts[0].to_string(),
                        parts.get(1).unwrap_or(&"unknown").to_string(),
                        SoftwareType::Flatpak,
                    ));
                }
            }
        }

        software
    }

    fn collect_macos(&self) -> Vec<Software> {
        let mut software = Vec::new();

        // System applications
        if let Ok(output) = Command::new("system_profiler")
            .args(["SPApplicationsDataType", "-json"])
            .output()
        {
            if output.status.success() {
                if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(apps) = data
                        .get("SPApplicationsDataType")
                        .and_then(|v| v.as_array())
                    {
                        for app in apps {
                            let name = app
                                .get("_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let version = app
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            let mut sw = Software::new(
                                name.to_string(),
                                version.to_string(),
                                SoftwareType::MacosApp,
                            );

                            sw.install_path = app
                                .get("path")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            software.push(sw);
                        }
                    }
                }
            }
        }

        // Homebrew
        if let Ok(output) = Command::new("brew")
            .args(["list", "--versions"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        software.push(Software::new(
                            parts[0].to_string(),
                            parts.get(1).unwrap_or(&"unknown").to_string(),
                            SoftwareType::Homebrew,
                        ));
                    }
                }
            }
        }

        software
    }

    fn collect_python_packages(&self) -> Vec<Software> {
        let mut software = Vec::new();

        for pip_cmd in &["pip", "pip3"] {
            if let Ok(output) = Command::new(pip_cmd)
                .args(["list", "--format=json"])
                .output()
            {
                if output.status.success() {
                    if let Ok(packages) =
                        serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout)
                    {
                        for pkg in packages {
                            let name = pkg
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let version = pkg
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            // Avoid duplicates
                            if !software.iter().any(|s: &Software| s.name == name) {
                                software.push(Software::new(
                                    name.to_string(),
                                    version.to_string(),
                                    SoftwareType::PythonPackage,
                                ));
                            }
                        }
                    }
                }
            }
        }

        software
    }

    fn collect_npm_packages(&self) -> Vec<Software> {
        let mut software = Vec::new();

        if let Ok(output) = Command::new("npm")
            .args(["list", "-g", "--json", "--depth=0"])
            .output()
        {
            if output.status.success() {
                if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(deps) = data.get("dependencies").and_then(|v| v.as_object()) {
                        for (name, info) in deps {
                            let version = info
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            software.push(Software::new(
                                name.clone(),
                                version.to_string(),
                                SoftwareType::NpmPackage,
                            ));
                        }
                    }
                }
            }
        }

        software
    }
}

impl Default for SoftwareCollector {
    fn default() -> Self {
        Self::new()
    }
}
