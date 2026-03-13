//! Plugin System
//!
//! Extensible protocol detection plugins.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Plugin detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub detected: bool,
    pub service_name: String,
    pub version: Option<String>,
    pub info: std::collections::HashMap<String, serde_json::Value>,
}

impl PluginResult {
    pub fn not_detected() -> Self {
        Self {
            detected: false,
            service_name: "unknown".to_string(),
            version: None,
            info: std::collections::HashMap::new(),
        }
    }

    pub fn detected(service_name: &str) -> Self {
        Self {
            detected: true,
            service_name: service_name.to_string(),
            version: None,
            info: std::collections::HashMap::new(),
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    pub fn with_info(mut self, key: &str, value: serde_json::Value) -> Self {
        self.info.insert(key.to_string(), value);
        self
    }
}

/// Protocol detection plugin trait
#[async_trait]
pub trait ProtocolPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;

    /// Plugin description
    fn description(&self) -> &str;

    /// Default ports for this protocol
    fn default_ports(&self) -> &[u16];

    /// Detect if the protocol is running on the given host:port
    async fn detect(&self, host: IpAddr, port: u16) -> PluginResult;

    /// Check for known vulnerabilities (optional)
    async fn check_vulnerabilities(&self, _host: IpAddr, _port: u16, _version: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Modbus TCP Protocol Plugin (ICS/SCADA)
pub struct ModbusPlugin;

#[async_trait]
impl ProtocolPlugin for ModbusPlugin {
    fn name(&self) -> &str {
        "modbus"
    }

    fn description(&self) -> &str {
        "Modbus TCP Protocol Detection"
    }

    fn default_ports(&self) -> &[u16] {
        &[502]
    }

    async fn detect(&self, host: IpAddr, port: u16) -> PluginResult {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::time::{timeout, Duration};

        let addr = std::net::SocketAddr::new(host, port);

        let result = timeout(Duration::from_secs(5), async {
            let mut stream = TcpStream::connect(addr).await?;

            // Modbus Read Device Identification request
            let request: [u8; 12] = [
                0x00, 0x01, // Transaction ID
                0x00, 0x00, // Protocol ID (Modbus)
                0x00, 0x05, // Length
                0x01,       // Unit ID
                0x2B,       // Function code (Read Device Identification)
                0x0E,       // MEI type
                0x01,       // Read device ID
                0x00,       // Object ID
                0x00,       // Padding
            ];

            stream.write_all(&request).await?;

            let mut response = vec![0u8; 256];
            let n = stream.read(&mut response).await?;
            response.truncate(n);

            Ok::<_, std::io::Error>(response)
        })
        .await;

        match result {
            Ok(Ok(response)) if response.len() >= 7 => {
                // Check for Modbus protocol ID
                if response.len() >= 4 {
                    let protocol_id = u16::from_be_bytes([response[2], response[3]]);
                    if protocol_id == 0 {
                        return PluginResult::detected("modbus")
                            .with_info("protocol", serde_json::json!("Modbus TCP"))
                            .with_info("unit_id", serde_json::json!(response.get(6).copied()));
                    }
                }
            }
            _ => {}
        }

        PluginResult::not_detected()
    }

    async fn check_vulnerabilities(&self, _host: IpAddr, _port: u16, _version: &str) -> Vec<String> {
        // Modbus has no authentication by design
        vec!["CWE-306".to_string()] // Missing Authentication
    }
}

/// Plugin registry
pub struct PluginRegistry {
    plugins: Vec<Box<dyn ProtocolPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(ModbusPlugin));
        registry
    }

    pub fn register(&mut self, plugin: Box<dyn ProtocolPlugin>) {
        self.plugins.push(plugin);
    }

    pub fn get(&self, name: &str) -> Option<&dyn ProtocolPlugin> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    pub fn list(&self) -> Vec<(&str, &str, &[u16])> {
        self.plugins
            .iter()
            .map(|p| (p.name(), p.description(), p.default_ports()))
            .collect()
    }

    /// Run all plugins against a host:port
    pub async fn detect_all(&self, host: IpAddr, port: u16) -> Vec<PluginResult> {
        let mut results = Vec::new();

        for plugin in &self.plugins {
            let result = plugin.detect(host, port).await;
            if result.detected {
                results.push(result);
            }
        }

        results
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}
