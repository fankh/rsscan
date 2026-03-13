//! Service detection via banner grabbing for RsScan
//!
//! Provides protocol-specific detection with JSON-serializable output.
//! Supports: SSH, HTTP, FTP, SMB, MySQL, PostgreSQL, Redis, and more.

use super::models::{PortState, ServiceInfo, ParsedVersion};
use anyhow::Result;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};
use regex::Regex;

/// Service detector using banner grabbing
pub struct ServiceDetector {
    timeout: Duration,
}

/// Protocol probe definition
struct Probe {
    data: &'static [u8],
    wait_first: bool, // Wait for banner before sending
}

impl ServiceDetector {
    /// Service signatures for identification
    const SIGNATURES: &'static [(&'static [u8], &'static str)] = &[
        (b"SSH-", "ssh"),
        (b"HTTP/", "http"),
        (b"220 ", "ftp"),
        (b"220-", "ftp"),
        (b"+OK", "pop3"),
        (b"* OK", "imap"),
        (b"mysql", "mysql"),
        (b"PostgreSQL", "postgresql"),
        (b"redis_version", "redis"),
        (b"MongoDB", "mongodb"),
        (b"<html", "http"),
        (b"<!DOCTYPE", "http"),
        (b"SMTP", "smtp"),
        (b"554 ", "smtp"),
        (b"RFB ", "vnc"),
    ];

    /// HTTP probe
    const HTTP_PROBE: &'static [u8] = b"GET / HTTP/1.0\r\nHost: target\r\n\r\n";

    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Detect service on a port with JSON-serializable output
    pub async fn detect(&self, ip: IpAddr, port: u16) -> Result<ServiceInfo> {
        let addr = SocketAddr::new(ip, port);

        let mut info = ServiceInfo::new(port, "unknown");
        info.method = "banner-grab".to_string();

        // Use protocol-specific detection for known ports
        match port {
            445 | 139 => {
                // SMB detection
                return self.detect_smb(ip, port).await;
            }
            _ => {}
        }

        // Connect with timeout
        let stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!("Connection failed to {}:{}: {}", ip, port, e);
                info.state = PortState::Closed;
                return Ok(info);
            }
            Err(_) => {
                debug!("Connection timeout to {}:{}", ip, port);
                info.state = PortState::Filtered;
                return Ok(info);
            }
        };

        // Try to grab banner
        let banner = self.grab_banner(stream).await;

        if let Some(ref banner_data) = banner {
            info.banner = Some(
                String::from_utf8_lossy(&banner_data[..banner_data.len().min(256)])
                    .to_string()
            );

            // Identify service
            let (service, version, product, os) = self.identify_service(banner_data);
            info.service = service.clone();
            info.product = product;
            info.os = os;
            info.confidence = 0.85;

            // Parse version with OS/distro separation
            if let Some(ref ver) = version {
                let parsed = ParsedVersion::parse(ver);
                info.version = Some(ver.clone());
                info.parsed_version = Some(parsed.clone());

                // Add version metadata
                info.set_metadata("version_major", parsed.major);
                info.set_metadata("version_minor", parsed.minor);
                if let Some(ref distro) = parsed.distro {
                    info.set_metadata("distro", distro.clone());
                    info.os = Some(distro.clone());
                }
                if parsed.has_backport {
                    info.set_metadata("has_backport", true);
                }
            }

            // Add service-specific metadata
            self.add_service_metadata(&mut info, &service, banner_data);
        }

        // If still unknown, try common port mapping
        if info.service == "unknown" {
            info.service = Self::port_to_service(port).to_string();
            info.confidence = 0.5; // Lower confidence for port-based detection
            info.method = "port-mapping".to_string();
        }

        Ok(info)
    }

    /// Add service-specific metadata
    fn add_service_metadata(&self, info: &mut ServiceInfo, service: &str, banner: &[u8]) {
        let banner_str = String::from_utf8_lossy(banner);

        match service {
            "ssh" => {
                // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
                if let Some(proto) = banner_str.split('-').nth(1) {
                    info.set_metadata("protocol", proto.trim());
                }
                // Extract key exchange info if present
                info.set_metadata("banner_type", "ssh");
            }
            "http" => {
                // Extract headers as metadata
                let mut headers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
                for line in banner_str.lines().skip(1) {
                    if let Some((key, value)) = line.split_once(':') {
                        headers.insert(
                            key.trim().to_lowercase(),
                            value.trim().to_string()
                        );
                    }
                }
                if !headers.is_empty() {
                    info.set_metadata("headers", headers);
                }

                // Extract status code
                if let Some(first_line) = banner_str.lines().next() {
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(code) = parts[1].parse::<u16>() {
                            info.set_metadata("status_code", code);
                        }
                    }
                }
            }
            "mysql" => {
                // MySQL protocol metadata
                if banner.len() > 5 {
                    info.set_metadata("protocol_version", banner[4] as u32);
                }
            }
            "redis" => {
                // Parse Redis INFO response
                for line in banner_str.lines() {
                    if line.starts_with("os:") {
                        info.os = Some(line[3..].trim().to_string());
                    } else if line.starts_with("redis_mode:") {
                        info.set_metadata("mode", line[11..].trim().to_string());
                    }
                }
            }
            _ => {}
        }
    }

    async fn grab_banner(&self, mut stream: TcpStream) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; 1024];

        // First, try to receive banner (some services send immediately)
        match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                return Some(buffer);
            }
            _ => {}
        }

        // No immediate banner, send HTTP probe
        if stream.write_all(Self::HTTP_PROBE).await.is_ok() {
            let _ = stream.flush().await;

            buffer.resize(1024, 0);
            match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    buffer.truncate(n);
                    return Some(buffer);
                }
                _ => {}
            }
        }

        None
    }

    fn identify_service(&self, banner: &[u8]) -> (String, Option<String>, Option<String>, Option<String>) {
        let banner_lower: Vec<u8> = banner.iter().map(|b| b.to_ascii_lowercase()).collect();

        // Check signatures
        for (sig, service) in Self::SIGNATURES {
            let sig_lower: Vec<u8> = sig.iter().map(|b| b.to_ascii_lowercase()).collect();
            if banner_lower.windows(sig_lower.len()).any(|w| w == sig_lower.as_slice()) {
                let version = self.extract_version(service, banner);
                let product = self.extract_product(service, banner);
                let os = self.extract_os(service, banner);
                return (service.to_string(), version, product, os);
            }
        }

        ("unknown".to_string(), None, None, None)
    }

    fn extract_os(&self, service: &str, banner: &[u8]) -> Option<String> {
        let banner_str = String::from_utf8_lossy(banner);

        match service {
            "ssh" => {
                // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
                let version_part = banner_str.split('-').nth(2)?;
                // Check for common OS patterns
                if version_part.contains("Ubuntu") {
                    Some("Ubuntu".to_string())
                } else if version_part.contains("Debian") {
                    Some("Debian".to_string())
                } else if version_part.contains("FreeBSD") {
                    Some("FreeBSD".to_string())
                } else {
                    None
                }
            }
            "http" => {
                // Server: Apache/2.4.52 (Ubuntu)
                for line in banner_str.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        let server = line[7..].trim();
                        if server.contains("(Ubuntu)") {
                            return Some("Ubuntu".to_string());
                        } else if server.contains("(Debian)") {
                            return Some("Debian".to_string());
                        } else if server.contains("(CentOS)") || server.contains("(Red Hat)") {
                            return Some("RHEL".to_string());
                        } else if server.contains("(Win") {
                            return Some("Windows".to_string());
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn extract_version(&self, service: &str, banner: &[u8]) -> Option<String> {
        let banner_str = String::from_utf8_lossy(banner);

        match service {
            "ssh" => {
                // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
                // SSH-2.0-OpenSSH_9.0p1 Debian-1+deb12u1
                // Keep the full version string including OS suffix
                if let Some(version_part) = banner_str.split('-').nth(2) {
                    // Get everything after "OpenSSH_" or similar
                    let full_version = version_part
                        .trim()
                        .trim_end_matches(|c: char| c == '\r' || c == '\n');
                    Some(full_version.to_string())
                } else {
                    None
                }
            }
            "http" => {
                // Server: Apache/2.4.52-1ubuntu4.7 (Ubuntu)
                // Server: nginx/1.18.0 (Ubuntu)
                for line in banner_str.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        return Some(line[7..].trim().to_string());
                    }
                }
                None
            }
            "ftp" => {
                // 220 ProFTPD 1.3.5 Server ready.
                // 220 (vsFTPd 3.0.5)
                let parts: Vec<&str> = banner_str.split_whitespace().collect();
                if parts.len() >= 3 {
                    // Try to find version pattern
                    for (i, part) in parts.iter().enumerate() {
                        if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                            // Found version number, include product name before it
                            if i > 0 {
                                return Some(format!("{} {}", parts[i-1], part));
                            }
                            return Some(part.to_string());
                        }
                    }
                }
                None
            }
            "mysql" => {
                // Extract MySQL version from binary protocol
                // Version string is at the start after protocol version
                if banner.len() > 5 {
                    // Skip packet header (4 bytes) and protocol version (1 byte)
                    let version_bytes = &banner[5..];
                    if let Some(null_pos) = version_bytes.iter().position(|&b| b == 0) {
                        let version = String::from_utf8_lossy(&version_bytes[..null_pos]);
                        return Some(version.to_string());
                    }
                }
                None
            }
            "redis" => {
                // redis_version:7.0.5
                for line in banner_str.lines() {
                    if line.starts_with("redis_version:") {
                        return Some(line[14..].trim().to_string());
                    }
                }
                None
            }
            "postgresql" => {
                // PostgreSQL returns version in error message or during handshake
                if let Some(caps) = Regex::new(r"PostgreSQL\s+([\d.]+)")
                    .ok()
                    .and_then(|re| re.captures(&banner_str))
                {
                    return caps.get(1).map(|m| m.as_str().to_string());
                }
                None
            }
            _ => None,
        }
    }

    fn extract_product(&self, service: &str, banner: &[u8]) -> Option<String> {
        let banner_str = String::from_utf8_lossy(banner);

        match service {
            "ssh" => {
                // SSH-2.0-OpenSSH_8.9p1 -> OpenSSH
                banner_str.split('-').nth(2).and_then(|s| {
                    s.split('_').next().map(|p| p.to_string())
                })
            }
            "http" => {
                // Server: Apache/2.4.49 -> Apache
                for line in banner_str.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        let server = line[7..].trim();
                        return server.split('/').next().map(|s| s.to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Map common ports to services
    fn port_to_service(port: u16) -> &'static str {
        match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 => "http",
            110 => "pop3",
            111 => "rpcbind",
            135 => "msrpc",
            139 => "netbios-ssn",
            143 => "imap",
            443 => "https",
            445 => "microsoft-ds",
            993 => "imaps",
            995 => "pop3s",
            1433 => "mssql",
            1521 => "oracle",
            3306 => "mysql",
            3389 => "rdp",
            5432 => "postgresql",
            5900 => "vnc",
            6379 => "redis",
            8080 => "http-proxy",
            8443 => "https-alt",
            27017 => "mongodb",
            _ => "unknown",
        }
    }

    // ==================== SMB Detection ====================

    /// SMB2 Negotiate Request packet
    const SMB2_NEGOTIATE: &'static [u8] = &[
        // NetBIOS Session
        0x00, 0x00, 0x00, 0x66,  // Length (102 bytes)
        // SMB2 Header (64 bytes)
        0xfe, 0x53, 0x4d, 0x42,  // Magic: 0xFE "SMB"
        0x40, 0x00,              // Header Length: 64
        0x00, 0x00,              // Credit Charge
        0x00, 0x00, 0x00, 0x00,  // Status
        0x00, 0x00,              // Command: Negotiate (0x00)
        0x00, 0x00,              // Credits Requested
        0x00, 0x00, 0x00, 0x00,  // Flags
        0x00, 0x00, 0x00, 0x00,  // Next Command
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Message ID
        0x00, 0x00, 0x00, 0x00,  // Process ID
        0x00, 0x00, 0x00, 0x00,  // Tree ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Session ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Signature
        // Negotiate Request (38 bytes)
        0x24, 0x00,              // Structure Size: 36
        0x05, 0x00,              // Dialect Count: 5
        0x01, 0x00,              // Security Mode: Signing Enabled
        0x00, 0x00,              // Reserved
        0x00, 0x00, 0x00, 0x00,  // Capabilities
        // Client GUID (16 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x00, 0x00, 0x00, 0x00,  // Negotiate Context Offset
        0x00, 0x00,              // Negotiate Context Count
        0x00, 0x00,              // Reserved2
        // Dialects (10 bytes)
        0x02, 0x02,              // SMB 2.0.2
        0x10, 0x02,              // SMB 2.1
        0x00, 0x03,              // SMB 3.0
        0x02, 0x03,              // SMB 3.0.2
        0x11, 0x03,              // SMB 3.1.1
    ];

    /// SMB1 Negotiate Request packet
    const SMB1_NEGOTIATE: &'static [u8] = &[
        // NetBIOS Session
        0x00, 0x00, 0x00, 0x54,  // Length
        // SMB1 Header
        0xff, 0x53, 0x4d, 0x42,  // Magic: 0xFF "SMB"
        0x72,                     // Command: Negotiate (0x72)
        0x00, 0x00, 0x00, 0x00,  // Status
        0x18,                     // Flags
        0x53, 0xc8,              // Flags2
        0x00, 0x00,              // PID High
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Signature
        0x00, 0x00,              // Reserved
        0xff, 0xff,              // TID
        0x00, 0x00,              // PID
        0x00, 0x00,              // UID
        0x00, 0x00,              // MID
        // Negotiate Request
        0x00,                     // Word Count
        0x31, 0x00,              // Byte Count
        // Dialect strings
        0x02, b'P', b'C', b' ', b'N', b'E', b'T', b'W', b'O', b'R', b'K',
        b' ', b'P', b'R', b'O', b'G', b'R', b'A', b'M', b' ', b'1', b'.', b'0', 0x00,
        0x02, b'L', b'A', b'N', b'M', b'A', b'N', b'1', b'.', b'0', 0x00,
        0x02, b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2', 0x00,
    ];

    /// Detect SMB service with protocol-specific negotiation
    async fn detect_smb(&self, ip: IpAddr, port: u16) -> Result<ServiceInfo> {
        let addr = SocketAddr::new(ip, port);
        let mut info = ServiceInfo::new(port, "smb");
        info.method = "smb-negotiate".to_string();

        // Try SMBv2/3 first (modern servers)
        match self.try_smb2(addr).await {
            Ok(smb_info) => {
                info.version = Some(smb_info.dialect.clone());
                info.confidence = 0.95;
                info.product = Some("SMB".to_string());

                // Add metadata
                info.set_metadata("dialect", smb_info.dialect.clone());
                info.set_metadata("dialect_raw", format!("0x{:04x}", smb_info.dialect_raw));
                info.set_metadata("signing_required", smb_info.signing_required);
                info.set_metadata("signing_enabled", smb_info.signing_enabled);
                info.set_metadata("smb_version", 2);

                if let Some(ref guid) = smb_info.server_guid {
                    info.set_metadata("server_guid", guid.clone());
                }
                if let Some(ref caps) = smb_info.capabilities {
                    info.set_metadata("capabilities", caps.clone());
                }

                // Infer Windows version from dialect
                info.os = Some(Self::smb_dialect_to_os(smb_info.dialect_raw));

                return Ok(info);
            }
            Err(e) => {
                trace!("SMBv2 detection failed: {}, trying SMBv1", e);
            }
        }

        // Fallback to SMBv1
        match self.try_smb1(addr).await {
            Ok(smb_info) => {
                info.version = Some(smb_info.dialect.clone());
                info.confidence = 0.90;
                info.product = Some("SMB".to_string());

                info.set_metadata("dialect", smb_info.dialect.clone());
                info.set_metadata("smb_version", 1);

                if let Some(ref os) = smb_info.native_os {
                    info.os = Some(os.clone());
                    info.set_metadata("native_os", os.clone());
                }
                if let Some(ref lanman) = smb_info.native_lanman {
                    info.set_metadata("native_lanman", lanman.clone());
                }
                if let Some(ref domain) = smb_info.domain {
                    info.set_metadata("domain", domain.clone());
                }

                return Ok(info);
            }
            Err(e) => {
                debug!("SMBv1 detection failed: {}", e);
                info.confidence = 0.3;
                info.set_metadata("error", e.to_string());
            }
        }

        Ok(info)
    }

    /// Try SMBv2/3 negotiation
    async fn try_smb2(&self, addr: SocketAddr) -> Result<Smb2Info> {
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        stream.write_all(Self::SMB2_NEGOTIATE).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;

        if n < 72 {
            anyhow::bail!("Response too short: {} bytes", n);
        }

        // Check for SMB2 magic (0xFE 'SMB')
        if &buf[4..8] != b"\xfeSMB" {
            anyhow::bail!("Invalid SMB2 magic");
        }

        // Parse Negotiate Response
        // Dialect at offset 70-71 (relative to NetBIOS header)
        let dialect_raw = u16::from_le_bytes([buf[70], buf[71]]);
        let dialect = match dialect_raw {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0311 => "SMB 3.1.1",
            0x02FF => "SMB 2.???",
            _ => "Unknown",
        }.to_string();

        // Security mode at offset 72
        let security_mode = buf[72];
        let signing_enabled = (security_mode & 0x01) != 0;
        let signing_required = (security_mode & 0x02) != 0;

        // Server GUID at offset 76-91 (16 bytes)
        let server_guid = if n >= 92 {
            let guid = &buf[76..92];
            Some(format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
                u16::from_le_bytes([guid[4], guid[5]]),
                u16::from_le_bytes([guid[6], guid[7]]),
                guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
            ))
        } else {
            None
        };

        // Capabilities at offset 92-95
        let capabilities = if n >= 96 {
            let caps = u32::from_le_bytes([buf[92], buf[93], buf[94], buf[95]]);
            let mut cap_list = Vec::new();
            if caps & 0x01 != 0 { cap_list.push("DFS".to_string()); }
            if caps & 0x02 != 0 { cap_list.push("LEASING".to_string()); }
            if caps & 0x04 != 0 { cap_list.push("LARGE_MTU".to_string()); }
            if caps & 0x08 != 0 { cap_list.push("MULTI_CHANNEL".to_string()); }
            if caps & 0x10 != 0 { cap_list.push("PERSISTENT_HANDLES".to_string()); }
            if caps & 0x20 != 0 { cap_list.push("DIRECTORY_LEASING".to_string()); }
            if caps & 0x40 != 0 { cap_list.push("ENCRYPTION".to_string()); }
            Some(cap_list)
        } else {
            None
        };

        Ok(Smb2Info {
            dialect,
            dialect_raw,
            signing_required,
            signing_enabled,
            server_guid,
            capabilities,
        })
    }

    /// Try SMBv1 negotiation
    async fn try_smb1(&self, addr: SocketAddr) -> Result<Smb1Info> {
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        stream.write_all(Self::SMB1_NEGOTIATE).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;

        if n < 39 {
            anyhow::bail!("Response too short: {} bytes", n);
        }

        // Check for SMB1 magic (0xFF 'SMB')
        if &buf[4..8] != b"\xffSMB" {
            anyhow::bail!("Invalid SMB1 magic");
        }

        // Selected dialect index at offset 37-38
        let dialect_index = u16::from_le_bytes([buf[37], buf[38]]);
        let dialect = match dialect_index {
            0 => "PC NETWORK PROGRAM 1.0",
            1 => "LANMAN1.0",
            2 => "NT LM 0.12",
            0xFFFF => "No common dialect",
            _ => "Unknown",
        }.to_string();

        // For NT LM 0.12, parse extended response
        // Native OS and LanMan strings come after Session Setup, not Negotiate
        // Keep them as None for now

        Ok(Smb1Info {
            dialect,
            native_os: None,
            native_lanman: None,
            domain: None,
        })
    }

    /// Map SMB dialect to likely Windows version
    fn smb_dialect_to_os(dialect: u16) -> String {
        match dialect {
            0x0202 => "Windows Vista/Server 2008".to_string(),
            0x0210 => "Windows 7/Server 2008 R2".to_string(),
            0x0300 => "Windows 8/Server 2012".to_string(),
            0x0302 => "Windows 8.1/Server 2012 R2".to_string(),
            0x0311 => "Windows 10+/Server 2016+".to_string(),
            _ => "Windows".to_string(),
        }
    }
}

/// SMBv2 negotiation result
struct Smb2Info {
    dialect: String,
    dialect_raw: u16,
    signing_required: bool,
    signing_enabled: bool,
    server_guid: Option<String>,
    capabilities: Option<Vec<String>>,
}

/// SMBv1 negotiation result
struct Smb1Info {
    dialect: String,
    native_os: Option<String>,
    native_lanman: Option<String>,
    domain: Option<String>,
}

impl Default for ServiceDetector {
    fn default() -> Self {
        Self::new()
    }
}
