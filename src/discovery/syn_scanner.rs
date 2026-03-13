//! SYN Scanner - Masscan-style half-open port scanning
//!
//! Uses raw sockets to send SYN packets and detect open ports
//! with minimal network traffic (2 packets per port vs 6 for TCP connect).
//!
//! **Requires root/administrator privileges**

use anyhow::{anyhow, Result};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    transport_channel, tcp_packet_iter, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// SYN Scanner configuration
#[derive(Clone)]
pub struct SynScannerConfig {
    /// Timeout waiting for responses (ms)
    pub timeout_ms: u64,
    /// Packets per second rate limit
    pub rate_limit: u32,
    /// Number of retries for each port
    pub retries: u32,
    /// Source port for scanning
    pub source_port: u16,
}

impl Default for SynScannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 3000,
            rate_limit: 1000,
            retries: 2,
            source_port: 0, // Random
        }
    }
}

/// High-performance SYN scanner
pub struct SynScanner {
    config: SynScannerConfig,
}

/// Result of a SYN scan
#[derive(Debug, Clone)]
pub struct SynScanResult {
    pub open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub duration: Duration,
}

impl SynScanner {
    pub fn new() -> Self {
        Self {
            config: SynScannerConfig::default(),
        }
    }

    pub fn with_config(config: SynScannerConfig) -> Self {
        Self { config }
    }

    /// Check if we have raw socket privileges
    pub fn check_privileges() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(windows)]
        {
            // On Windows, check if we can create raw sockets
            use std::net::UdpSocket;
            // Simplified check - actual raw socket creation will fail if no admin
            true
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    /// Get the default network interface
    fn get_default_interface() -> Result<NetworkInterface> {
        let interfaces = datalink::interfaces();

        interfaces
            .into_iter()
            .find(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && !iface.ips.is_empty()
                    && iface.ips.iter().any(|ip| ip.is_ipv4())
            })
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    /// Get local IP address
    fn get_local_ip() -> Result<Ipv4Addr> {
        let iface = Self::get_default_interface()?;

        iface
            .ips
            .iter()
            .find_map(|ip| {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    Some(ipv4)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("No IPv4 address found"))
    }

    /// Perform SYN scan on target
    pub async fn scan(&self, target: Ipv4Addr, ports: &[u16]) -> Result<SynScanResult> {
        if !Self::check_privileges() {
            return Err(anyhow!(
                "SYN scan requires root/administrator privileges. \
                Use --method connect for unprivileged scanning."
            ));
        }

        let start_time = Instant::now();
        let source_ip = Self::get_local_ip()?;
        let source_port = if self.config.source_port == 0 {
            rand::thread_rng().gen_range(49152..65535)
        } else {
            self.config.source_port
        };

        info!(
            "Starting SYN scan: {} -> {} ({} ports)",
            source_ip,
            target,
            ports.len()
        );

        // Create transport channel
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Tcp,
        ));

        let (mut tx, mut rx) = transport_channel(4096, protocol)
            .map_err(|e| anyhow!("Failed to create transport channel: {}. Run as root.", e))?;

        // Track sent packets and responses
        let pending_ports: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
        let open_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let closed_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));

        let mut packets_sent = 0u64;
        let packets_received = Arc::new(Mutex::new(0u64));

        // Calculate delay between packets for rate limiting
        let delay_us = if self.config.rate_limit > 0 {
            1_000_000 / self.config.rate_limit as u64
        } else {
            0
        };

        // Send SYN packets
        for &port in ports {
            let packet = self.create_syn_packet(source_ip, source_port, target, port)?;

            {
                let mut pending = pending_ports.lock().await;
                pending.insert(port);
            }

            tx.send_to(packet, IpAddr::V4(target))
                .map_err(|e| anyhow!("Failed to send packet: {}", e))?;

            packets_sent += 1;

            if delay_us > 0 {
                tokio::time::sleep(Duration::from_micros(delay_us)).await;
            }
        }

        debug!("Sent {} SYN packets, waiting for responses...", packets_sent);

        // Receive responses with timeout
        let pending_clone = pending_ports.clone();
        let open_clone = open_ports.clone();
        let closed_clone = closed_ports.clone();
        let recv_count = packets_received.clone();
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        let receive_task = tokio::spawn(async move {
            Self::receive_responses(
                rx,
                target,
                source_port,
                pending_clone,
                open_clone,
                closed_clone,
                recv_count,
                timeout_duration,
            )
            .await
        });

        // Wait for receive task with timeout
        let _ = timeout(
            Duration::from_millis(self.config.timeout_ms + 1000),
            receive_task,
        )
        .await;

        // Remaining pending ports are filtered
        let filtered_ports: Vec<u16> = {
            let pending = pending_ports.lock().await;
            pending.iter().copied().collect()
        };

        let open = open_ports.lock().await.clone();
        let closed = closed_ports.lock().await.clone();
        let received = *packets_received.lock().await;

        Ok(SynScanResult {
            open_ports: open,
            closed_ports: closed,
            filtered_ports,
            packets_sent,
            packets_received: received,
            duration: start_time.elapsed(),
        })
    }

    /// Create a SYN packet
    fn create_syn_packet(
        &self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Result<MutableTcpPacket<'static>> {
        let mut tcp_buffer = vec![0u8; 20]; // TCP header without options
        let mut tcp_packet = MutableTcpPacket::owned(tcp_buffer)
            .ok_or_else(|| anyhow!("Failed to create TCP packet"))?;

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(rand::thread_rng().gen::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5); // 20 bytes / 4
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(65535);
        tcp_packet.set_urgent_ptr(0);

        // Calculate checksum
        let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
        tcp_packet.set_checksum(checksum);

        Ok(tcp_packet)
    }

    /// Receive and process responses
    async fn receive_responses(
        mut rx: TransportReceiver,
        target: Ipv4Addr,
        source_port: u16,
        pending: Arc<Mutex<HashSet<u16>>>,
        open: Arc<Mutex<Vec<u16>>>,
        closed: Arc<Mutex<Vec<u16>>>,
        recv_count: Arc<Mutex<u64>>,
        timeout_duration: Duration,
    ) {
        let start = Instant::now();
        let mut iter = tcp_packet_iter(&mut rx);

        while start.elapsed() < timeout_duration {
            // Check if we still have pending ports
            {
                let p = pending.lock().await;
                if p.is_empty() {
                    break;
                }
            }

            match iter.next_with_timeout(Duration::from_millis(100)) {
                Ok(Some((packet, addr))) => {
                    if addr != IpAddr::V4(target) {
                        continue;
                    }

                    if packet.get_destination() != source_port {
                        continue;
                    }

                    let port = packet.get_source();
                    let flags = packet.get_flags();

                    {
                        let mut p = pending.lock().await;
                        if !p.remove(&port) {
                            continue; // Not a port we're scanning
                        }
                    }

                    {
                        let mut count = recv_count.lock().await;
                        *count += 1;
                    }

                    // SYN-ACK = open, RST = closed
                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        debug!("Port {} is OPEN (SYN-ACK)", port);
                        let mut o = open.lock().await;
                        o.push(port);
                    } else if flags & TcpFlags::RST != 0 {
                        debug!("Port {} is CLOSED (RST)", port);
                        let mut c = closed.lock().await;
                        c.push(port);
                    }
                }
                Ok(None) => {
                    // Timeout, continue
                }
                Err(e) => {
                    warn!("Error receiving packet: {}", e);
                }
            }
        }
    }

    /// Quick scan using SYN method with fallback to connect
    pub async fn scan_with_fallback(
        &self,
        target: Ipv4Addr,
        ports: &[u16],
    ) -> Result<Vec<u16>> {
        match self.scan(target, ports).await {
            Ok(result) => Ok(result.open_ports),
            Err(e) => {
                warn!("SYN scan failed ({}), falling back to connect scan", e);
                // Fallback to TCP connect scan
                let scanner = super::PortScanner::with_config(
                    self.config.timeout_ms,
                    500,
                );
                scanner.scan_host(IpAddr::V4(target), ports).await
            }
        }
    }
}

impl Default for SynScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan method selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMethod {
    /// TCP connect scan (no privileges required)
    Connect,
    /// SYN scan (requires root/admin, pnet-based)
    Syn,
    /// AF_PACKET + MMAP zero-copy scan (Linux only, masscan-level performance)
    AfPacket,
    /// Auto-detect: try AF_PACKET -> SYN -> connect
    Auto,
}

impl std::str::FromStr for ScanMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "connect" | "tcp" => Ok(ScanMethod::Connect),
            "syn" | "stealth" | "half-open" => Ok(ScanMethod::Syn),
            "afpacket" | "af_packet" | "fast" | "mmap" => Ok(ScanMethod::AfPacket),
            "auto" => Ok(ScanMethod::Auto),
            _ => Err(anyhow!("Unknown scan method: {}", s)),
        }
    }
}

impl std::fmt::Display for ScanMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMethod::Connect => write!(f, "connect"),
            ScanMethod::Syn => write!(f, "syn"),
            ScanMethod::AfPacket => write!(f, "afpacket"),
            ScanMethod::Auto => write!(f, "auto"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_method_parse() {
        assert_eq!("syn".parse::<ScanMethod>().unwrap(), ScanMethod::Syn);
        assert_eq!("connect".parse::<ScanMethod>().unwrap(), ScanMethod::Connect);
        assert_eq!("auto".parse::<ScanMethod>().unwrap(), ScanMethod::Auto);
    }

    #[test]
    fn test_config_default() {
        let config = SynScannerConfig::default();
        assert_eq!(config.timeout_ms, 3000);
        assert_eq!(config.rate_limit, 1000);
    }
}
