//! High-performance async port scanner

use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::debug;
use std::sync::Arc;

/// Async port scanner with configurable concurrency
pub struct PortScanner {
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    retries: u32,
}

impl PortScanner {
    /// Common ports for quick scan
    pub const TOP_PORTS: [u16; 25] = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 27017,
    ];

    /// Extended ports for thorough scan
    pub const EXTENDED_PORTS: [u16; 100] = [
        1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79,
        80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113,
        119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
        254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407,
        416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
        513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
        616, 617, 625, 631, 636, 646, 648, 666, 667, 668,
    ];

    pub fn new() -> Self {
        Self::with_config(1000, 500)
    }

    pub fn with_config(timeout_ms: u64, max_concurrent: usize) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            retries: 1,
        }
    }

    /// Check if a single port is open
    pub async fn check_port(&self, addr: SocketAddr) -> bool {
        let _permit = self.semaphore.acquire().await.unwrap();

        for attempt in 0..=self.retries {
            match timeout(self.timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => {
                    debug!("Port {} open on {}", addr.port(), addr.ip());
                    return true;
                }
                Ok(Err(_)) | Err(_) => {
                    if attempt < self.retries {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        false
    }

    /// Scan multiple ports on a single host
    pub async fn scan_host(&self, ip: IpAddr, ports: &[u16]) -> Result<Vec<u16>> {
        let open_ports: Vec<u16> = stream::iter(ports.iter().copied())
            .map(|port| {
                let addr = SocketAddr::new(ip, port);
                async move {
                    if self.check_port(addr).await {
                        Some(port)
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(self.semaphore.available_permits())
            .filter_map(|x| async move { x })
            .collect()
            .await;

        Ok(open_ports)
    }

    /// Scan a range of ports
    pub async fn scan_port_range(&self, ip: IpAddr, start: u16, end: u16) -> Result<Vec<u16>> {
        let ports: Vec<u16> = (start..=end).collect();
        self.scan_host(ip, &ports).await
    }

    /// Scan all 65535 ports
    pub async fn scan_all_ports(&self, ip: IpAddr) -> Result<Vec<u16>> {
        self.scan_port_range(ip, 1, 65535).await
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = PortScanner::new();
        assert_eq!(scanner.timeout, Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn test_localhost_scan() {
        let scanner = PortScanner::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // This will likely find no open ports in test environment
        let result = scanner.scan_host(ip, &[80, 443]).await;
        assert!(result.is_ok());
    }
}
