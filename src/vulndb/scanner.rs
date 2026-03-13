//! Vulnerability Scanner - matches services to CVEs

use super::database::CveDatabase;
use super::models::{Confidence, Severity, VulnMatch, VulnReport, Vulnerability};
use crate::discovery::Host;
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use tracing::debug;

/// Vulnerability scanner that matches discovered services to CVEs
pub struct VulnerabilityScanner<'a> {
    cve_db: &'a CveDatabase,
}

impl<'a> VulnerabilityScanner<'a> {
    /// Service to product name mapping
    const SERVICE_PRODUCTS: &'static [(&'static str, &'static [&'static str])] = &[
        ("ssh", &["openssh", "ssh", "dropbear"]),
        ("http", &["apache", "nginx", "iis", "httpd", "lighttpd"]),
        ("https", &["apache", "nginx", "iis", "httpd", "openssl"]),
        ("ftp", &["proftpd", "vsftpd", "pureftpd", "filezilla"]),
        ("mysql", &["mysql", "mariadb"]),
        ("postgresql", &["postgresql", "postgres"]),
        ("redis", &["redis"]),
        ("mongodb", &["mongodb", "mongo"]),
        ("smtp", &["postfix", "sendmail", "exim"]),
    ];

    pub fn new(cve_db: &'a CveDatabase) -> Self {
        Self { cve_db }
    }

    /// Scan a host for vulnerabilities
    pub fn scan_host(&self, host: &Host) -> Result<Vec<VulnMatch>> {
        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        for (port, service_info) in &host.services {
            let service = &service_info.service;
            let version = service_info.version.as_deref().unwrap_or("");

            // Get products to search for this service
            let mut products: Vec<String> = Self::SERVICE_PRODUCTS
                .iter()
                .find(|(s, _)| *s == service)
                .map(|(_, p)| p.iter().map(|s| s.to_string()).collect())
                .unwrap_or_else(|| vec![service.clone()]);

            // Extract product from version string
            if let Some(product) = service_info.product.as_ref() {
                if !products.iter().any(|p| p.eq_ignore_ascii_case(product)) {
                    products.push(product.to_lowercase());
                }
            }

            // Also try to extract from banner
            if let Some(banner) = &service_info.banner {
                if let Some(extracted) = self.extract_product_from_banner(banner) {
                    if !products.iter().any(|p| p.eq_ignore_ascii_case(&extracted)) {
                        products.push(extracted);
                    }
                }
            }

            for product in &products {
                let vulns = self.cve_db.search(product, Some(version), Severity::Low)?;

                for vuln in vulns {
                    let key = (host.ip, *port, vuln.cve_id.clone());
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);

                    let confidence = self.calculate_confidence(service, version, product, &vuln);

                    matches.push(VulnMatch {
                        host: host.ip,
                        port: *port,
                        service: service.clone(),
                        version: version.to_string(),
                        vulnerability: vuln,
                        confidence,
                    });
                }
            }
        }

        debug!(
            "Found {} vulnerabilities for host {}",
            matches.len(),
            host.ip
        );
        Ok(matches)
    }

    /// Scan multiple hosts and generate report
    pub fn scan_hosts(&self, hosts: &[Host]) -> Result<VulnReport> {
        let mut report = VulnReport::new();

        for host in hosts {
            let matches = self.scan_host(host)?;
            for m in matches {
                report.add_match(m);
            }
        }

        Ok(report)
    }

    fn extract_product_from_banner(&self, banner: &str) -> Option<String> {
        // Common patterns: Apache/2.4.49, OpenSSH_8.9p1, nginx/1.21.0
        let re = Regex::new(r"^(\w+)[/_-][\d\.]+").ok()?;
        re.captures(banner)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase())
    }

    fn calculate_confidence(
        &self,
        _service: &str,
        version: &str,
        _product: &str,
        vuln: &Vulnerability,
    ) -> Confidence {
        // High confidence: exact product and version range match
        if !version.is_empty() && vuln.version_start.is_some() && vuln.version_end.is_some() {
            return Confidence::High;
        }

        // Medium confidence: product match with version
        if !version.is_empty() {
            return Confidence::Medium;
        }

        // Low confidence: only service type match
        Confidence::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_product() {
        let scanner_db = CveDatabase::in_memory().unwrap();
        let scanner = VulnerabilityScanner::new(&scanner_db);

        assert_eq!(
            scanner.extract_product_from_banner("Apache/2.4.49"),
            Some("apache".to_string())
        );
        assert_eq!(
            scanner.extract_product_from_banner("OpenSSH_8.9p1"),
            Some("openssh".to_string())
        );
        assert_eq!(
            scanner.extract_product_from_banner("nginx/1.21.0"),
            Some("nginx".to_string())
        );
    }
}
