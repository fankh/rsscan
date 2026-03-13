//! CPE (Common Platform Enumeration) matching for RsScan.
//!
//! Implements CPE 2.3 parsing, matching, and a banner-to-CPE dictionary
//! for automatic service identification.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CpePart
// ---------------------------------------------------------------------------

/// CPE component type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpePart {
    Application,
    OperatingSystem,
    Hardware,
    Any,
}

impl CpePart {
    pub fn from_char(c: char) -> Self {
        match c {
            'a' => Self::Application,
            'o' => Self::OperatingSystem,
            'h' => Self::Hardware,
            _ => Self::Any,
        }
    }

    pub fn to_char(&self) -> char {
        match self {
            Self::Application => 'a',
            Self::OperatingSystem => 'o',
            Self::Hardware => 'h',
            Self::Any => '*',
        }
    }
}

impl fmt::Display for CpePart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_char())
    }
}

// ---------------------------------------------------------------------------
// Cpe
// ---------------------------------------------------------------------------

/// A parsed CPE 2.3 identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cpe {
    pub part: CpePart,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe {
    /// Parse a CPE 2.3 or 2.2 formatted string.
    ///
    /// CPE 2.3 format: `cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`
    /// CPE 2.2 format: `cpe:/part:vendor:product:version:...`
    pub fn parse(cpe_str: &str) -> Option<Self> {
        let s = cpe_str.trim();

        // CPE 2.3 formatted string
        if s.starts_with("cpe:2.3:") {
            let parts: Vec<&str> = s[8..].split(':').collect();
            if parts.len() < 4 {
                return None;
            }

            let part = CpePart::from_char(parts[0].chars().next().unwrap_or('*'));
            let get = |i: usize| -> String {
                parts
                    .get(i)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "*".to_string())
            };

            return Some(Self {
                part,
                vendor: get(1),
                product: get(2),
                version: get(3),
                update: get(4),
                edition: get(5),
                language: get(6),
                sw_edition: get(7),
                target_sw: get(8),
                target_hw: get(9),
                other: get(10),
            });
        }

        // CPE 2.2 URI format: cpe:/part:vendor:product:version:...
        if s.starts_with("cpe:/") {
            let parts: Vec<&str> = s[5..].split(':').collect();
            if parts.is_empty() {
                return None;
            }

            let first = parts[0];
            let part = if !first.is_empty() {
                CpePart::from_char(first.chars().next().unwrap_or('*'))
            } else {
                CpePart::Any
            };

            let get = |i: usize| -> String {
                parts
                    .get(i)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "*".to_string())
            };

            // In URI format, part prefix is on the vendor field
            let vendor = if first.len() > 1 {
                first[1..].to_string()
            } else {
                get(1)
            };

            return Some(Self {
                part,
                vendor,
                product: get(1),
                version: get(2),
                update: get(3),
                edition: get(4),
                language: get(5),
                sw_edition: "*".to_string(),
                target_sw: "*".to_string(),
                target_hw: "*".to_string(),
                other: "*".to_string(),
            });
        }

        None
    }

    /// Convert to CPE 2.3 formatted string.
    pub fn to_uri(&self) -> String {
        format!(
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other,
        )
    }

    /// Check if this CPE matches another CPE (wildcard-aware).
    pub fn matches(&self, other: &Cpe) -> bool {
        if self.part != CpePart::Any && other.part != CpePart::Any && self.part != other.part {
            return false;
        }

        Self::match_field(&self.vendor, &other.vendor)
            && Self::match_field(&self.product, &other.product)
            && self.version_matches(&other.version)
    }

    /// Match a single CPE field with wildcard support.
    pub fn match_field(a: &str, b: &str) -> bool {
        if a == "*" || b == "*" {
            return true;
        }
        if a == "-" || b == "-" {
            return a == b;
        }
        a.to_lowercase() == b.to_lowercase()
    }

    /// Check if version matches (with wildcard and prefix support).
    pub fn version_matches(&self, other_version: &str) -> bool {
        if self.version == "*" || other_version == "*" {
            return true;
        }
        if self.version == "-" || other_version == "-" {
            return self.version == other_version;
        }

        // Exact match
        if self.version.to_lowercase() == other_version.to_lowercase() {
            return true;
        }

        // Prefix match (e.g., "2.4" matches "2.4.54")
        let sv = self.version.to_lowercase();
        let ov = other_version.to_lowercase();
        if ov.starts_with(&sv) && ov[sv.len()..].starts_with('.') {
            return true;
        }
        if sv.starts_with(&ov) && sv[ov.len()..].starts_with('.') {
            return true;
        }

        false
    }
}

impl fmt::Display for Cpe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

// ---------------------------------------------------------------------------
// CpeMatch
// ---------------------------------------------------------------------------

/// A CPE match configuration (as used in NVD CVE data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeMatch {
    pub cpe: Cpe,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

impl CpeMatch {
    /// Check if a given version is affected by this match configuration.
    pub fn version_affected(&self, version: &str) -> bool {
        if version == "*" || version.is_empty() {
            return true; // Can't determine, assume affected
        }

        let v = SemanticVersion::parse(version);

        // Check start boundary
        if let Some(ref start) = self.version_start_including {
            let s = SemanticVersion::parse(start);
            if v < s {
                return false;
            }
        }
        if let Some(ref start) = self.version_start_excluding {
            let s = SemanticVersion::parse(start);
            if v <= s {
                return false;
            }
        }

        // Check end boundary
        if let Some(ref end) = self.version_end_including {
            let e = SemanticVersion::parse(end);
            if v > e {
                return false;
            }
        }
        if let Some(ref end) = self.version_end_excluding {
            let e = SemanticVersion::parse(end);
            if v >= e {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// SemanticVersion
// ---------------------------------------------------------------------------

/// A parsed semantic version for comparison.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SemanticVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: String,
}

impl SemanticVersion {
    /// Parse a version string.
    pub fn parse(s: &str) -> Self {
        let re = Regex::new(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[._-](.+))?$").unwrap();

        if let Some(caps) = re.captures(s.trim()) {
            Self {
                major: caps.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                minor: caps.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                patch: caps.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                pre: caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default(),
            }
        } else {
            Self {
                major: 0,
                minor: 0,
                patch: 0,
                pre: s.to_string(),
            }
        }
    }
}

impl Ord for SemanticVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| {
                // Empty pre-release is "greater" than any pre-release tag
                // (1.0.0 > 1.0.0-beta)
                match (self.pre.is_empty(), other.pre.is_empty()) {
                    (true, true) => Ordering::Equal,
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    (false, false) => self.pre.cmp(&other.pre),
                }
            })
    }
}

impl PartialOrd for SemanticVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// CpeDictionary
// ---------------------------------------------------------------------------

/// Maps service banners to CPE identifiers.
pub struct CpeDictionary {
    patterns: Vec<(Regex, String)>,
}

impl CpeDictionary {
    /// Create a new dictionary with built-in banner-to-CPE mappings.
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // SSH
        patterns.push((
            Regex::new(r"(?i)OpenSSH[_\s]+([\d]+(?:\.[\d]+)*(?:p\d+)?)").unwrap(),
            "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)dropbear[_\s]+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)libssh[_\s-]+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:libssh:libssh:{version}:*:*:*:*:*:*:*".to_string(),
        ));

        // HTTP servers
        patterns.push((
            Regex::new(r"(?i)Apache/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)nginx/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)Microsoft-IIS/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*"
                .to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)lighttpd/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)LiteSpeed/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:litespeedtech:litespeed_web_server:{version}:*:*:*:*:*:*:*".to_string(),
        ));

        // Databases
        patterns.push((
            Regex::new(r"(?i)MySQL/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)MariaDB/([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)PostgreSQL\s+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)Redis[:/\s]v?([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)MongoDB\s+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*".to_string(),
        ));

        // FTP
        patterns.push((
            Regex::new(r"(?i)vsFTPd\s+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:vsftpd_project:vsftpd:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)ProFTPD\s+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:proftpd:proftpd:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)Pure-FTPd").unwrap(),
            "cpe:2.3:a:pureftpd:pure-ftpd:*:*:*:*:*:*:*:*".to_string(),
        ));

        // Mail
        patterns.push((
            Regex::new(r"(?i)Postfix").unwrap(),
            "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)Exim\s+([\d]+(?:\.[\d]+)*)").unwrap(),
            "cpe:2.3:a:exim:exim:{version}:*:*:*:*:*:*:*".to_string(),
        ));
        patterns.push((
            Regex::new(r"(?i)Dovecot").unwrap(),
            "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*".to_string(),
        ));

        // OpenSSL (from TLS banners)
        patterns.push((
            Regex::new(r"(?i)OpenSSL/([\d]+(?:\.[\d]+)*[a-z]?)").unwrap(),
            "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*".to_string(),
        ));

        Self { patterns }
    }

    /// Look up a banner and return matching CPE identifiers.
    pub fn lookup(&self, banner: &str) -> Vec<Cpe> {
        let mut results = Vec::new();

        for (re, template) in &self.patterns {
            if let Some(caps) = re.captures(banner) {
                let version = caps
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or("*");
                let cpe_str = template.replace("{version}", version);
                if let Some(cpe) = Cpe::parse(&cpe_str) {
                    results.push(cpe);
                }
            }
        }

        results
    }

    /// Get a CPE for a known product/version pair.
    pub fn from_product_version(&self, product: &str, version: &str) -> Option<Cpe> {
        let banner = format!("{}/{}", product, version);
        self.lookup(&banner).into_iter().next()
    }

    /// Extract CPE from a service banner (convenience method, returns first match).
    pub fn from_banner(&self, banner: &str) -> Option<Cpe> {
        self.lookup(banner).into_iter().next()
    }
}

impl Default for CpeDictionary {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpe_parse_23() {
        let cpe = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.part, CpePart::Application);
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, "2.4.54");
    }

    #[test]
    fn test_cpe_parse_23_with_update() {
        let cpe = Cpe::parse("cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor, "openbsd");
        assert_eq!(cpe.product, "openssh");
        assert_eq!(cpe.version, "8.9");
        assert_eq!(cpe.update, "p1");
    }

    #[test]
    fn test_cpe_parse_22() {
        let cpe = Cpe::parse("cpe:/a:openbsd:openssh:8.9").unwrap();
        assert_eq!(cpe.part, CpePart::Application);
        assert_eq!(cpe.product, "openssh");
    }

    #[test]
    fn test_cpe_parse_invalid() {
        assert!(Cpe::parse("not-a-cpe").is_none());
        assert!(Cpe::parse("").is_none());
    }

    #[test]
    fn test_cpe_to_uri() {
        let cpe = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*").unwrap();
        let uri = cpe.to_uri();
        assert!(uri.starts_with("cpe:2.3:a:apache:http_server:2.4.54:"));
    }

    #[test]
    fn test_cpe_matches_exact() {
        let a = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*").unwrap();
        let b = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*").unwrap();
        assert!(a.matches(&b));
    }

    #[test]
    fn test_cpe_matches_wildcard() {
        let a = Cpe::parse("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*").unwrap();
        let b = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*").unwrap();
        assert!(a.matches(&b));
    }

    #[test]
    fn test_cpe_no_match_different_product() {
        let a = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*").unwrap();
        let b = Cpe::parse("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*").unwrap();
        assert!(!a.matches(&b));
    }

    #[test]
    fn test_cpe_version_prefix_match() {
        let a = Cpe::parse("cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*").unwrap();
        assert!(a.version_matches("2.4.54"));
    }

    #[test]
    fn test_match_field_wildcard() {
        assert!(Cpe::match_field("*", "anything"));
        assert!(Cpe::match_field("anything", "*"));
    }

    #[test]
    fn test_match_field_na() {
        assert!(Cpe::match_field("-", "-"));
        assert!(!Cpe::match_field("-", "value"));
    }

    #[test]
    fn test_match_field_case_insensitive() {
        assert!(Cpe::match_field("Apache", "apache"));
        assert!(Cpe::match_field("NGINX", "nginx"));
    }

    #[test]
    fn test_cpe_match_version_affected() {
        let m = CpeMatch {
            cpe: Cpe::parse("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*").unwrap(),
            vulnerable: true,
            version_start_including: Some("2.4.49".to_string()),
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: Some("2.4.52".to_string()),
        };

        assert!(m.version_affected("2.4.49"));
        assert!(m.version_affected("2.4.50"));
        assert!(m.version_affected("2.4.51"));
        assert!(!m.version_affected("2.4.52")); // excluded
        assert!(!m.version_affected("2.4.48")); // before start
    }

    #[test]
    fn test_cpe_match_version_including() {
        let m = CpeMatch {
            cpe: Cpe::parse("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*").unwrap(),
            vulnerable: true,
            version_start_including: Some("8.0".to_string()),
            version_start_excluding: None,
            version_end_including: Some("8.9".to_string()),
            version_end_excluding: None,
        };

        assert!(m.version_affected("8.0"));
        assert!(m.version_affected("8.5"));
        assert!(m.version_affected("8.9"));
        assert!(!m.version_affected("9.0"));
        assert!(!m.version_affected("7.9"));
    }

    #[test]
    fn test_semantic_version_parse() {
        let v = SemanticVersion::parse("2.4.54");
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 4);
        assert_eq!(v.patch, 54);
        assert!(v.pre.is_empty());
    }

    #[test]
    fn test_semantic_version_with_pre() {
        let v = SemanticVersion::parse("1.0.0-beta1");
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
        assert_eq!(v.pre, "beta1");
    }

    #[test]
    fn test_semantic_version_ordering() {
        let v1 = SemanticVersion::parse("1.0.0");
        let v2 = SemanticVersion::parse("2.0.0");
        assert!(v1 < v2);

        let v3 = SemanticVersion::parse("1.1.0");
        assert!(v1 < v3);
        assert!(v3 < v2);

        let v4 = SemanticVersion::parse("1.0.1");
        assert!(v1 < v4);
        assert!(v4 < v3);
    }

    #[test]
    fn test_semantic_version_pre_release_ordering() {
        let release = SemanticVersion::parse("1.0.0");
        let beta = SemanticVersion::parse("1.0.0-beta");
        // Release is greater than pre-release
        assert!(release > beta);
    }

    #[test]
    fn test_semantic_version_basic_compare() {
        let v1 = SemanticVersion::parse("8.9");
        let v2 = SemanticVersion::parse("9.0");
        let v3 = SemanticVersion::parse("8.9p1");

        assert!(v1 < v2);
        assert!(v3 < v2);
    }

    #[test]
    fn test_cpe_part_from_char() {
        assert_eq!(CpePart::from_char('a'), CpePart::Application);
        assert_eq!(CpePart::from_char('o'), CpePart::OperatingSystem);
        assert_eq!(CpePart::from_char('h'), CpePart::Hardware);
        assert_eq!(CpePart::from_char('x'), CpePart::Any);
    }

    #[test]
    fn test_dictionary_ssh() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("SSH-2.0-OpenSSH_8.9p1");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "openssh");
        assert_eq!(cpes[0].version, "8.9p1");
    }

    #[test]
    fn test_dictionary_apache() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("Apache/2.4.54 (Ubuntu)");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "http_server");
        assert_eq!(cpes[0].version, "2.4.54");
    }

    #[test]
    fn test_dictionary_nginx() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("nginx/1.24.0");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "nginx");
    }

    #[test]
    fn test_dictionary_redis() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("Redis:v7.0.5");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "redis");
        assert_eq!(cpes[0].version, "7.0.5");
    }

    #[test]
    fn test_dictionary_mysql() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("MySQL/8.0.33");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "mysql");
    }

    #[test]
    fn test_dictionary_no_match() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("UnknownService/1.0");
        assert!(cpes.is_empty());
    }

    #[test]
    fn test_dictionary_openssl() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("OpenSSL/3.0.7");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "openssl");
        assert_eq!(cpes[0].version, "3.0.7");
    }

    #[test]
    fn test_dictionary_from_product_version() {
        let dict = CpeDictionary::new();
        let cpe = dict.from_product_version("nginx", "1.24.0");
        assert!(cpe.is_some());
    }

    #[test]
    fn test_dictionary_from_banner() {
        let dict = CpeDictionary::new();
        let cpe = dict.from_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu").unwrap();
        assert_eq!(cpe.vendor, "openbsd");
        assert_eq!(cpe.product, "openssh");
        assert_eq!(cpe.version, "8.9p1");

        let cpe = dict.from_banner("Apache/2.4.49 (Ubuntu)").unwrap();
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, "2.4.49");
    }

    #[test]
    fn test_dictionary_dropbear() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("SSH-2.0-dropbear_2022.83");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "dropbear_ssh");
    }

    #[test]
    fn test_dictionary_vsftpd() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("220 (vsFTPd 3.0.5)");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].version, "3.0.5");
    }

    #[test]
    fn test_dictionary_proftpd() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("220 ProFTPD 1.3.8 Server");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].version, "1.3.8");
    }

    #[test]
    fn test_dictionary_postfix() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("220 mail.example.com ESMTP Postfix");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].vendor, "postfix");
    }

    #[test]
    fn test_dictionary_exim() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("220 mail.example.com ESMTP Exim 4.96");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "exim");
        assert_eq!(cpes[0].version, "4.96");
    }

    #[test]
    fn test_dictionary_iis() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("Microsoft-IIS/10.0");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "internet_information_services");
    }

    #[test]
    fn test_dictionary_mariadb() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("MariaDB/10.11.4");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "mariadb");
        assert_eq!(cpes[0].version, "10.11.4");
    }

    #[test]
    fn test_dictionary_postgresql() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("PostgreSQL 15.3");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "postgresql");
        assert_eq!(cpes[0].version, "15.3");
    }

    #[test]
    fn test_dictionary_lighttpd() {
        let dict = CpeDictionary::new();
        let cpes = dict.lookup("lighttpd/1.4.71");
        assert!(!cpes.is_empty());
        assert_eq!(cpes[0].product, "lighttpd");
    }
}
