//! CVE Database with NVD sync and external source support
//!
//! Enterprise-grade vulnerability management with:
//! - Risk scoring (CVSS × Confidence × Exploitability × Asset Criticality)
//! - EPSS (Exploit Prediction Scoring System) integration
//! - CISA KEV (Known Exploited Vulnerabilities) prioritization
//! - CPE-based accurate matching
//! - False positive reduction
//! - Remediation tracking

use super::models::{Severity, Vulnerability};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

/// Sync source configuration
#[derive(Debug, Clone)]
pub enum SyncSource {
    /// NVD (National Vulnerability Database)
    Nvd { api_key: Option<String> },
    /// External REST API
    ExternalApi {
        url: String,
        api_key: Option<String>,
        headers: Vec<(String, String)>,
    },
    /// JSON file import
    JsonFile { path: String },
    /// Another SQLite database
    SqliteDb { path: String },
    /// CISA Known Exploited Vulnerabilities
    Kev,
    /// EPSS bulk CSV download
    Epss,
    /// NVD GitHub mirror (local clone)
    GithubMirror { path: String },
    /// NVD GitHub mirror (download via HTTP)
    GithubMirrorUrl,
}

/// External API response format (configurable)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalCveResponse {
    #[serde(default)]
    pub total: Option<u32>,
    #[serde(alias = "vulnerabilities", alias = "cves", alias = "data", alias = "items")]
    pub vulnerabilities: Vec<ExternalCve>,
    #[serde(default)]
    pub next_page: Option<String>,
}

/// External CVE format (flexible schema)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalCve {
    #[serde(alias = "cve_id", alias = "id", alias = "cveId")]
    pub cve_id: String,
    #[serde(alias = "severity", alias = "risk", default)]
    pub severity: Option<String>,
    #[serde(alias = "cvss_score", alias = "cvss", alias = "score", default)]
    pub cvss_score: Option<f32>,
    #[serde(alias = "cvss_vector", alias = "vector_string", default)]
    pub cvss_vector: Option<String>,
    #[serde(alias = "description", alias = "desc", alias = "summary", default)]
    pub description: Option<String>,
    #[serde(alias = "product", alias = "affected_product", default)]
    pub product: Option<String>,
    #[serde(alias = "vendor", alias = "manufacturer", default)]
    pub vendor: Option<String>,
    #[serde(alias = "version_start", alias = "affected_from", default)]
    pub version_start: Option<String>,
    #[serde(alias = "version_end", alias = "affected_to", default)]
    pub version_end: Option<String>,
    #[serde(alias = "version_start_type", default)]
    pub version_start_type: Option<String>,  // "including" or "excluding"
    #[serde(alias = "version_end_type", default)]
    pub version_end_type: Option<String>,    // "including" or "excluding"
    #[serde(alias = "fix_version", alias = "patched_version", default)]
    pub fix_version: Option<String>,
    #[serde(alias = "published", alias = "published_date", alias = "pub_date", default)]
    pub published: Option<String>,
    #[serde(alias = "modified", alias = "last_modified", alias = "updated", default)]
    pub modified: Option<String>,
    #[serde(alias = "cpe", alias = "cpe_list", default)]
    pub cpe: Option<Vec<String>>,
    #[serde(alias = "epss_score", alias = "epss", default)]
    pub epss_score: Option<f32>,
    #[serde(alias = "epss_percentile", default)]
    pub epss_percentile: Option<f32>,
    #[serde(alias = "kev", alias = "known_exploited", alias = "cisa_kev", default)]
    pub is_kev: Option<bool>,
    #[serde(alias = "exploit_available", alias = "has_exploit", default)]
    pub exploit_available: Option<bool>,
    #[serde(alias = "references", alias = "refs", default)]
    pub references: Option<Vec<String>>,
    #[serde(alias = "cwe_id", alias = "cwe", default)]
    pub cwe_id: Option<String>,
}

/// Sync statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncStats {
    pub source: String,
    pub total_processed: usize,
    pub inserted: usize,
    pub updated: usize,
    pub skipped: usize,
    pub errors: usize,
    pub duration_ms: u64,
}

/// Parsed version data for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedVersionData {
    /// Core upstream version (e.g., "8.9p1")
    pub core: String,
    /// Major version number
    pub major: Option<u32>,
    /// Minor version number
    pub minor: Option<u32>,
    /// Patch version number
    pub patch: Option<u32>,
    /// OS/Distro name (e.g., "Ubuntu", "Debian", "RHEL")
    pub distro: Option<String>,
    /// Distro-specific version/patch level
    pub distro_version: Option<String>,
    /// Whether this version likely has backported patches
    pub has_backport: bool,
}

/// CVE Database manager
pub struct CveDatabase {
    conn: Connection,
    api_key: Option<String>,
}

/// NVD API response structures
#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: u32,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    configurations: Option<Vec<NvdConfiguration>>,
    published: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_v30: Option<Vec<CvssMetric>>,
}

#[derive(Debug, Deserialize)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f32,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
struct NvdNode {
    #[serde(rename = "cpeMatch")]
    cpe_match: Option<Vec<CpeMatch>>,
}

#[derive(Debug, Deserialize)]
struct CpeMatch {
    criteria: String,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

impl CveDatabase {
    const NVD_API_URL: &'static str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// Create or open database
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let db = Self { conn, api_key: None };
        db.init_schema()?;
        Ok(db)
    }

    /// Create in-memory database
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn, api_key: None };
        db.init_schema()?;
        Ok(db)
    }

    /// Set NVD API key for faster syncing
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            -- CVE vulnerabilities table (enhanced)
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                cvss_vector TEXT,              -- CVSS vector string for detailed analysis
                description TEXT,
                product TEXT,
                vendor TEXT,
                version_start TEXT,
                version_end TEXT,
                version_start_type TEXT DEFAULT 'including',  -- 'including' or 'excluding'
                version_end_type TEXT DEFAULT 'including',    -- 'including' or 'excluding'
                fix_version TEXT,              -- First fixed version (for remediation)
                published TEXT,
                modified TEXT,
                -- Exploitability indicators
                epss_score REAL DEFAULT 0,     -- EPSS probability (0-1)
                epss_percentile REAL DEFAULT 0, -- EPSS percentile (0-100)
                is_kev INTEGER DEFAULT 0,      -- CISA Known Exploited Vulnerability
                exploit_available INTEGER DEFAULT 0, -- Public exploit exists
                -- Metadata
                cwe_id TEXT,                   -- CWE classification
                references TEXT,               -- JSON array of reference URLs
                last_sync TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_product ON vulnerabilities(product);
            CREATE INDEX IF NOT EXISTS idx_vendor ON vulnerabilities(vendor);
            CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);
            CREATE INDEX IF NOT EXISTS idx_cvss ON vulnerabilities(cvss_score);
            CREATE INDEX IF NOT EXISTS idx_epss ON vulnerabilities(epss_score);
            CREATE INDEX IF NOT EXISTS idx_kev ON vulnerabilities(is_kev);
            CREATE INDEX IF NOT EXISTS idx_published ON vulnerabilities(published);

            -- CPE entries for accurate matching
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                cpe23_uri TEXT NOT NULL,       -- Full CPE 2.3 URI
                vendor TEXT,
                product TEXT,
                version TEXT,
                version_start TEXT,
                version_end TEXT,
                version_start_type TEXT,
                version_end_type TEXT,
                vulnerable INTEGER DEFAULT 1,
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_matches(cve_id);
            CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_matches(product);
            CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_matches(vendor, product);

            CREATE TABLE IF NOT EXISTS sync_status (
                id INTEGER PRIMARY KEY,
                source TEXT,
                last_sync TEXT,
                total_cves INTEGER,
                epss_last_sync TEXT,
                kev_last_sync TEXT
            );

            -- Discovered assets table (Step 1: Port Scan)
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                hostname TEXT,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                state TEXT DEFAULT 'open',
                scan_id TEXT,
                -- Asset classification
                criticality INTEGER DEFAULT 3,  -- 1=critical, 2=high, 3=medium, 4=low
                asset_type TEXT,               -- server, workstation, network, iot, etc.
                environment TEXT,              -- production, staging, development
                owner TEXT,
                tags TEXT,                     -- JSON array of tags
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, port, protocol, scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
            CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);

            -- Service information table (Step 2: Banner Grab)
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,              -- Full version string
                version_core TEXT,         -- Core version without OS suffix (for CVE matching)
                version_major INTEGER,     -- Major version number
                version_minor INTEGER,     -- Minor version number
                version_patch INTEGER,     -- Patch version number
                distro TEXT,               -- OS/Distro name (Ubuntu, Debian, RHEL)
                distro_version TEXT,       -- Distro-specific patch level
                has_backport INTEGER DEFAULT 0,  -- 1 if likely has backported patches
                banner TEXT,
                cpe TEXT,
                -- Additional detection data
                ssl_enabled INTEGER DEFAULT 0,
                ssl_version TEXT,
                fingerprint TEXT,          -- Service fingerprint hash
                extra_info TEXT,           -- JSON with additional data
                grabbed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id);
            CREATE INDEX IF NOT EXISTS idx_services_product ON services(product);
            CREATE INDEX IF NOT EXISTS idx_services_cpe ON services(cpe);

            -- Vulnerability matches table (Step 3: CVE Match) - Enhanced
            CREATE TABLE IF NOT EXISTS vuln_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                -- Confidence scoring
                confidence REAL,           -- Numeric confidence 0-1
                confidence_level TEXT,     -- high/medium/low
                match_type TEXT,           -- cpe, product, fuzzy
                -- Risk scoring
                risk_score REAL,           -- Combined risk score
                risk_factors TEXT,         -- JSON: {cvss, confidence, epss, kev, criticality}
                -- Status tracking
                status TEXT DEFAULT 'open', -- open, confirmed, false_positive, remediated, accepted
                verified_at TEXT,
                verified_by TEXT,
                remediation_notes TEXT,
                -- Timestamps
                matched_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id),
                UNIQUE(service_id, cve_id)
            );

            CREATE INDEX IF NOT EXISTS idx_vuln_matches_service ON vuln_matches(service_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_matches_cve ON vuln_matches(cve_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_matches_risk ON vuln_matches(risk_score);
            CREATE INDEX IF NOT EXISTS idx_vuln_matches_status ON vuln_matches(status);

            -- Scan history table (enhanced)
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT DEFAULT 'full',  -- full, discovery, service, vuln
                step INTEGER DEFAULT 1,
                status TEXT DEFAULT 'running',
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                -- Statistics
                total_hosts INTEGER DEFAULT 0,
                total_ports INTEGER DEFAULT 0,
                total_services INTEGER DEFAULT 0,
                total_vulns INTEGER DEFAULT 0,
                -- Risk summary
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                max_risk_score REAL DEFAULT 0,
                -- Configuration
                config TEXT                -- JSON scan configuration
            );

            -- False positive tracking
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                product TEXT,
                version_pattern TEXT,      -- Regex pattern for version
                reason TEXT,
                created_by TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT            -- Optional expiration
            );

            CREATE INDEX IF NOT EXISTS idx_fp_cve ON false_positives(cve_id);
            CREATE INDEX IF NOT EXISTS idx_fp_product ON false_positives(product);

            -- Remediation tracking
            CREATE TABLE IF NOT EXISTS remediations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                product TEXT,
                fix_version TEXT,
                workaround TEXT,
                vendor_advisory TEXT,
                patch_url TEXT,
                priority INTEGER DEFAULT 3,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
            );

            CREATE INDEX IF NOT EXISTS idx_remediation_cve ON remediations(cve_id);

            -- CISA KEV catalog (detailed entries)
            CREATE TABLE IF NOT EXISTS kev_catalog (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                due_date TEXT,
                known_ransomware TEXT,
                notes TEXT
            );

            -- EPSS historical scores
            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT,
                score_date TEXT,
                epss REAL,
                percentile REAL,
                PRIMARY KEY (cve_id, score_date)
            );

            CREATE INDEX IF NOT EXISTS idx_epss_scores_date ON epss_scores(score_date);
            "#,
        )?;

        // Migration: add priority_tier column if not exists
        let has_priority_tier: bool = self.conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('vulnerabilities') WHERE name = 'priority_tier'")?
            .query_row([], |row| row.get::<_, i64>(0))
            .unwrap_or(0) > 0;

        if !has_priority_tier {
            self.conn.execute_batch(
                "ALTER TABLE vulnerabilities ADD COLUMN priority_tier INTEGER DEFAULT 4;
                 CREATE INDEX IF NOT EXISTS idx_priority_tier ON vulnerabilities(priority_tier);"
            )?;
        }

        Ok(())
    }

    /// Sync CVEs from NVD
    pub async fn sync_from_nvd(&self, days_back: i64) -> Result<usize> {
        let start_date = Utc::now() - Duration::days(days_back);
        let end_date = Utc::now();

        info!("Syncing CVEs from NVD (last {} days)", days_back);

        let client = reqwest::Client::new();
        let mut total_synced = 0;
        let mut start_index = 0;
        let results_per_page = 2000;

        loop {
            let mut request = client
                .get(Self::NVD_API_URL)
                .query(&[
                    ("pubStartDate", start_date.format("%Y-%m-%dT00:00:00.000").to_string()),
                    ("pubEndDate", end_date.format("%Y-%m-%dT23:59:59.999").to_string()),
                    ("resultsPerPage", results_per_page.to_string()),
                    ("startIndex", start_index.to_string()),
                ]);

            if let Some(ref key) = self.api_key {
                request = request.header("apiKey", key);
            }

            let response = request.send().await?;

            if response.status() == 403 {
                warn!("NVD API rate limited, waiting 30 seconds...");
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }

            if !response.status().is_success() {
                anyhow::bail!("NVD API error: {}", response.status());
            }

            let data: NvdResponse = response.json().await?;

            if data.vulnerabilities.is_empty() {
                break;
            }

            let count = self.store_vulnerabilities(&data.vulnerabilities)?;
            total_synced += count;

            info!("Synced {} CVEs (total: {})", count, total_synced);

            if start_index + data.vulnerabilities.len() as u32 >= data.total_results {
                break;
            }

            start_index += results_per_page;

            // Rate limiting
            let delay = if self.api_key.is_some() { 600 } else { 6000 };
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, last_sync, total_cves) VALUES (1, ?, ?)",
            params![Utc::now().to_rfc3339(), total_synced as i64],
        )?;

        info!("CVE sync complete: {} vulnerabilities", total_synced);
        Ok(total_synced)
    }

    fn store_vulnerabilities(&self, vulns: &[NvdVulnerability]) -> Result<usize> {
        let mut count = 0;

        for item in vulns {
            let cve = &item.cve;

            // Get CVSS score and severity
            let (score, severity) = self.extract_cvss(&cve.metrics);

            // Get English description
            let description = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_default();

            // Get affected products
            if let Some(configs) = &cve.configurations {
                for config in configs {
                    for node in &config.nodes {
                        if let Some(matches) = &node.cpe_match {
                            for m in matches {
                                let (vendor, product) = self.parse_cpe(&m.criteria);

                                let version_start = m
                                    .version_start_including
                                    .as_ref()
                                    .or(m.version_start_excluding.as_ref());
                                let version_end = m
                                    .version_end_including
                                    .as_ref()
                                    .or(m.version_end_excluding.as_ref());

                                self.conn.execute(
                                    r#"
                                    INSERT OR REPLACE INTO vulnerabilities
                                    (cve_id, severity, cvss_score, description, product, vendor,
                                     version_start, version_end, published, modified)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    "#,
                                    params![
                                        cve.id,
                                        severity.to_string(),
                                        score,
                                        &description[..description.len().min(2000)],
                                        product,
                                        vendor,
                                        version_start,
                                        version_end,
                                        cve.published,
                                        cve.last_modified,
                                    ],
                                )?;
                                count += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    fn extract_cvss(&self, metrics: &Option<NvdMetrics>) -> (f32, Severity) {
        if let Some(m) = metrics {
            // Try CVSS v3.1 first, then v3.0
            let cvss = m.cvss_v31.as_ref().or(m.cvss_v30.as_ref());

            if let Some(metrics) = cvss {
                if let Some(first) = metrics.first() {
                    let score = first.cvss_data.base_score;
                    let severity = first
                        .cvss_data
                        .base_severity
                        .as_ref()
                        .map(|s| Severity::from_str(s))
                        .unwrap_or_else(|| Severity::from_cvss(score));
                    return (score, severity);
                }
            }
        }
        (0.0, Severity::Low)
    }

    fn parse_cpe(&self, cpe: &str) -> (Option<String>, Option<String>) {
        // cpe:2.3:a:vendor:product:version:...
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() >= 5 {
            let vendor = if parts[3] != "*" { Some(parts[3].to_string()) } else { None };
            let product = if parts[4] != "*" { Some(parts[4].to_string()) } else { None };
            return (vendor, product);
        }
        (None, None)
    }

    /// Search for vulnerabilities
    pub fn search(
        &self,
        product: &str,
        version: Option<&str>,
        min_severity: Severity,
    ) -> Result<Vec<Vulnerability>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT cve_id, severity, cvss_score, description, product, vendor,
                   version_start, version_end, published, modified
            FROM vulnerabilities
            WHERE LOWER(product) LIKE ?
            ORDER BY cvss_score DESC
            "#,
        )?;

        let pattern = format!("%{}%", product.to_lowercase());
        let rows = stmt.query_map([&pattern], |row| {
            Ok(Vulnerability {
                cve_id: row.get(0)?,
                severity: Severity::from_str(&row.get::<_, String>(1)?),
                cvss_score: row.get(2)?,
                description: row.get(3)?,
                product: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                vendor: row.get(5)?,
                version_start: row.get(6)?,
                version_end: row.get(7)?,
                references: Vec::new(),
                published: row.get::<_, Option<String>>(8)?
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                modified: row.get::<_, Option<String>>(9)?
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
            })
        })?;

        let mut results = Vec::new();
        for vuln_result in rows {
            let vuln = vuln_result?;

            // Filter by severity
            if vuln.severity < min_severity {
                continue;
            }

            // Filter by version if provided
            if let Some(v) = version {
                if !self.version_affected(v, &vuln.version_start, &vuln.version_end) {
                    continue;
                }
            }

            results.push(vuln);
        }

        debug!("Found {} vulnerabilities for {}", results.len(), product);
        Ok(results)
    }

    /// Search with product aliases for better matching
    pub fn search_with_aliases(
        &self,
        product: &str,
        version: Option<&str>,
        min_severity: Severity,
    ) -> Result<Vec<Vulnerability>> {
        let aliases = ProductAliases::get_aliases(product);
        let mut all_results = Vec::new();
        let mut seen_cves = std::collections::HashSet::new();

        // Search for main product
        let results = self.search(product, version, min_severity)?;
        for vuln in results {
            if seen_cves.insert(vuln.cve_id.clone()) {
                all_results.push(vuln);
            }
        }

        // Search for aliases
        for alias in aliases {
            if alias != product.to_lowercase() {
                let results = self.search(alias, version, min_severity)?;
                for vuln in results {
                    if seen_cves.insert(vuln.cve_id.clone()) {
                        all_results.push(vuln);
                    }
                }
            }
        }

        Ok(all_results)
    }

    fn version_affected(
        &self,
        version: &str,
        start: &Option<String>,
        end: &Option<String>,
    ) -> bool {
        // If no version constraints, assume affected
        if start.is_none() && end.is_none() {
            return true;
        }

        // Use semantic version comparison
        let v = SemanticVersion::parse(version);
        let v_start = start.as_ref().map(|s| SemanticVersion::parse(s));
        let v_end = end.as_ref().map(|s| SemanticVersion::parse(s));

        // Check range
        let after_start = v_start.map(|s| v.compare(&s) >= 0).unwrap_or(true);
        let before_end = v_end.map(|e| v.compare(&e) <= 0).unwrap_or(true);

        after_start && before_end
    }

    fn normalize_version(&self, version: &str) -> (u32, u32, u32) {
        let parts: Vec<u32> = version
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|s| s.parse().ok())
            .collect();

        (
            *parts.first().unwrap_or(&0),
            *parts.get(1).unwrap_or(&0),
            *parts.get(2).unwrap_or(&0),
        )
    }

    /// Check version match with confidence scoring
    pub fn version_match_confidence(
        &self,
        detected_version: &str,
        cve_version_start: Option<&str>,
        cve_version_end: Option<&str>,
        has_backport: bool,
    ) -> VersionMatchResult {
        let detected = SemanticVersion::parse(detected_version);

        // No version constraints - low confidence match
        if cve_version_start.is_none() && cve_version_end.is_none() {
            return VersionMatchResult {
                matched: true,
                confidence: if has_backport { 0.3 } else { 0.5 },
                reason: "No version constraints in CVE".to_string(),
            };
        }

        let start = cve_version_start.map(SemanticVersion::parse);
        let end = cve_version_end.map(SemanticVersion::parse);

        // Check range
        let after_start = start.as_ref().map(|s| detected.compare(s) >= 0).unwrap_or(true);
        let before_end = end.as_ref().map(|e| detected.compare(e) <= 0).unwrap_or(true);

        if !after_start || !before_end {
            return VersionMatchResult {
                matched: false,
                confidence: 0.0,
                reason: "Version outside affected range".to_string(),
            };
        }

        // Version is in range - calculate confidence
        let mut confidence = 0.9;
        let mut reasons = Vec::new();

        // Reduce confidence for backported versions
        if has_backport {
            confidence *= 0.4;
            reasons.push("distro backport detected");
        }

        // Reduce confidence for edge cases
        if let Some(end_ver) = &end {
            // Exact boundary match - might be off-by-one
            if detected.compare(end_ver) == 0 {
                confidence *= 0.8;
                reasons.push("exact boundary version");
            }
        }

        // Check for pre-release versions
        if detected.prerelease.is_some() {
            confidence *= 0.7;
            reasons.push("pre-release version");
        }

        VersionMatchResult {
            matched: true,
            confidence,
            reason: if reasons.is_empty() {
                "Version in affected range".to_string()
            } else {
                format!("Version in range but: {}", reasons.join(", "))
            },
        }
    }

    /// Get database statistics
    pub fn stats(&self) -> Result<(usize, Option<DateTime<Utc>>)> {
        let count: usize = self.conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities",
            [],
            |row| row.get(0),
        )?;

        let last_sync: Option<DateTime<Utc>> = self.conn.query_row(
            "SELECT last_sync FROM sync_status WHERE id = 1",
            [],
            |row| {
                let s: Option<String> = row.get(0)?;
                Ok(s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)))
            },
        ).unwrap_or(None);

        Ok((count, last_sync))
    }

    // =========================================================================
    // External Sync Methods
    // =========================================================================

    /// Sync from any supported source
    pub async fn sync_from_source(&mut self, source: SyncSource) -> Result<SyncStats> {
        let start = std::time::Instant::now();

        let mut stats = match &source {
            SyncSource::Nvd { api_key } => {
                if let Some(key) = api_key {
                    self.api_key = Some(key.clone());
                }
                let count = self.sync_from_nvd(30).await?;
                SyncStats {
                    source: "NVD".to_string(),
                    total_processed: count,
                    inserted: count,
                    ..Default::default()
                }
            }
            SyncSource::ExternalApi { url, api_key, headers } => {
                self.sync_from_external_api(url, api_key.as_deref(), headers).await?
            }
            SyncSource::JsonFile { path } => {
                self.import_from_json(path)?
            }
            SyncSource::SqliteDb { path } => {
                self.sync_from_sqlite(path)?
            }
            SyncSource::Kev => {
                self.sync_kev().await?
            }
            SyncSource::Epss => {
                self.sync_epss_bulk().await?
            }
            SyncSource::GithubMirror { path } => {
                self.sync_from_github_mirror(path)?
            }
            SyncSource::GithubMirrorUrl => {
                self.sync_from_github_mirror_url().await?
            }
        };

        stats.duration_ms = start.elapsed().as_millis() as u64;
        Ok(stats)
    }

    /// Sync from external REST API
    pub async fn sync_from_external_api(
        &self,
        url: &str,
        api_key: Option<&str>,
        headers: &[(String, String)],
    ) -> Result<SyncStats> {
        info!("Syncing CVEs from external API: {}", url);

        let client = reqwest::Client::new();
        let mut stats = SyncStats {
            source: url.to_string(),
            ..Default::default()
        };

        let mut current_url = url.to_string();

        loop {
            let mut request = client.get(&current_url);

            // Add API key if provided
            if let Some(key) = api_key {
                request = request.header("Authorization", format!("Bearer {}", key));
            }

            // Add custom headers
            for (name, value) in headers {
                request = request.header(name, value);
            }

            let response = request.send().await?;

            if !response.status().is_success() {
                anyhow::bail!("External API error: {} - {}", response.status(), current_url);
            }

            let data: ExternalCveResponse = response.json().await?;

            if data.vulnerabilities.is_empty() {
                break;
            }

            // Store vulnerabilities
            for cve in &data.vulnerabilities {
                match self.store_external_cve(cve) {
                    Ok(inserted) => {
                        if inserted {
                            stats.inserted += 1;
                        } else {
                            stats.updated += 1;
                        }
                    }
                    Err(e) => {
                        debug!("Error storing CVE {}: {}", cve.cve_id, e);
                        stats.errors += 1;
                    }
                }
                stats.total_processed += 1;
            }

            info!("Processed {} CVEs from external API", stats.total_processed);

            // Check for pagination
            match data.next_page {
                Some(next) if !next.is_empty() => {
                    current_url = next;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                _ => break,
            }
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, last_sync, total_cves) VALUES (1, ?, ?)",
            params![Utc::now().to_rfc3339(), stats.total_processed as i64],
        )?;

        info!("External API sync complete: {} CVEs", stats.total_processed);
        Ok(stats)
    }

    /// Store a CVE from external source
    fn store_external_cve(&self, cve: &ExternalCve) -> Result<bool> {
        // Check if exists
        let exists: bool = self.conn.query_row(
            "SELECT 1 FROM vulnerabilities WHERE cve_id = ?",
            [&cve.cve_id],
            |_| Ok(true),
        ).unwrap_or(false);

        // Parse severity
        let severity = cve.severity
            .as_ref()
            .map(|s| Severity::from_str(s))
            .or_else(|| cve.cvss_score.map(Severity::from_cvss))
            .unwrap_or(Severity::Low);

        // Parse product from CPE if not provided
        let (vendor, product) = if cve.vendor.is_some() || cve.product.is_some() {
            (cve.vendor.clone(), cve.product.clone())
        } else if let Some(cpes) = &cve.cpe {
            cpes.first()
                .map(|c| self.parse_cpe(c))
                .unwrap_or((None, None))
        } else {
            (None, None)
        };

        // Serialize references to JSON
        let references_json = cve.references.as_ref()
            .map(|refs| serde_json::to_string(refs).unwrap_or_default());

        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO vulnerabilities
            (cve_id, severity, cvss_score, cvss_vector, description, product, vendor,
             version_start, version_end, version_start_type, version_end_type, fix_version,
             published, modified, epss_score, epss_percentile, is_kev, exploit_available,
             cwe_id, references)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                cve.cve_id,
                severity.to_string(),
                cve.cvss_score.unwrap_or(0.0),
                cve.cvss_vector,
                cve.description.as_deref().unwrap_or(""),
                product,
                vendor,
                cve.version_start,
                cve.version_end,
                cve.version_start_type.as_deref().unwrap_or("including"),
                cve.version_end_type.as_deref().unwrap_or("including"),
                cve.fix_version,
                cve.published,
                cve.modified,
                cve.epss_score.unwrap_or(0.0),
                cve.epss_percentile.unwrap_or(0.0),
                cve.is_kev.map(|b| if b { 1i64 } else { 0i64 }).unwrap_or(0),
                cve.exploit_available.map(|b| if b { 1i64 } else { 0i64 }).unwrap_or(0),
                cve.cwe_id,
                references_json,
            ],
        )?;

        // Store CPE entries if provided
        if let Some(cpes) = &cve.cpe {
            for cpe_uri in cpes {
                let (cpe_vendor, cpe_product) = self.parse_cpe(cpe_uri);
                let cpe_version = self.parse_cpe_version(cpe_uri);

                self.conn.execute(
                    r#"
                    INSERT OR IGNORE INTO cpe_matches
                    (cve_id, cpe23_uri, vendor, product, version, version_start, version_end,
                     version_start_type, version_end_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        cve.cve_id,
                        cpe_uri,
                        cpe_vendor,
                        cpe_product,
                        cpe_version,
                        cve.version_start,
                        cve.version_end,
                        cve.version_start_type.as_deref().unwrap_or("including"),
                        cve.version_end_type.as_deref().unwrap_or("including"),
                    ],
                ).ok();  // Ignore errors for CPE insertion
            }
        }

        Ok(!exists)
    }

    /// Parse version from CPE URI
    fn parse_cpe_version(&self, cpe: &str) -> Option<String> {
        // cpe:2.3:a:vendor:product:version:...
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() >= 6 {
            let version = parts[5];
            if version != "*" && !version.is_empty() {
                return Some(version.to_string());
            }
        }
        None
    }

    /// Sync from another SQLite database
    pub fn sync_from_sqlite(&self, source_path: &str) -> Result<SyncStats> {
        info!("Syncing from SQLite database: {}", source_path);

        let source = Connection::open(source_path)?;
        let mut stats = SyncStats {
            source: format!("sqlite:{}", source_path),
            ..Default::default()
        };

        // Attach source database
        self.conn.execute(
            &format!("ATTACH DATABASE '{}' AS source_db", source_path),
            [],
        )?;

        // Copy vulnerabilities
        let result = self.conn.execute(
            r#"
            INSERT OR REPLACE INTO vulnerabilities
            SELECT * FROM source_db.vulnerabilities
            "#,
            [],
        );

        match result {
            Ok(count) => {
                stats.inserted = count;
                stats.total_processed = count;
            }
            Err(e) => {
                warn!("Error syncing from SQLite: {}", e);
                stats.errors = 1;
            }
        }

        // Detach source database
        self.conn.execute("DETACH DATABASE source_db", [])?;

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, last_sync, total_cves) VALUES (1, ?, ?)",
            params![Utc::now().to_rfc3339(), stats.total_processed as i64],
        )?;

        info!("SQLite sync complete: {} CVEs", stats.total_processed);
        Ok(stats)
    }

    /// Import CVEs from JSON file
    pub fn import_from_json(&self, path: &str) -> Result<SyncStats> {
        info!("Importing CVEs from JSON: {}", path);

        let content = std::fs::read_to_string(path)?;
        let data: ExternalCveResponse = serde_json::from_str(&content)?;

        let mut stats = SyncStats {
            source: format!("json:{}", path),
            ..Default::default()
        };

        for cve in &data.vulnerabilities {
            match self.store_external_cve(cve) {
                Ok(inserted) => {
                    if inserted {
                        stats.inserted += 1;
                    } else {
                        stats.updated += 1;
                    }
                }
                Err(e) => {
                    debug!("Error storing CVE {}: {}", cve.cve_id, e);
                    stats.errors += 1;
                }
            }
            stats.total_processed += 1;
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, last_sync, total_cves) VALUES (1, ?, ?)",
            params![Utc::now().to_rfc3339(), stats.total_processed as i64],
        )?;

        info!("JSON import complete: {} CVEs", stats.total_processed);
        Ok(stats)
    }

    /// Export CVEs to JSON file
    pub fn export_to_json(&self, path: &str, min_severity: Option<Severity>) -> Result<usize> {
        info!("Exporting CVEs to JSON: {}", path);

        let min_sev = min_severity.unwrap_or(Severity::Low);

        let mut stmt = self.conn.prepare(
            r#"
            SELECT cve_id, severity, cvss_score, cvss_vector, description, product, vendor,
                   version_start, version_end, version_start_type, version_end_type, fix_version,
                   published, modified, epss_score, epss_percentile, is_kev, exploit_available,
                   cwe_id, references
            FROM vulnerabilities
            ORDER BY cvss_score DESC
            "#,
        )?;

        let vulnerabilities: Vec<ExternalCve> = stmt
            .query_map([], |row| {
                // Parse references JSON back to Vec
                let refs_json: Option<String> = row.get(19)?;
                let references = refs_json.and_then(|j| serde_json::from_str(&j).ok());

                Ok(ExternalCve {
                    cve_id: row.get(0)?,
                    severity: row.get(1)?,
                    cvss_score: row.get(2)?,
                    cvss_vector: row.get(3)?,
                    description: row.get(4)?,
                    product: row.get(5)?,
                    vendor: row.get(6)?,
                    version_start: row.get(7)?,
                    version_end: row.get(8)?,
                    version_start_type: row.get(9)?,
                    version_end_type: row.get(10)?,
                    fix_version: row.get(11)?,
                    published: row.get(12)?,
                    modified: row.get(13)?,
                    epss_score: row.get(14)?,
                    epss_percentile: row.get(15)?,
                    is_kev: row.get::<_, Option<i64>>(16)?.map(|v| v != 0),
                    exploit_available: row.get::<_, Option<i64>>(17)?.map(|v| v != 0),
                    cwe_id: row.get(18)?,
                    references,
                    cpe: None,  // CPEs are stored separately
                })
            })?
            .filter_map(|r| r.ok())
            .filter(|cve| {
                cve.severity
                    .as_ref()
                    .map(|s| Severity::from_str(s) >= min_sev)
                    .unwrap_or(true)
            })
            .collect();

        let count = vulnerabilities.len();
        let output = ExternalCveResponse {
            total: Some(count as u32),
            vulnerabilities,
            next_page: None,
        };

        let json = serde_json::to_string_pretty(&output)?;
        std::fs::write(path, json)?;

        info!("Exported {} CVEs to {}", count, path);
        Ok(count)
    }

    /// Get sync source info
    pub fn get_sync_info(&self) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT last_sync, total_cves FROM sync_status WHERE id = 1"
        )?;

        let info: Vec<(String, String, i64)> = stmt
            .query_map([], |row| {
                Ok((
                    "primary".to_string(),
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(info)
    }

    // =========================================================================
    // 3-Step Scanning Methods
    // =========================================================================

    /// Create a new scan record
    pub fn create_scan(&self, target: &str) -> Result<String> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT INTO scans (scan_id, target, step, status) VALUES (?, ?, 1, 'running')",
            params![scan_id, target],
        )?;
        info!("Created scan: {}", scan_id);
        Ok(scan_id)
    }

    /// Step 1: Save discovered open ports
    pub fn save_open_ports(
        &self,
        scan_id: &str,
        ip: &str,
        hostname: Option<&str>,
        ports: &[u16],
    ) -> Result<usize> {
        let mut count = 0;
        for port in ports {
            self.conn.execute(
                r#"
                INSERT OR REPLACE INTO assets (ip, hostname, port, state, scan_id, discovered_at)
                VALUES (?, ?, ?, 'open', ?, datetime('now'))
                "#,
                params![ip, hostname, *port as i64, scan_id],
            )?;
            count += 1;
        }

        // Update scan stats
        self.conn.execute(
            "UPDATE scans SET total_ports = total_ports + ?, step = 1 WHERE scan_id = ?",
            params![count as i64, scan_id],
        )?;

        debug!("Saved {} open ports for {}", count, ip);
        Ok(count)
    }

    /// Step 2: Save service/banner information
    pub fn save_service_info(
        &self,
        scan_id: &str,
        ip: &str,
        port: u16,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<i64> {
        self.save_service_info_parsed(scan_id, ip, port, service, product, version, banner, None)
    }

    /// Step 2: Save service/banner information with parsed version
    pub fn save_service_info_parsed(
        &self,
        scan_id: &str,
        ip: &str,
        port: u16,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
        parsed_version: Option<&ParsedVersionData>,
    ) -> Result<i64> {
        // Find the asset
        let asset_id: i64 = self.conn.query_row(
            "SELECT id FROM assets WHERE ip = ? AND port = ? AND scan_id = ?",
            params![ip, port as i64, scan_id],
            |row| row.get(0),
        )?;

        // Extract parsed version data
        let (version_core, version_major, version_minor, version_patch, distro, distro_version, has_backport) =
            if let Some(pv) = parsed_version {
                (
                    Some(pv.core.as_str()),
                    pv.major.map(|v| v as i64),
                    pv.minor.map(|v| v as i64),
                    pv.patch.map(|v| v as i64),
                    pv.distro.as_deref(),
                    pv.distro_version.as_deref(),
                    if pv.has_backport { 1i64 } else { 0i64 },
                )
            } else {
                (None, None, None, None, None, None, 0i64)
            };

        // Generate CPE using core version (without distro suffix)
        let cpe = if let (Some(prod), Some(ver)) = (product, version_core.or(version)) {
            Some(format!("cpe:2.3:a:*:{}:{}:*:*:*:*:*:*:*",
                prod.to_lowercase().replace(' ', "_"),
                ver.split_whitespace().next().unwrap_or(ver)
            ))
        } else {
            None
        };

        // Insert or update service
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO services
            (asset_id, service, product, version, version_core, version_major, version_minor,
             version_patch, distro, distro_version, has_backport, banner, cpe, grabbed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            "#,
            params![
                asset_id, service, product, version, version_core,
                version_major, version_minor, version_patch,
                distro, distro_version, has_backport,
                banner, cpe
            ],
        )?;

        let service_id = self.conn.last_insert_rowid();

        // Update scan stats
        self.conn.execute(
            "UPDATE scans SET total_services = total_services + 1, step = 2 WHERE scan_id = ?",
            params![scan_id],
        )?;

        debug!("Saved service {} for {}:{} (core version: {:?}, distro: {:?})",
               service, ip, port, version_core, distro);
        Ok(service_id)
    }

    /// Step 3: Match CVEs for discovered services with confidence scoring
    pub fn match_cves_for_scan(&self, scan_id: &str) -> Result<Vec<ScanVulnMatch>> {
        let mut matches = Vec::new();

        // Get all services for this scan (including backport flag)
        let mut stmt = self.conn.prepare(
            r#"
            SELECT s.id, s.product, s.version, s.version_core, s.has_backport, a.ip, a.port
            FROM services s
            JOIN assets a ON s.asset_id = a.id
            WHERE a.scan_id = ? AND s.product IS NOT NULL
            "#,
        )?;

        let services: Vec<(i64, String, Option<String>, Option<String>, bool, String, i64)> = stmt
            .query_map([scan_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for (service_id, product, version, version_core, has_backport, ip, port) in services {
            // Use core version for CVE matching if available
            let match_version = version_core.as_deref().or(version.as_deref());

            // Search for matching CVEs using product aliases
            let vulns = self.search_with_aliases(&product, match_version, Severity::Low)?;

            for vuln in vulns {
                // Calculate confidence using semantic version comparison
                let match_result = if let Some(ver) = match_version {
                    self.version_match_confidence(
                        ver,
                        vuln.version_start.as_deref(),
                        vuln.version_end.as_deref(),
                        has_backport,
                    )
                } else {
                    VersionMatchResult {
                        matched: true,
                        confidence: 0.4,  // No version = low confidence
                        reason: "No version detected".to_string(),
                    }
                };

                if !match_result.matched {
                    continue;
                }

                // Convert confidence to level string
                let confidence_str = if match_result.confidence >= 0.8 {
                    "high"
                } else if match_result.confidence >= 0.5 {
                    "medium"
                } else {
                    "low"
                };

                // Insert match
                let result = self.conn.execute(
                    r#"
                    INSERT OR IGNORE INTO vuln_matches
                    (service_id, cve_id, severity, cvss_score, confidence, matched_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                    "#,
                    params![
                        service_id,
                        vuln.cve_id,
                        vuln.severity.to_string(),
                        vuln.cvss_score,
                        format!("{} ({:.0}%)", confidence_str, match_result.confidence * 100.0),
                    ],
                );

                if result.is_ok() {
                    // Get EPSS and KEV data for risk scoring
                    let (epss_score, is_kev, exploit_available, fix_ver): (f32, bool, bool, Option<String>) =
                        self.conn.query_row(
                            "SELECT epss_score, is_kev, exploit_available, fix_version FROM vulnerabilities WHERE cve_id = ?",
                            [&vuln.cve_id],
                            |row| Ok((
                                row.get::<_, f32>(0).unwrap_or(0.0),
                                row.get::<_, i64>(1).unwrap_or(0) != 0,
                                row.get::<_, i64>(2).unwrap_or(0) != 0,
                                row.get(3)?,
                            ))
                        ).unwrap_or((0.0, false, false, None));

                    // Calculate risk score
                    let risk_engine = RiskEngine::with_defaults();
                    let risk = risk_engine.calculate(
                        vuln.cvss_score as f64,
                        match_result.confidence,
                        epss_score as f64,
                        3,  // Default medium asset criticality
                        is_kev,
                        exploit_available,
                    );

                    // Update match with risk score
                    self.conn.execute(
                        r#"
                        UPDATE vuln_matches
                        SET confidence = ?, confidence_level = ?, risk_score = ?, match_type = ?,
                            risk_factors = ?
                        WHERE service_id = ? AND cve_id = ?
                        "#,
                        params![
                            match_result.confidence,
                            confidence_str,
                            risk.score,
                            "product",
                            serde_json::to_string(&risk.factors).unwrap_or_default(),
                            service_id,
                            vuln.cve_id,
                        ],
                    ).ok();

                    matches.push(ScanVulnMatch {
                        ip: ip.clone(),
                        port: port as u16,
                        product: product.clone(),
                        version: version.clone(),
                        cve_id: vuln.cve_id,
                        severity: vuln.severity.to_string(),
                        cvss_score: vuln.cvss_score,
                        confidence: format!("{} ({:.0}%)", confidence_str, match_result.confidence * 100.0),
                        epss_score: Some(epss_score),
                        is_kev: Some(is_kev),
                        risk_score: Some(risk.score),
                        risk_level: Some(risk.level),
                        fix_version: fix_ver,
                        match_type: Some("product".to_string()),
                    });
                }
            }
        }

        // Update scan stats with severity counts
        let (critical, high, medium, low) = self.count_severity_for_matches(&matches);
        let max_risk = matches.iter()
            .filter_map(|m| m.risk_score)
            .fold(0.0f64, f64::max);

        self.conn.execute(
            r#"
            UPDATE scans
            SET total_vulns = ?, step = 3, status = 'completed', completed_at = datetime('now'),
                critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, max_risk_score = ?
            WHERE scan_id = ?
            "#,
            params![matches.len() as i64, critical, high, medium, low, max_risk, scan_id],
        )?;

        info!("Found {} CVE matches for scan {}", matches.len(), scan_id);
        Ok(matches)
    }

    /// Count vulnerabilities by severity
    fn count_severity_for_matches(&self, matches: &[ScanVulnMatch]) -> (i64, i64, i64, i64) {
        let mut critical = 0i64;
        let mut high = 0i64;
        let mut medium = 0i64;
        let mut low = 0i64;

        for m in matches {
            match m.severity.to_uppercase().as_str() {
                "CRITICAL" => critical += 1,
                "HIGH" => high += 1,
                "MEDIUM" => medium += 1,
                _ => low += 1,
            }
        }

        (critical, high, medium, low)
    }

    /// Get assets for a scan (for Step 2 processing)
    pub fn get_scan_assets(&self, scan_id: &str) -> Result<Vec<(String, Option<String>, u16)>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, hostname, port FROM assets WHERE scan_id = ? ORDER BY ip, port"
        )?;

        let assets: Vec<(String, Option<String>, u16)> = stmt
            .query_map([scan_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, i64>(2)? as u16,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(assets)
    }

    /// Get services for a scan (for Step 3 processing)
    pub fn get_scan_services(&self, scan_id: &str) -> Result<Vec<ServiceRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT s.id, a.ip, a.port, s.service, s.product, s.version, s.banner, s.cpe
            FROM services s
            JOIN assets a ON s.asset_id = a.id
            WHERE a.scan_id = ?
            ORDER BY a.ip, a.port
            "#,
        )?;

        let services: Vec<ServiceRecord> = stmt
            .query_map([scan_id], |row| {
                Ok(ServiceRecord {
                    id: row.get(0)?,
                    ip: row.get(1)?,
                    port: row.get::<_, i64>(2)? as u16,
                    service: row.get(3)?,
                    product: row.get(4)?,
                    version: row.get(5)?,
                    banner: row.get(6)?,
                    cpe: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(services)
    }

    /// Get vulnerability matches for a scan
    pub fn get_scan_vulns(&self, scan_id: &str) -> Result<Vec<ScanVulnMatch>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT a.ip, a.port, s.product, s.version, vm.cve_id, vm.severity, vm.cvss_score,
                   vm.confidence, vm.risk_score, vm.confidence_level, vm.match_type,
                   v.epss_score, v.is_kev, v.fix_version
            FROM vuln_matches vm
            JOIN services s ON vm.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            LEFT JOIN vulnerabilities v ON vm.cve_id = v.cve_id
            WHERE a.scan_id = ?
            ORDER BY vm.risk_score DESC NULLS LAST, vm.cvss_score DESC
            "#,
        )?;

        let vulns: Vec<ScanVulnMatch> = stmt
            .query_map([scan_id], |row| {
                let risk_score: Option<f64> = row.get(8)?;
                let confidence_level: Option<String> = row.get(9)?;

                // Determine risk level from score
                let risk_level = risk_score.map(|s| {
                    match s {
                        s if s >= 9.0 => "Critical",
                        s if s >= 7.0 => "High",
                        s if s >= 4.0 => "Medium",
                        s if s >= 1.0 => "Low",
                        _ => "Info",
                    }.to_string()
                });

                Ok(ScanVulnMatch {
                    ip: row.get(0)?,
                    port: row.get::<_, i64>(1)? as u16,
                    product: row.get(2)?,
                    version: row.get(3)?,
                    cve_id: row.get(4)?,
                    severity: row.get(5)?,
                    cvss_score: row.get(6)?,
                    confidence: row.get::<_, Option<String>>(7)?.unwrap_or_else(|| "unknown".to_string()),
                    epss_score: row.get(11).ok(),
                    is_kev: row.get::<_, Option<i64>>(12).ok().flatten().map(|v| v != 0),
                    risk_score,
                    risk_level,
                    fix_version: row.get(13).ok().flatten(),
                    match_type: row.get(10).ok().flatten(),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(vulns)
    }

    /// Get scan status
    pub fn get_scan_status(&self, scan_id: &str) -> Result<ScanStatus> {
        self.conn.query_row(
            r#"
            SELECT scan_id, target, step, status, started_at, completed_at,
                   total_hosts, total_ports, total_services, total_vulns
            FROM scans WHERE scan_id = ?
            "#,
            [scan_id],
            |row| {
                Ok(ScanStatus {
                    scan_id: row.get(0)?,
                    target: row.get(1)?,
                    step: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    completed_at: row.get(5)?,
                    total_hosts: row.get(6)?,
                    total_ports: row.get(7)?,
                    total_services: row.get(8)?,
                    total_vulns: row.get(9)?,
                })
            },
        ).map_err(|e| anyhow::anyhow!("Scan not found: {}", e))
    }

    /// List recent scans
    pub fn list_scans(&self, limit: usize) -> Result<Vec<ScanStatus>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT scan_id, target, step, status, started_at, completed_at,
                   total_hosts, total_ports, total_services, total_vulns
            FROM scans
            ORDER BY started_at DESC
            LIMIT ?
            "#,
        )?;

        let scans: Vec<ScanStatus> = stmt
            .query_map([limit as i64], |row| {
                Ok(ScanStatus {
                    scan_id: row.get(0)?,
                    target: row.get(1)?,
                    step: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    completed_at: row.get(5)?,
                    total_hosts: row.get(6)?,
                    total_ports: row.get(7)?,
                    total_services: row.get(8)?,
                    total_vulns: row.get(9)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(scans)
    }
}

/// Service record from database
#[derive(Debug, Clone, Serialize)]
pub struct ServiceRecord {
    pub id: i64,
    pub ip: String,
    pub port: u16,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
}

/// Vulnerability match result (enhanced)
#[derive(Debug, Clone, Serialize)]
pub struct ScanVulnMatch {
    pub ip: String,
    pub port: u16,
    pub product: String,
    pub version: Option<String>,
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub confidence: String,
    // Enhanced fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_kev: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
}

/// Scan status
#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub target: String,
    pub step: i32,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_hosts: i32,
    pub total_ports: i32,
    pub total_services: i32,
    pub total_vulns: i32,
}

/// Semantic version for accurate comparison
/// Handles: OpenSSL (1.0.2zn), Java (1.8.0_392), Debian epochs (1:2.3.4),
/// distro revisions (-3ubuntu0.6), pre-release (alpha/beta/rc), etc.
#[derive(Debug, Clone, Default)]
pub struct SemanticVersion {
    /// Debian/RPM epoch (1:2.3.4 → epoch=1)
    pub epoch: u32,
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub extra: Vec<u32>,             // Additional components (1.2.3.4.5 → extra=[4,5])
    pub prerelease: Option<PreRelease>, // alpha, beta, rc1, etc.
    pub build: Option<String>,       // build metadata (ignored in comparison)
    pub suffix: Option<VersionSuffix>, // p1, patch1, letter suffix (OpenSSL)
    pub distro_revision: Option<String>, // -3ubuntu0.6, -1.el9
    pub raw: String,                 // Original string for debugging
}

/// Pre-release version type with ordering
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreRelease {
    Dev(u32),      // dev0, dev1 (lowest)
    Alpha(u32),    // alpha1, a1
    Beta(u32),     // beta1, b1
    Rc(u32),       // rc1, release candidate
    Preview(u32),  // preview1
    // Release = None (no prerelease = higher than all prereleases)
}

impl PreRelease {
    fn order(&self) -> (u32, u32) {
        match self {
            PreRelease::Dev(n) => (0, *n),
            PreRelease::Alpha(n) => (1, *n),
            PreRelease::Beta(n) => (2, *n),
            PreRelease::Preview(n) => (3, *n),
            PreRelease::Rc(n) => (4, *n),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        let s_lower = s.to_lowercase();
        let extract_num = |prefix: &str| -> u32 {
            s_lower.strip_prefix(prefix)
                .and_then(|rest| rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
                .unwrap_or(0)
        };

        if s_lower.starts_with("dev") {
            Some(PreRelease::Dev(extract_num("dev")))
        } else if s_lower.starts_with("alpha") || s_lower.starts_with("a") && s_lower.len() > 1 && s_lower.chars().nth(1).map(|c| c.is_ascii_digit()).unwrap_or(false) {
            Some(PreRelease::Alpha(extract_num(if s_lower.starts_with("alpha") { "alpha" } else { "a" })))
        } else if s_lower.starts_with("beta") || s_lower.starts_with("b") && s_lower.len() > 1 && s_lower.chars().nth(1).map(|c| c.is_ascii_digit()).unwrap_or(false) {
            Some(PreRelease::Beta(extract_num(if s_lower.starts_with("beta") { "beta" } else { "b" })))
        } else if s_lower.starts_with("rc") {
            Some(PreRelease::Rc(extract_num("rc")))
        } else if s_lower.starts_with("pre") {
            Some(PreRelease::Preview(extract_num("pre")))
        } else {
            None
        }
    }
}

/// Version suffix types
#[derive(Debug, Clone)]
pub enum VersionSuffix {
    /// Numeric patch: p1, p2 (OpenSSH style)
    Patch(u32),
    /// Letter suffix: a-z, za-zz (OpenSSL style: 1.0.2a through 1.0.2zn)
    Letter(String),
    /// Other suffix
    Other(String),
}

impl VersionSuffix {
    fn parse(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }

        // Check for p1, p2 style (OpenSSH)
        if s.to_lowercase().starts_with('p') {
            if let Ok(n) = s[1..].parse::<u32>() {
                return Some(VersionSuffix::Patch(n));
            }
        }

        // Check for letter suffix (OpenSSL: a-z, za-zz, etc.)
        if s.chars().all(|c| c.is_ascii_lowercase()) {
            return Some(VersionSuffix::Letter(s.to_string()));
        }

        Some(VersionSuffix::Other(s.to_string()))
    }

    /// Compare suffixes: returns -1, 0, or 1
    fn compare(&self, other: &Self) -> i32 {
        match (self, other) {
            (VersionSuffix::Patch(a), VersionSuffix::Patch(b)) => {
                if a > b { 1 } else if a < b { -1 } else { 0 }
            }
            (VersionSuffix::Letter(a), VersionSuffix::Letter(b)) => {
                // OpenSSL letter ordering: a < b < ... < z < za < zb < ... < zz
                Self::compare_letters(a, b)
            }
            (VersionSuffix::Patch(_), _) => 1,  // Patch > Letter/Other
            (_, VersionSuffix::Patch(_)) => -1,
            (VersionSuffix::Letter(_), VersionSuffix::Other(_)) => -1,
            (VersionSuffix::Other(_), VersionSuffix::Letter(_)) => 1,
            (VersionSuffix::Other(a), VersionSuffix::Other(b)) => {
                a.cmp(b) as i32
            }
        }
    }

    /// Compare OpenSSL-style letter suffixes: a < z < za < zz < zza
    fn compare_letters(a: &str, b: &str) -> i32 {
        // Length matters: "z" < "za" < "zz" < "zza"
        if a.len() != b.len() {
            return if a.len() > b.len() { 1 } else { -1 };
        }
        // Same length: compare lexicographically
        a.cmp(b) as i32
    }
}

impl SemanticVersion {
    /// Parse version string into semantic components
    /// Handles:
    /// - Debian/RPM epochs: "1:2.3.4" → epoch=1, version=2.3.4
    /// - Distro revisions: "8.9p1-3ubuntu0.6" → revision=3ubuntu0.6
    /// - OpenSSL letters: "1.0.2zn" → suffix=Letter("zn")
    /// - OpenSSH patches: "8.9p1" → suffix=Patch(1)
    /// - Java underscores: "1.8.0_392" → 1.8.0.392
    /// - Build metadata: "11.0.21+13" → build=13 (ignored in comparison)
    /// - Pre-releases: "3.11.0rc1" → prerelease=Rc(1)
    pub fn parse(version: &str) -> Self {
        let mut result = Self {
            raw: version.to_string(),
            ..Default::default()
        };

        // Step 1: Remove distro name suffix (e.g., "8.9p1 Ubuntu-3ubuntu0.6")
        let core = version.split_whitespace().next().unwrap_or(version);

        // Step 2: Parse Debian/RPM epoch (e.g., "1:2.3.4")
        let (epoch_str, version_after_epoch) = if let Some(idx) = core.find(':') {
            let (e, v) = core.split_at(idx);
            (e, v.trim_start_matches(':'))
        } else {
            ("0", core)
        };
        result.epoch = epoch_str.parse().unwrap_or(0);

        // Step 3: Extract distro revision (e.g., "-3ubuntu0.6", "-1.el9")
        // Be careful: "-alpha", "-beta", "-rc" are prereleases, not revisions
        let (version_part, distro_rev) = Self::split_distro_revision(version_after_epoch);
        result.distro_revision = distro_rev;

        // Step 4: Handle build metadata (+build123, +13)
        let (version_part, build) = if let Some(idx) = version_part.find('+') {
            let (v, b) = version_part.split_at(idx);
            (v, Some(b.trim_start_matches('+').to_string()))
        } else {
            (version_part, None)
        };
        result.build = build;

        // Step 5: Extract numeric components, suffix, and prerelease
        let mut numbers = Vec::new();
        let mut current_num = String::new();
        let mut suffix_str = String::new();
        let mut in_suffix = false;

        for c in version_part.chars() {
            if in_suffix {
                suffix_str.push(c);
            } else if c.is_ascii_digit() {
                current_num.push(c);
            } else if c == '.' || c == '_' {
                // Dot or underscore (Java uses underscore: 1.8.0_392)
                if !current_num.is_empty() {
                    numbers.push(current_num.parse::<u32>().unwrap_or(0));
                    current_num.clear();
                }
            } else if c == 'p' || c == 'P' {
                // Could be patch suffix (p1) or part of word
                if !current_num.is_empty() {
                    numbers.push(current_num.parse::<u32>().unwrap_or(0));
                    current_num.clear();
                }
                suffix_str.push(c);
                in_suffix = true;
            } else if c.is_ascii_lowercase() {
                // Letter suffix (OpenSSL: 1.0.2a, 1.0.2zn) or prerelease start
                if !current_num.is_empty() {
                    numbers.push(current_num.parse::<u32>().unwrap_or(0));
                    current_num.clear();
                }
                suffix_str.push(c);
                in_suffix = true;
            } else {
                // Unknown character
                if !current_num.is_empty() {
                    numbers.push(current_num.parse::<u32>().unwrap_or(0));
                    current_num.clear();
                }
                suffix_str.push(c);
                in_suffix = true;
            }
        }

        // Push last number if any
        if !current_num.is_empty() {
            numbers.push(current_num.parse::<u32>().unwrap_or(0));
        }

        // Step 6: Parse suffix as prerelease or version suffix
        if !suffix_str.is_empty() {
            // Check if it's a prerelease marker
            if let Some(pre) = PreRelease::parse(&suffix_str) {
                result.prerelease = Some(pre);
            } else {
                result.suffix = VersionSuffix::parse(&suffix_str);
            }
        }

        // Step 7: Assign version components
        result.major = numbers.first().copied().unwrap_or(0);
        result.minor = numbers.get(1).copied().unwrap_or(0);
        result.patch = numbers.get(2).copied().unwrap_or(0);
        if numbers.len() > 3 {
            result.extra = numbers[3..].to_vec();
        }

        result
    }

    /// Split version from distro revision
    /// "8.9p1-3ubuntu0.6" → ("8.9p1", Some("-3ubuntu0.6"))
    /// "3.11.0-alpha" → ("3.11.0-alpha", None) - alpha is prerelease, not revision
    fn split_distro_revision(version: &str) -> (&str, Option<String>) {
        // Look for distro patterns: -Nubuntu, -N.elN, -N.fcN, -N.debN
        let distro_patterns = [
            "ubuntu", "debian", "deb", ".el", ".fc", ".amzn", ".suse", ".mga"
        ];

        // Find the last hyphen that starts a distro revision
        for (idx, _) in version.match_indices('-').rev() {
            let after = &version[idx + 1..];

            // Check if it starts with a digit followed by distro pattern
            if after.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                let after_lower = after.to_lowercase();
                if distro_patterns.iter().any(|p| after_lower.contains(p)) {
                    return (&version[..idx], Some(version[idx..].to_string()));
                }
            }

            // Check for pure numeric revision (e.g., -1, -2)
            if after.chars().all(|c| c.is_ascii_digit() || c == '.') && !after.is_empty() {
                // Could be revision, but be conservative
                continue;
            }
        }

        (version, None)
    }

    /// Compare two versions (-1: self < other, 0: equal, 1: self > other)
    /// Comparison order:
    /// 1. Epoch (highest priority for Debian/RPM)
    /// 2. Major.Minor.Patch.Extra
    /// 3. Suffix (p1, letter suffix)
    /// 4. Pre-release (alpha < beta < rc < release)
    /// Note: Build metadata and distro_revision are NOT compared (per semver spec)
    pub fn compare(&self, other: &Self) -> i32 {
        // 1. Compare epoch (Debian/RPM: epoch always wins)
        if self.epoch != other.epoch {
            return if self.epoch > other.epoch { 1 } else { -1 };
        }

        // 2. Compare major.minor.patch
        if self.major != other.major {
            return if self.major > other.major { 1 } else { -1 };
        }
        if self.minor != other.minor {
            return if self.minor > other.minor { 1 } else { -1 };
        }
        if self.patch != other.patch {
            return if self.patch > other.patch { 1 } else { -1 };
        }

        // 3. Compare extra components (1.2.3.4 vs 1.2.3.5)
        let max_extra = self.extra.len().max(other.extra.len());
        for i in 0..max_extra {
            let a = self.extra.get(i).copied().unwrap_or(0);
            let b = other.extra.get(i).copied().unwrap_or(0);
            if a != b {
                return if a > b { 1 } else { -1 };
            }
        }

        // 4. Compare suffix (p1 < p2, a < z < za < zz)
        match (&self.suffix, &other.suffix) {
            (None, None) => {}
            (Some(_), None) => return 1,  // 8.9p1 > 8.9, 1.0.2a > 1.0.2
            (None, Some(_)) => return -1, // 8.9 < 8.9p1
            (Some(a), Some(b)) => {
                let cmp = a.compare(b);
                if cmp != 0 {
                    return cmp;
                }
            }
        }

        // 5. Compare prerelease (no prerelease > any prerelease)
        match (&self.prerelease, &other.prerelease) {
            (None, None) => 0,
            (Some(_), None) => -1,  // 1.0-alpha < 1.0 (release)
            (None, Some(_)) => 1,   // 1.0 > 1.0-alpha
            (Some(a), Some(b)) => {
                let (a_ord, a_num) = a.order();
                let (b_ord, b_num) = b.order();
                if a_ord != b_ord {
                    return if a_ord > b_ord { 1 } else { -1 };
                }
                if a_num != b_num {
                    return if a_num > b_num { 1 } else { -1 };
                }
                0
            }
        }
    }

    /// Check if this version equals another (ignoring build metadata)
    pub fn equals(&self, other: &Self) -> bool {
        self.compare(other) == 0
    }

    /// Format version for display
    pub fn to_string_short(&self) -> String {
        let mut s = String::new();
        if self.epoch > 0 {
            s.push_str(&format!("{}:", self.epoch));
        }
        s.push_str(&format!("{}.{}.{}", self.major, self.minor, self.patch));
        for e in &self.extra {
            s.push_str(&format!(".{}", e));
        }
        if let Some(ref suffix) = self.suffix {
            match suffix {
                VersionSuffix::Patch(n) => s.push_str(&format!("p{}", n)),
                VersionSuffix::Letter(l) => s.push_str(l),
                VersionSuffix::Other(o) => s.push_str(o),
            }
        }
        if let Some(ref pre) = self.prerelease {
            match pre {
                PreRelease::Dev(n) => s.push_str(&format!("-dev{}", n)),
                PreRelease::Alpha(n) => s.push_str(&format!("-alpha{}", n)),
                PreRelease::Beta(n) => s.push_str(&format!("-beta{}", n)),
                PreRelease::Preview(n) => s.push_str(&format!("-preview{}", n)),
                PreRelease::Rc(n) => s.push_str(&format!("-rc{}", n)),
            }
        }
        s
    }
}

impl std::fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_short())
    }
}

/// Version match result with confidence score
#[derive(Debug, Clone, Serialize)]
pub struct VersionMatchResult {
    pub matched: bool,
    pub confidence: f64,  // 0.0 - 1.0
    pub reason: String,
}

/// Product name aliases for better matching
pub struct ProductAliases;

impl ProductAliases {
    /// Get canonical product name and aliases
    pub fn get_aliases(product: &str) -> Vec<&'static str> {
        let product_lower = product.to_lowercase();

        // Common product aliases
        match product_lower.as_str() {
            "apache" | "httpd" | "apache_http_server" | "apache2" =>
                vec!["apache", "httpd", "apache_http_server", "apache2"],
            "openssh" | "ssh" | "sshd" | "openssh_server" =>
                vec!["openssh", "ssh", "sshd", "openssh_server"],
            "nginx" | "nginx_plus" =>
                vec!["nginx", "nginx_plus"],
            "mysql" | "mysqld" | "mysql_server" =>
                vec!["mysql", "mysqld", "mysql_server"],
            "postgresql" | "postgres" | "psql" =>
                vec!["postgresql", "postgres", "psql"],
            "openssl" | "libssl" =>
                vec!["openssl", "libssl"],
            "tomcat" | "apache_tomcat" =>
                vec!["tomcat", "apache_tomcat"],
            "iis" | "microsoft_iis" | "internet_information_services" =>
                vec!["iis", "microsoft_iis", "internet_information_services"],
            "redis" | "redis_server" =>
                vec!["redis", "redis_server"],
            "mongodb" | "mongod" =>
                vec!["mongodb", "mongod"],
            "elasticsearch" | "elastic" =>
                vec!["elasticsearch", "elastic"],
            "vsftpd" | "ftp" =>
                vec!["vsftpd", "ftp"],
            "proftpd" | "proftp" =>
                vec!["proftpd", "proftp"],
            "bind" | "named" | "bind9" =>
                vec!["bind", "named", "bind9"],
            "postfix" | "smtp" =>
                vec!["postfix"],  // smtp is too generic
            "dovecot" | "imap" | "pop3" =>
                vec!["dovecot"],  // imap/pop3 are too generic
            _ => vec![],
        }
    }

    /// Check if two product names are equivalent
    pub fn is_equivalent(product1: &str, product2: &str) -> bool {
        let p1 = product1.to_lowercase();
        let p2 = product2.to_lowercase();

        if p1 == p2 {
            return true;
        }

        let aliases1 = Self::get_aliases(&p1);
        let aliases2 = Self::get_aliases(&p2);

        // Check if either product's aliases contain the other
        if !aliases1.is_empty() && !aliases2.is_empty() {
            for a1 in &aliases1 {
                if aliases2.contains(a1) {
                    return true;
                }
            }
        }

        // Substring matching as fallback (e.g., "OpenSSH" matches "openssh_server")
        p1.contains(&p2) || p2.contains(&p1)
    }
}

// =============================================================================
// Risk Scoring Engine
// =============================================================================

/// Risk scoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    /// Weight for CVSS score (0-1)
    pub cvss_weight: f64,
    /// Weight for confidence (0-1)
    pub confidence_weight: f64,
    /// Weight for EPSS (0-1)
    pub epss_weight: f64,
    /// Weight for asset criticality (0-1)
    pub criticality_weight: f64,
    /// Multiplier for KEV vulnerabilities
    pub kev_multiplier: f64,
    /// Multiplier for exploit availability
    pub exploit_multiplier: f64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            cvss_weight: 0.35,
            confidence_weight: 0.20,
            epss_weight: 0.25,
            criticality_weight: 0.20,
            kev_multiplier: 1.5,
            exploit_multiplier: 1.3,
        }
    }
}

/// Detailed risk score breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Final risk score (0-10)
    pub score: f64,
    /// Risk level: Critical, High, Medium, Low, Info
    pub level: String,
    /// Individual factor scores
    pub factors: RiskFactors,
    /// Recommended priority (1=highest)
    pub priority: u32,
}

/// Individual risk factor scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    pub cvss_component: f64,
    pub confidence_component: f64,
    pub epss_component: f64,
    pub criticality_component: f64,
    pub kev_boost: bool,
    pub exploit_boost: bool,
}

/// Risk scoring engine
pub struct RiskEngine {
    config: RiskConfig,
}

impl RiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(RiskConfig::default())
    }

    /// Calculate risk score for a vulnerability match
    pub fn calculate(
        &self,
        cvss_score: f64,
        confidence: f64,
        epss_score: f64,
        asset_criticality: u32,  // 1=critical, 2=high, 3=medium, 4=low
        is_kev: bool,
        exploit_available: bool,
    ) -> RiskScore {
        // Normalize CVSS to 0-1
        let cvss_normalized = cvss_score / 10.0;

        // Convert criticality to score (1=critical=1.0, 4=low=0.25)
        let criticality_score = match asset_criticality {
            1 => 1.0,
            2 => 0.75,
            3 => 0.5,
            _ => 0.25,
        };

        // Calculate weighted components
        let cvss_component = cvss_normalized * self.config.cvss_weight;
        let confidence_component = confidence * self.config.confidence_weight;
        let epss_component = epss_score * self.config.epss_weight;
        let criticality_component = criticality_score * self.config.criticality_weight;

        // Base score (0-1)
        let mut base_score = cvss_component + confidence_component + epss_component + criticality_component;

        // Apply multipliers
        if is_kev {
            base_score *= self.config.kev_multiplier;
        }
        if exploit_available {
            base_score *= self.config.exploit_multiplier;
        }

        // Normalize to 0-10 scale and cap at 10
        let final_score = (base_score * 10.0).min(10.0);

        // Determine level and priority
        let (level, priority) = match final_score {
            s if s >= 9.0 => ("Critical", 1),
            s if s >= 7.0 => ("High", 2),
            s if s >= 4.0 => ("Medium", 3),
            s if s >= 1.0 => ("Low", 4),
            _ => ("Info", 5),
        };

        RiskScore {
            score: (final_score * 100.0).round() / 100.0,  // Round to 2 decimals
            level: level.to_string(),
            factors: RiskFactors {
                cvss_component: (cvss_component * 1000.0).round() / 1000.0,
                confidence_component: (confidence_component * 1000.0).round() / 1000.0,
                epss_component: (epss_component * 1000.0).round() / 1000.0,
                criticality_component: (criticality_component * 1000.0).round() / 1000.0,
                kev_boost: is_kev,
                exploit_boost: exploit_available,
            },
            priority,
        }
    }

    /// Batch calculate risk scores
    pub fn calculate_batch(&self, items: &[RiskInput]) -> Vec<RiskScore> {
        items.iter().map(|item| {
            self.calculate(
                item.cvss_score,
                item.confidence,
                item.epss_score,
                item.asset_criticality,
                item.is_kev,
                item.exploit_available,
            )
        }).collect()
    }
}

/// Input for risk calculation
#[derive(Debug, Clone)]
pub struct RiskInput {
    pub cvss_score: f64,
    pub confidence: f64,
    pub epss_score: f64,
    pub asset_criticality: u32,
    pub is_kev: bool,
    pub exploit_available: bool,
}

// =============================================================================
// EPSS & KEV Integration
// =============================================================================

/// EPSS data for a CVE
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EpssEntry {
    pub cve: String,
    pub epss: f32,
    pub percentile: f32,
}

/// CISA KEV entry
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KevEntry {
    #[serde(alias = "cveID")]
    pub cve_id: String,
    #[serde(alias = "vendorProject")]
    pub vendor: Option<String>,
    pub product: Option<String>,
    #[serde(alias = "vulnerabilityName")]
    pub vulnerability_name: Option<String>,
    #[serde(alias = "dateAdded")]
    pub date_added: Option<String>,
    #[serde(alias = "shortDescription")]
    pub short_description: Option<String>,
    #[serde(alias = "requiredAction")]
    pub required_action: Option<String>,
    #[serde(alias = "dueDate")]
    pub due_date: Option<String>,
    #[serde(alias = "knownRansomwareCampaignUse", default)]
    pub known_ransomware: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevEntry>,
}

impl CveDatabase {
    // =========================================================================
    // EPSS Integration
    // =========================================================================

    /// Sync EPSS scores from FIRST.org API
    pub async fn sync_epss(&self) -> Result<usize> {
        const EPSS_API: &str = "https://api.first.org/data/v1/epss";

        info!("Syncing EPSS scores from FIRST.org");

        let client = reqwest::Client::new();

        // Get all CVE IDs we have
        let mut stmt = self.conn.prepare("SELECT cve_id FROM vulnerabilities")?;
        let cve_ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        if cve_ids.is_empty() {
            return Ok(0);
        }

        let mut updated = 0;

        // Process in batches of 100 (API limit)
        for chunk in cve_ids.chunks(100) {
            let cve_list = chunk.join(",");
            let response = client
                .get(EPSS_API)
                .query(&[("cve", &cve_list)])
                .send()
                .await?;

            if !response.status().is_success() {
                warn!("EPSS API error: {}", response.status());
                continue;
            }

            #[derive(Deserialize)]
            struct EpssResponse {
                data: Vec<EpssEntry>,
            }

            let data: EpssResponse = response.json().await?;

            for entry in data.data {
                let result = self.conn.execute(
                    "UPDATE vulnerabilities SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?",
                    params![entry.epss, entry.percentile, entry.cve],
                );

                if result.is_ok() {
                    updated += 1;
                }
            }

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Update sync status
        self.conn.execute(
            "UPDATE sync_status SET epss_last_sync = ? WHERE id = 1",
            params![Utc::now().to_rfc3339()],
        )?;

        info!("EPSS sync complete: {} CVEs updated", updated);
        Ok(updated)
    }

    /// Bulk sync all EPSS scores from Cyentia CSV download (~315K scores)
    ///
    /// Downloads the gzipped CSV from epss.cyentia.com (no rate limit, <30s).
    /// This is much faster than the FIRST.org API for full database updates.
    pub async fn sync_epss_bulk(&self) -> Result<SyncStats> {
        const EPSS_CSV_URL: &str = "https://epss.cyentia.com/epss_scores-current.csv.gz";

        let start = std::time::Instant::now();
        info!("Downloading bulk EPSS scores from Cyentia");

        let client = reqwest::Client::new();
        let response = client.get(EPSS_CSV_URL).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("EPSS CSV download error: {}", response.status());
        }

        let bytes = response.bytes().await?;
        info!("Downloaded {} bytes of EPSS data", bytes.len());

        // Decompress gzip
        use flate2::read::GzDecoder;
        use std::io::{BufRead, BufReader};

        let decoder = GzDecoder::new(&bytes[..]);
        let reader = BufReader::new(decoder);

        let mut stats = SyncStats {
            source: "EPSS Bulk CSV".to_string(),
            ..Default::default()
        };

        let today = Utc::now().format("%Y-%m-%d").to_string();

        // Parse CSV lines
        let mut lines = reader.lines();

        // Skip comment line (starts with #) and header line
        let mut header_found = false;
        while let Some(Ok(line)) = lines.next() {
            if line.starts_with('#') {
                continue;
            }
            if !header_found {
                // This is the header line: cve,epss,percentile
                header_found = true;
                continue;
            }

            // Parse data line: CVE-YYYY-NNNNN,0.00123,0.456
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 3 {
                continue;
            }

            let cve_id = parts[0].trim();
            let epss: f32 = match parts[1].trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let percentile: f32 = match parts[2].trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            stats.total_processed += 1;

            // Update vulnerabilities table
            let updated = self.conn.execute(
                "UPDATE vulnerabilities SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?",
                params![epss, percentile, cve_id],
            ).unwrap_or(0);

            if updated > 0 {
                stats.updated += 1;
            }

            // Store in epss_scores for historical tracking
            match self.conn.execute(
                "INSERT OR REPLACE INTO epss_scores (cve_id, score_date, epss, percentile) VALUES (?, ?, ?, ?)",
                params![cve_id, &today, epss, percentile],
            ) {
                Ok(_) => { stats.inserted += 1; }
                Err(e) => {
                    debug!("Error storing EPSS score for {}: {}", cve_id, e);
                    stats.errors += 1;
                }
            }
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, source, last_sync, epss_last_sync) VALUES (1, 'multi', COALESCE((SELECT last_sync FROM sync_status WHERE id = 1), ?), ?)",
            params![Utc::now().to_rfc3339(), Utc::now().to_rfc3339()],
        )?;

        stats.duration_ms = start.elapsed().as_millis() as u64;
        info!("EPSS bulk sync complete: {} scores processed, {} CVEs updated", stats.total_processed, stats.updated);
        Ok(stats)
    }

    // =========================================================================
    // CISA KEV Integration
    // =========================================================================

    /// Sync Known Exploited Vulnerabilities from CISA
    ///
    /// Downloads the full KEV catalog, stores entries in `kev_catalog` table,
    /// and flags matching CVEs in `vulnerabilities.is_kev`.
    /// No rate limit, typically completes in <5 seconds.
    pub async fn sync_kev(&self) -> Result<SyncStats> {
        const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

        let start = std::time::Instant::now();
        info!("Syncing CISA Known Exploited Vulnerabilities");

        let client = reqwest::Client::new();
        let response = client.get(KEV_URL).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("KEV API error: {}", response.status());
        }

        let catalog: KevCatalog = response.json().await?;
        let mut stats = SyncStats {
            source: "CISA KEV".to_string(),
            ..Default::default()
        };

        for entry in &catalog.vulnerabilities {
            stats.total_processed += 1;

            // Store in kev_catalog table
            match self.conn.execute(
                r#"INSERT OR REPLACE INTO kev_catalog
                   (cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
                params![
                    entry.cve_id,
                    entry.vendor,
                    entry.product,
                    entry.vulnerability_name,
                    entry.date_added,
                    entry.due_date,
                    entry.known_ransomware,
                    entry.notes,
                ],
            ) {
                Ok(_) => { stats.inserted += 1; }
                Err(e) => {
                    debug!("Error storing KEV entry {}: {}", entry.cve_id, e);
                    stats.errors += 1;
                }
            }

            // Flag in vulnerabilities table
            let _ = self.conn.execute(
                "UPDATE vulnerabilities SET is_kev = 1 WHERE cve_id = ?",
                params![entry.cve_id],
            );
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, source, last_sync, kev_last_sync) VALUES (1, 'multi', COALESCE((SELECT last_sync FROM sync_status WHERE id = 1), ?), ?)",
            params![Utc::now().to_rfc3339(), Utc::now().to_rfc3339()],
        )?;

        stats.duration_ms = start.elapsed().as_millis() as u64;
        info!("KEV sync complete: {} entries stored, {} CVEs flagged", stats.inserted, stats.total_processed);
        Ok(stats)
    }

    // =========================================================================
    // NVD GitHub Mirror Sync
    // =========================================================================

    /// Sync CVEs from a local clone of the fkie-cad NVD JSON data feeds
    ///
    /// The user should `git clone https://github.com/fkie-cad/nvd-json-data-feeds.git`
    /// and pass the path to the cloned repo.
    pub fn sync_from_github_mirror(&self, repo_path: &str) -> Result<SyncStats> {
        let start = std::time::Instant::now();
        info!("Syncing CVEs from local NVD GitHub mirror: {}", repo_path);

        let mut stats = SyncStats {
            source: "NVD GitHub Mirror (local)".to_string(),
            ..Default::default()
        };

        let base = std::path::Path::new(repo_path);
        if !base.exists() {
            anyhow::bail!("NVD mirror path does not exist: {}", repo_path);
        }

        // Process year files: CVE-YYYY.json
        for year in 2002..=2026 {
            let file_name = format!("CVE-{}.json", year);
            let file_path = base.join(&file_name);

            if !file_path.exists() {
                debug!("Skipping missing year file: {}", file_name);
                continue;
            }

            info!("Processing {}", file_name);

            let content = match std::fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to read {}: {}", file_name, e);
                    stats.errors += 1;
                    continue;
                }
            };

            match self.parse_and_store_nvd_json(&content) {
                Ok(count) => {
                    stats.total_processed += count;
                    stats.inserted += count;
                    info!("  {} CVEs from {}", count, file_name);
                }
                Err(e) => {
                    warn!("Failed to parse {}: {}", file_name, e);
                    stats.errors += 1;
                }
            }
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, source, last_sync, total_cves) VALUES (1, 'github-mirror', ?, ?)",
            params![Utc::now().to_rfc3339(), stats.total_processed as i64],
        )?;

        stats.duration_ms = start.elapsed().as_millis() as u64;
        info!("GitHub mirror sync complete: {} CVEs", stats.total_processed);
        Ok(stats)
    }

    /// Sync CVEs by downloading year files directly from GitHub (no git clone needed)
    ///
    /// Downloads CVE-YYYY.json files from fkie-cad/nvd-json-data-feeds raw URLs.
    /// No rate limit, typically 5-10 minutes for full history (~250K CVEs).
    pub async fn sync_from_github_mirror_url(&self) -> Result<SyncStats> {
        const BASE_URL: &str = "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main";

        let start = std::time::Instant::now();
        info!("Downloading NVD data from GitHub mirror");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()?;

        let mut stats = SyncStats {
            source: "NVD GitHub Mirror (URL)".to_string(),
            ..Default::default()
        };

        for year in 2002..=2026 {
            let url = format!("{}/CVE-{}.json", BASE_URL, year);
            info!("Downloading CVE-{}.json ...", year);

            let response = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to download CVE-{}.json: {}", year, e);
                    stats.errors += 1;
                    continue;
                }
            };

            if !response.status().is_success() {
                if response.status().as_u16() == 404 {
                    debug!("CVE-{}.json not found, skipping", year);
                    continue;
                }
                warn!("HTTP {} for CVE-{}.json", response.status(), year);
                stats.errors += 1;
                continue;
            }

            let content = match response.text().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to read response for CVE-{}.json: {}", year, e);
                    stats.errors += 1;
                    continue;
                }
            };

            match self.parse_and_store_nvd_json(&content) {
                Ok(count) => {
                    stats.total_processed += count;
                    stats.inserted += count;
                    info!("  {} CVEs from CVE-{}.json", count, year);
                }
                Err(e) => {
                    warn!("Failed to parse CVE-{}.json: {}", year, e);
                    stats.errors += 1;
                }
            }
        }

        // Update sync status
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_status (id, source, last_sync, total_cves) VALUES (1, 'github-mirror-url', ?, ?)",
            params![Utc::now().to_rfc3339(), stats.total_processed as i64],
        )?;

        stats.duration_ms = start.elapsed().as_millis() as u64;
        info!("GitHub mirror URL sync complete: {} CVEs", stats.total_processed);
        Ok(stats)
    }

    /// Parse NVD JSON 2.0 format and store vulnerabilities
    fn parse_and_store_nvd_json(&self, json_content: &str) -> Result<usize> {
        let data: NvdResponse = serde_json::from_str(json_content)?;
        self.store_vulnerabilities(&data.vulnerabilities)
    }

    // =========================================================================
    // Priority Tier Calculation
    // =========================================================================

    /// Update priority tiers for all vulnerabilities based on KEV/EPSS/CVSS
    ///
    /// Tier 0: CISA KEV (actively exploited)
    /// Tier 1: EPSS > 0.1 (high exploit probability)
    /// Tier 2: CVSS >= 9.0 (critical severity)
    /// Tier 3: CVSS >= 7.0 (high severity)
    /// Tier 4: Everything else
    pub fn update_priority_tiers(&self) -> Result<usize> {
        info!("Updating priority tiers");

        let updated = self.conn.execute(
            r#"UPDATE vulnerabilities SET priority_tier = CASE
                WHEN is_kev = 1 THEN 0
                WHEN epss_score > 0.1 THEN 1
                WHEN cvss_score >= 9.0 THEN 2
                WHEN cvss_score >= 7.0 THEN 3
                ELSE 4
            END"#,
            [],
        )?;

        info!("Updated priority tiers for {} CVEs", updated);
        Ok(updated)
    }

    // =========================================================================
    // Enhanced CVE Matching
    // =========================================================================

    /// Match CVEs using CPE for higher accuracy
    pub fn match_by_cpe(
        &self,
        vendor: &str,
        product: &str,
        version: &str,
    ) -> Result<Vec<EnhancedVulnMatch>> {
        let mut results = Vec::new();

        // Query CPE matches
        let mut stmt = self.conn.prepare(
            r#"
            SELECT c.cve_id, v.severity, v.cvss_score, v.epss_score, v.is_kev,
                   v.exploit_available, c.version_start, c.version_end,
                   c.version_start_type, c.version_end_type, v.description, v.fix_version
            FROM cpe_matches c
            JOIN vulnerabilities v ON c.cve_id = v.cve_id
            WHERE LOWER(c.vendor) = LOWER(?) OR c.vendor = '*'
            AND (LOWER(c.product) = LOWER(?) OR c.product = '*')
            ORDER BY v.cvss_score DESC
            "#,
        )?;

        let matches = stmt.query_map(params![vendor, product], |row| {
            Ok((
                row.get::<_, String>(0)?,       // cve_id
                row.get::<_, String>(1)?,       // severity
                row.get::<_, f32>(2)?,          // cvss_score
                row.get::<_, f32>(3).unwrap_or(0.0),  // epss_score
                row.get::<_, i64>(4).unwrap_or(0) != 0, // is_kev
                row.get::<_, i64>(5).unwrap_or(0) != 0, // exploit_available
                row.get::<_, Option<String>>(6)?,  // version_start
                row.get::<_, Option<String>>(7)?,  // version_end
                row.get::<_, Option<String>>(8)?,  // version_start_type
                row.get::<_, Option<String>>(9)?,  // version_end_type
                row.get::<_, Option<String>>(10)?, // description
                row.get::<_, Option<String>>(11)?, // fix_version
            ))
        })?;

        let detected_version = SemanticVersion::parse(version);

        for m in matches.filter_map(|r| r.ok()) {
            let (cve_id, severity, cvss_score, epss_score, is_kev, exploit_available,
                 version_start, version_end, start_type, end_type, description, fix_version) = m;

            // Check version range
            let in_range = self.check_version_range(
                &detected_version,
                version_start.as_deref(),
                version_end.as_deref(),
                start_type.as_deref().unwrap_or("including"),
                end_type.as_deref().unwrap_or("including"),
            );

            if !in_range {
                continue;
            }

            // Calculate risk score
            let risk_engine = RiskEngine::with_defaults();
            let risk = risk_engine.calculate(
                cvss_score as f64,
                0.9,  // CPE match = high confidence
                epss_score as f64,
                3,    // Default medium criticality
                is_kev,
                exploit_available,
            );

            results.push(EnhancedVulnMatch {
                cve_id,
                severity,
                cvss_score,
                epss_score,
                is_kev,
                exploit_available,
                confidence: 0.9,
                match_type: "cpe".to_string(),
                risk_score: risk.score,
                risk_level: risk.level,
                priority: risk.priority,
                description,
                fix_version,
            });
        }

        Ok(results)
    }

    /// Check if version is in affected range with proper boundary handling
    fn check_version_range(
        &self,
        version: &SemanticVersion,
        start: Option<&str>,
        end: Option<&str>,
        start_type: &str,
        end_type: &str,
    ) -> bool {
        // No constraints = all versions affected
        if start.is_none() && end.is_none() {
            return true;
        }

        // Check start boundary
        if let Some(start_ver) = start {
            let start_v = SemanticVersion::parse(start_ver);
            let cmp = version.compare(&start_v);

            if start_type == "excluding" {
                if cmp <= 0 { return false; }
            } else {
                if cmp < 0 { return false; }
            }
        }

        // Check end boundary
        if let Some(end_ver) = end {
            let end_v = SemanticVersion::parse(end_ver);
            let cmp = version.compare(&end_v);

            if end_type == "excluding" {
                if cmp >= 0 { return false; }
            } else {
                if cmp > 0 { return false; }
            }
        }

        true
    }

    // =========================================================================
    // False Positive Management
    // =========================================================================

    /// Add a false positive rule
    pub fn add_false_positive(
        &self,
        cve_id: &str,
        product: Option<&str>,
        version_pattern: Option<&str>,
        reason: &str,
        created_by: Option<&str>,
        expires_days: Option<i64>,
    ) -> Result<i64> {
        let expires_at = expires_days.map(|d| {
            (Utc::now() + Duration::days(d)).to_rfc3339()
        });

        self.conn.execute(
            r#"
            INSERT INTO false_positives (cve_id, product, version_pattern, reason, created_by, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
            params![cve_id, product, version_pattern, reason, created_by, expires_at],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Check if a match is a known false positive
    pub fn is_false_positive(&self, cve_id: &str, product: &str, version: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM false_positives
            WHERE cve_id = ?
            AND (product IS NULL OR LOWER(product) = LOWER(?))
            AND (version_pattern IS NULL OR ? GLOB version_pattern)
            AND (expires_at IS NULL OR expires_at > datetime('now'))
            "#,
            params![cve_id, product, version],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    /// List false positive rules
    pub fn list_false_positives(&self) -> Result<Vec<FalsePositiveRule>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, cve_id, product, version_pattern, reason, created_by, created_at, expires_at
            FROM false_positives
            WHERE expires_at IS NULL OR expires_at > datetime('now')
            ORDER BY created_at DESC
            "#,
        )?;

        let rules: Vec<FalsePositiveRule> = stmt
            .query_map([], |row| {
                Ok(FalsePositiveRule {
                    id: row.get(0)?,
                    cve_id: row.get(1)?,
                    product: row.get(2)?,
                    version_pattern: row.get(3)?,
                    reason: row.get(4)?,
                    created_by: row.get(5)?,
                    created_at: row.get(6)?,
                    expires_at: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rules)
    }

    /// Remove a false positive rule
    pub fn remove_false_positive(&self, id: i64) -> Result<bool> {
        let count = self.conn.execute(
            "DELETE FROM false_positives WHERE id = ?",
            params![id],
        )?;

        Ok(count > 0)
    }

    // =========================================================================
    // Remediation Tracking
    // =========================================================================

    /// Get remediation info for a CVE
    pub fn get_remediation(&self, cve_id: &str) -> Result<Option<Remediation>> {
        // First check remediation table
        let result: Option<Remediation> = self.conn.query_row(
            r#"
            SELECT r.fix_version, r.workaround, r.vendor_advisory, r.patch_url, r.priority,
                   v.description
            FROM remediations r
            JOIN vulnerabilities v ON r.cve_id = v.cve_id
            WHERE r.cve_id = ?
            "#,
            params![cve_id],
            |row| Ok(Remediation {
                cve_id: cve_id.to_string(),
                fix_version: row.get(0)?,
                workaround: row.get(1)?,
                vendor_advisory: row.get(2)?,
                patch_url: row.get(3)?,
                priority: row.get(4)?,
                description: row.get(5)?,
            }),
        ).ok();

        // Fall back to fix_version in vulnerabilities table
        if result.is_none() {
            return self.conn.query_row(
                "SELECT fix_version, description FROM vulnerabilities WHERE cve_id = ?",
                params![cve_id],
                |row| {
                    let fix_version: Option<String> = row.get(0)?;
                    let description: Option<String> = row.get(1)?;

                    if fix_version.is_some() {
                        Ok(Some(Remediation {
                            cve_id: cve_id.to_string(),
                            fix_version,
                            workaround: None,
                            vendor_advisory: None,
                            patch_url: None,
                            priority: 3,
                            description,
                        }))
                    } else {
                        Ok(None)
                    }
                },
            ).unwrap_or(None).map(|r| Ok(r)).transpose();
        }

        Ok(result)
    }

    /// Update vulnerability match status
    pub fn update_match_status(
        &self,
        service_id: i64,
        cve_id: &str,
        status: &str,
        notes: Option<&str>,
        verified_by: Option<&str>,
    ) -> Result<bool> {
        let count = self.conn.execute(
            r#"
            UPDATE vuln_matches
            SET status = ?, remediation_notes = ?, verified_by = ?, verified_at = datetime('now')
            WHERE service_id = ? AND cve_id = ?
            "#,
            params![status, notes, verified_by, service_id, cve_id],
        )?;

        Ok(count > 0)
    }

    // =========================================================================
    // Reporting & Analytics
    // =========================================================================

    /// Get vulnerability statistics for a scan
    pub fn get_scan_stats(&self, scan_id: &str) -> Result<ScanStatistics> {
        // Count by severity
        let severity_counts: HashMap<String, i64> = self.conn.prepare(
            r#"
            SELECT vm.severity, COUNT(*) as cnt
            FROM vuln_matches vm
            JOIN services s ON vm.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            WHERE a.scan_id = ?
            GROUP BY vm.severity
            "#,
        )?
        .query_map([scan_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

        // Top vulnerable assets
        let top_assets: Vec<(String, i64)> = self.conn.prepare(
            r#"
            SELECT a.ip, COUNT(DISTINCT vm.cve_id) as vuln_count
            FROM vuln_matches vm
            JOIN services s ON vm.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            WHERE a.scan_id = ?
            GROUP BY a.ip
            ORDER BY vuln_count DESC
            LIMIT 10
            "#,
        )?
        .query_map([scan_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

        // Top CVEs
        let top_cves: Vec<(String, f32, i64)> = self.conn.prepare(
            r#"
            SELECT vm.cve_id, vm.cvss_score, COUNT(*) as affected_count
            FROM vuln_matches vm
            JOIN services s ON vm.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            WHERE a.scan_id = ?
            GROUP BY vm.cve_id
            ORDER BY vm.cvss_score DESC, affected_count DESC
            LIMIT 10
            "#,
        )?
        .query_map([scan_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();

        // KEV count
        let kev_count: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(DISTINCT vm.cve_id)
            FROM vuln_matches vm
            JOIN services s ON vm.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            JOIN vulnerabilities v ON vm.cve_id = v.cve_id
            WHERE a.scan_id = ? AND v.is_kev = 1
            "#,
            [scan_id],
            |row| row.get(0),
        )?;

        Ok(ScanStatistics {
            total_vulns: severity_counts.values().sum(),
            critical: *severity_counts.get("CRITICAL").unwrap_or(&0),
            high: *severity_counts.get("HIGH").unwrap_or(&0),
            medium: *severity_counts.get("MEDIUM").unwrap_or(&0),
            low: *severity_counts.get("LOW").unwrap_or(&0),
            kev_count,
            top_assets,
            top_cves,
        })
    }

    /// Get trending vulnerabilities (recently published, high impact)
    pub fn get_trending_vulns(&self, days: i64, limit: usize) -> Result<Vec<TrendingVuln>> {
        let since = (Utc::now() - Duration::days(days)).to_rfc3339();

        let mut stmt = self.conn.prepare(
            r#"
            SELECT cve_id, severity, cvss_score, epss_score, is_kev, published, description
            FROM vulnerabilities
            WHERE published >= ?
            ORDER BY
                is_kev DESC,
                epss_score DESC,
                cvss_score DESC
            LIMIT ?
            "#,
        )?;

        let vulns: Vec<TrendingVuln> = stmt
            .query_map(params![since, limit as i64], |row| {
                Ok(TrendingVuln {
                    cve_id: row.get(0)?,
                    severity: row.get(1)?,
                    cvss_score: row.get(2)?,
                    epss_score: row.get::<_, f32>(3).unwrap_or(0.0),
                    is_kev: row.get::<_, i64>(4).unwrap_or(0) != 0,
                    published: row.get(5)?,
                    description: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(vulns)
    }
}

// =============================================================================
// Additional Data Structures
// =============================================================================

/// Enhanced vulnerability match with full details
#[derive(Debug, Clone, Serialize)]
pub struct EnhancedVulnMatch {
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub epss_score: f32,
    pub is_kev: bool,
    pub exploit_available: bool,
    pub confidence: f64,
    pub match_type: String,
    pub risk_score: f64,
    pub risk_level: String,
    pub priority: u32,
    pub description: Option<String>,
    pub fix_version: Option<String>,
}

/// False positive rule
#[derive(Debug, Clone, Serialize)]
pub struct FalsePositiveRule {
    pub id: i64,
    pub cve_id: String,
    pub product: Option<String>,
    pub version_pattern: Option<String>,
    pub reason: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Remediation information
#[derive(Debug, Clone, Serialize)]
pub struct Remediation {
    pub cve_id: String,
    pub fix_version: Option<String>,
    pub workaround: Option<String>,
    pub vendor_advisory: Option<String>,
    pub patch_url: Option<String>,
    pub priority: i32,
    pub description: Option<String>,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize)]
pub struct ScanStatistics {
    pub total_vulns: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub kev_count: i64,
    pub top_assets: Vec<(String, i64)>,
    pub top_cves: Vec<(String, f32, i64)>,
}

/// Trending vulnerability
#[derive(Debug, Clone, Serialize)]
pub struct TrendingVuln {
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub epss_score: f32,
    pub is_kev: bool,
    pub published: Option<String>,
    pub description: Option<String>,
}
