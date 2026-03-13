//! Vulnerability Database Module
//!
//! CVE database management and vulnerability matching.

mod database;
mod models;
mod scanner;
mod cpe;
pub mod active_tests;

pub use database::{
    // Core database
    CveDatabase, SyncSource, SyncStats, ExternalCve, ExternalCveResponse,
    // Scan results
    ServiceRecord, ScanVulnMatch, ScanStatus, ParsedVersionData,
    // Version matching
    SemanticVersion, VersionMatchResult, ProductAliases, PreRelease, VersionSuffix,
    // Risk scoring
    RiskEngine, RiskConfig, RiskScore, RiskFactors, RiskInput,
    // EPSS & KEV
    EpssEntry, KevEntry,
    // Enhanced matching
    EnhancedVulnMatch,
    // False positive management
    FalsePositiveRule,
    // Remediation
    Remediation,
    // Analytics
    ScanStatistics, TrendingVuln,
};
pub use models::{Vulnerability, VulnMatch, Severity};
pub use scanner::VulnerabilityScanner;
pub use cpe::{Cpe, CpePart, CpeMatch, CpeDictionary};

// Active testing
pub use active_tests::{
    ActiveTest, ActiveTestRunner, ActiveTestResult, TestStatus, TestRisk,
    ActiveTestConfig,
    load_builtin_tests, test_cve,
};
