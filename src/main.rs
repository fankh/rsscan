//! RsScan - Network Vulnerability Scanner
//!
//! A high-performance network vulnerability scanner written in Rust.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use rsscan::discovery::{NetworkDiscovery, PortScanner, ScanMethod, SynScanner, ParsedVersion};
use rsscan::vulndb::{
    CveDatabase, Severity, SyncSource, VulnerabilityScanner, ParsedVersionData,
    ActiveTestConfig, ActiveTestRunner, TestRisk, TestStatus,
};

#[derive(Parser)]
#[command(name = "rsscan")]
#[command(author, version, about = "RsScan - Network Vulnerability Scanner", long_about = None)]
struct Cli {
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan target for open ports and vulnerabilities
    Scan {
        /// Target IP, hostname, or CIDR network
        target: String,

        /// Ports to scan (e.g., 22,80,443 or 1-1000)
        #[arg(short, long)]
        ports: Option<String>,

        /// Scan top N common ports
        #[arg(long)]
        top_ports: Option<usize>,

        /// Scan all 65535 ports
        #[arg(long)]
        all_ports: bool,

        /// Skip vulnerability check
        #[arg(long)]
        no_vuln: bool,

        /// Output file (JSON)
        #[arg(short, long)]
        output: Option<String>,

        /// Port scan timeout in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,

        /// Scan method: connect, syn, or auto (default: auto)
        /// - connect: TCP connect scan (no root required, ~6 packets/port)
        /// - syn: SYN scan (requires root/admin, ~2 packets/port)
        /// - auto: try SYN first, fallback to connect
        #[arg(short, long, default_value = "auto")]
        method: String,

        /// Packets per second rate limit (for SYN scan)
        #[arg(long, default_value = "1000")]
        rate: u32,

        /// Output as JSON (service detection with full metadata)
        #[arg(long)]
        json: bool,
    },

    /// Sync CVE database from NVD or external source
    Sync {
        /// Number of days to sync (for NVD)
        #[arg(long, default_value = "30")]
        days: i64,

        /// NVD API key (recommended for faster sync)
        #[arg(long)]
        api_key: Option<String>,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,

        /// External CVE API URL (alternative to NVD)
        #[arg(long)]
        external_url: Option<String>,

        /// Import from JSON file
        #[arg(long)]
        import_json: Option<String>,

        /// Import from another SQLite database
        #[arg(long)]
        import_sqlite: Option<String>,

        /// Export to JSON file after sync
        #[arg(long)]
        export_json: Option<String>,

        /// Sync CISA KEV (Known Exploited Vulnerabilities) catalog
        #[arg(long)]
        kev: bool,

        /// Sync EPSS scores (bulk CSV download, ~315K scores)
        #[arg(long)]
        epss: bool,

        /// Sync from local NVD GitHub mirror clone (path to repo)
        #[arg(long)]
        github_mirror: Option<String>,

        /// Download NVD year files from GitHub mirror (no git clone needed)
        #[arg(long)]
        github_mirror_url: bool,

        /// Sync all no-rate-limit sources (NVD delta + KEV + EPSS)
        #[arg(long)]
        all_sources: bool,

        /// Recalculate priority tiers after sync
        #[arg(long)]
        update_priorities: bool,
    },

    /// Search CVE database
    Search {
        /// Product name to search
        product: String,

        /// Product version
        #[arg(short, long)]
        version: Option<String>,

        /// Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
        #[arg(long, default_value = "LOW")]
        min_severity: String,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,
    },

    /// Start API server
    Server {
        /// Bind host
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Bind port
        #[arg(long, default_value = "8000")]
        port: u16,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,
    },

    /// Step 1: Fast port discovery (no banner grab)
    Discover {
        /// Target IP, hostname, or CIDR network
        target: String,

        /// Ports to scan (e.g., 22,80,443 or 1-1000)
        #[arg(short, long)]
        ports: Option<String>,

        /// Scan top N common ports
        #[arg(long, default_value = "100")]
        top_ports: usize,

        /// Scan method: connect, syn, auto
        #[arg(short, long, default_value = "auto")]
        method: String,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,
    },

    /// Step 2: Banner grab for discovered ports
    Grab {
        /// Scan ID from discover step
        scan_id: String,

        /// Banner grab timeout in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,
    },

    /// Step 3: Match CVEs for discovered services
    Match {
        /// Scan ID from grab step
        scan_id: String,

        /// Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
        #[arg(long, default_value = "LOW")]
        min_severity: String,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,

        /// Output file (JSON)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// List recent scans
    Scans {
        /// Number of scans to list
        #[arg(long, default_value = "10")]
        limit: usize,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,
    },

    /// Show scan status and results
    Status {
        /// Scan ID
        scan_id: String,

        /// Database file path
        #[arg(long, default_value = "cve_database.db")]
        db: String,

        /// Show detailed results
        #[arg(long)]
        detail: bool,
    },

    /// Run active vulnerability tests
    Test {
        /// Target IP or hostname
        target: String,

        /// Port(s) to test (e.g., 22,80,443)
        #[arg(short, long)]
        ports: Option<String>,

        /// Specific CVE to test (e.g., CVE-2014-0160)
        #[arg(long)]
        cve: Option<String>,

        /// Test ID to run (e.g., heartbleed, ftp-anon)
        #[arg(long)]
        id: Option<String>,

        /// Load custom tests from YAML file
        #[arg(long)]
        load_tests: Option<std::path::PathBuf>,

        /// Config file (YAML, TOML, or JSON)
        #[arg(long, short)]
        config: Option<std::path::PathBuf>,

        /// Maximum risk level (safe, low, medium, high)
        #[arg(long, default_value = "safe")]
        max_risk: String,

        /// Run all available tests
        #[arg(long)]
        all: bool,

        /// List available tests
        #[arg(long)]
        list: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = if cli.debug { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Scan {
            target,
            ports,
            top_ports,
            all_ports,
            no_vuln,
            output,
            timeout,
            method,
            rate,
            json,
        } => {
            run_scan(target, ports, top_ports, all_ports, no_vuln, output, timeout, &method, rate, json).await?;
        }

        Commands::Sync {
            days,
            api_key,
            db,
            external_url,
            import_json,
            import_sqlite,
            export_json,
            kev,
            epss,
            github_mirror,
            github_mirror_url,
            all_sources,
            update_priorities,
        } => {
            run_sync(
                days, api_key, &db, external_url, import_json, import_sqlite, export_json,
                kev, epss, github_mirror, github_mirror_url, all_sources, update_priorities,
            ).await?;
        }

        Commands::Search {
            product,
            version,
            min_severity,
            db,
        } => {
            run_search(&product, version.as_deref(), &min_severity, &db)?;
        }

        Commands::Server { host, port, db } => {
            rsscan::api::run_server(&db, &host, port).await?;
        }

        Commands::Discover {
            target,
            ports,
            top_ports,
            method,
            db,
        } => {
            run_discover(&target, ports, top_ports, &method, &db).await?;
        }

        Commands::Grab { scan_id, timeout, db } => {
            run_grab(&scan_id, timeout, &db).await?;
        }

        Commands::Match {
            scan_id,
            min_severity,
            db,
            output,
        } => {
            run_match(&scan_id, &min_severity, &db, output)?;
        }

        Commands::Scans { limit, db } => {
            run_list_scans(limit, &db)?;
        }

        Commands::Status { scan_id, db, detail } => {
            run_status(&scan_id, &db, detail)?;
        }

        Commands::Test {
            target,
            ports,
            cve,
            id,
            load_tests,
            config,
            max_risk,
            all,
            list,
            json,
        } => {
            run_active_tests(
                &target, ports, cve, id, load_tests, config,
                &max_risk, all, list, json
            ).await?;
        }
    }

    Ok(())
}

async fn run_scan(
    target: String,
    ports: Option<String>,
    top_ports: Option<usize>,
    all_ports: bool,
    no_vuln: bool,
    output: Option<String>,
    timeout: u64,
    method: &str,
    rate: u32,
    json_output: bool,
) -> Result<()> {
    // Parse scan method
    let scan_method: ScanMethod = method.parse().unwrap_or(ScanMethod::Auto);

    // Parse ports
    let port_list: Option<Vec<u16>> = if let Some(ref p) = ports {
        Some(parse_ports(p)?)
    } else if let Some(n) = top_ports {
        Some(PortScanner::TOP_PORTS.iter().take(n).copied().collect())
    } else if all_ports {
        Some((1..=65535).collect())
    } else {
        None
    };

    // Display scan info (only if not JSON output)
    if !json_output {
        println!("\n\x1b[1;34mScanning target:\x1b[0m {}", target);
        if let Some(ref p) = port_list {
            println!("\x1b[2mPorts: {} ports\x1b[0m", p.len());
        }

        // Show scan method
        let method_display = match scan_method {
            ScanMethod::Syn => {
                if SynScanner::check_privileges() {
                    "\x1b[32mSYN (stealth, ~2 packets/port)\x1b[0m"
                } else {
                    println!("\x1b[33mWarning: SYN scan requires root/admin privileges\x1b[0m");
                    "\x1b[33mSYN (will fallback to connect)\x1b[0m"
                }
            }
            ScanMethod::Connect => "\x1b[36mTCP Connect (~6 packets/port)\x1b[0m",
            ScanMethod::Auto => {
                if SynScanner::check_privileges() {
                    "\x1b[32mAuto → SYN (has privileges)\x1b[0m"
                } else {
                    "\x1b[36mAuto → Connect (no privileges)\x1b[0m"
                }
            }
        };
        println!("\x1b[2mMethod: {}\x1b[0m", method_display);
        if scan_method == ScanMethod::Syn {
            println!("\x1b[2mRate: {} packets/sec\x1b[0m", rate);
        }
    }

    // Run discovery
    let discovery = NetworkDiscovery::with_config(timeout, 3000, 500)
        .with_scan_method(scan_method);
    let result = discovery.discover(&target, port_list, true).await?;

    // JSON output mode - output full result and exit
    if json_output {
        // Vulnerability scan if needed
        let mut all_vulns = Vec::new();
        if !no_vuln && !result.hosts.is_empty() {
            let cve_db = CveDatabase::new("cve_database.db")?;
            let scanner = VulnerabilityScanner::new(&cve_db);
            for host in &result.hosts {
                if let Ok(vulns) = scanner.scan_host(host) {
                    all_vulns.extend(vulns);
                }
            }
        }

        // Build JSON output with full service metadata
        let json_report = serde_json::json!({
            "target": target,
            "scan_start": result.scan_start,
            "scan_end": result.scan_end,
            "total_hosts": result.total_hosts,
            "total_open_ports": result.total_open_ports,
            "scan_method": method,
            "hosts": result.hosts.iter().map(|host| {
                serde_json::json!({
                    "ip": host.ip.to_string(),
                    "hostname": host.hostname,
                    "open_ports": host.open_ports,
                    "services": host.services.iter().map(|(port, svc)| {
                        serde_json::json!({
                            "port": port,
                            "service": svc.service,
                            "version": svc.version,
                            "product": svc.product,
                            "os": svc.os,
                            "banner": svc.banner,
                            "confidence": svc.confidence,
                            "method": svc.method,
                            "metadata": svc.metadata,
                            "parsed_version": svc.parsed_version,
                        })
                    }).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>(),
            "vulnerabilities": all_vulns.iter().map(|v| {
                serde_json::json!({
                    "host": v.host.to_string(),
                    "port": v.port,
                    "service": v.service,
                    "version": v.version,
                    "cve_id": v.vulnerability.cve_id,
                    "severity": v.vulnerability.severity.to_string(),
                    "cvss_score": v.vulnerability.cvss_score,
                    "description": v.vulnerability.description,
                    "confidence": v.confidence.to_string(),
                })
            }).collect::<Vec<_>>()
        });

        println!("{}", serde_json::to_string_pretty(&json_report)?);
        return Ok(());
    }

    // Text output mode
    println!("\n\x1b[1;32mDiscovery Complete\x1b[0m");
    println!("  Hosts found: {}", result.total_hosts);
    println!("  Open ports: {}", result.total_open_ports);
    if let Some(duration) = result.duration() {
        println!("  Duration: {}s", duration.num_seconds());
    }

    // Display hosts
    if !result.hosts.is_empty() {
        println!("\n\x1b[1mDiscovered Hosts:\x1b[0m");
        println!("{:-<70}", "");

        for host in &result.hosts {
            println!(
                "\n\x1b[36m{}\x1b[0m ({})",
                host.ip,
                host.hostname.as_deref().unwrap_or("unknown")
            );

            for (port, svc) in &host.services {
                let version = svc.version.as_deref().unwrap_or("");
                println!(
                    "  \x1b[32m{}/tcp\x1b[0m  {:15} {}",
                    port, svc.service, version
                );
            }
        }
    }

    // Vulnerability scan
    let mut all_vulns = Vec::new();
    if !no_vuln && !result.hosts.is_empty() {
        println!("\n\x1b[1;34mChecking vulnerabilities...\x1b[0m");

        let cve_db = CveDatabase::new("cve_database.db")?;
        let scanner = VulnerabilityScanner::new(&cve_db);

        for host in &result.hosts {
            if let Ok(vulns) = scanner.scan_host(host) {
                all_vulns.extend(vulns);
            }
        }

        if !all_vulns.is_empty() {
            let critical = all_vulns
                .iter()
                .filter(|v| v.vulnerability.severity == Severity::Critical)
                .count();
            let high = all_vulns
                .iter()
                .filter(|v| v.vulnerability.severity == Severity::High)
                .count();
            let medium = all_vulns
                .iter()
                .filter(|v| v.vulnerability.severity == Severity::Medium)
                .count();
            let low = all_vulns
                .iter()
                .filter(|v| v.vulnerability.severity == Severity::Low)
                .count();

            println!("\n\x1b[1;31mVulnerabilities Found: {}\x1b[0m", all_vulns.len());
            println!("  \x1b[31mCritical: {}\x1b[0m", critical);
            println!("  \x1b[33mHigh: {}\x1b[0m", high);
            println!("  \x1b[34mMedium: {}\x1b[0m", medium);
            println!("  \x1b[2mLow: {}\x1b[0m", low);

            // Show top vulnerabilities
            println!("\n\x1b[1mTop Vulnerabilities:\x1b[0m");
            println!("{:-<70}", "");

            for v in all_vulns.iter().take(10) {
                println!(
                    "  \x1b[31m{}\x1b[0m [{:8}] CVSS:{:.1} - {}:{}",
                    v.vulnerability.cve_id,
                    v.vulnerability.severity.to_string(),
                    v.vulnerability.cvss_score,
                    v.service,
                    v.version
                );
            }
        } else {
            println!("\x1b[32mNo vulnerabilities found\x1b[0m");
        }
    }

    // Save output
    if let Some(output_path) = output {
        let report = serde_json::json!({
            "target": target,
            "scan_start": result.scan_start,
            "scan_end": result.scan_end,
            "hosts": result.hosts,
            "vulnerabilities": all_vulns.iter().map(|v| {
                serde_json::json!({
                    "host": v.host.to_string(),
                    "port": v.port,
                    "service": v.service,
                    "version": v.version,
                    "cve_id": v.vulnerability.cve_id,
                    "severity": v.vulnerability.severity.to_string(),
                    "cvss_score": v.vulnerability.cvss_score,
                    "description": v.vulnerability.description,
                    "confidence": v.confidence.to_string(),
                })
            }).collect::<Vec<_>>()
        });

        std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;
        println!("\n\x1b[32mResults saved to {}\x1b[0m", output_path);
    }

    Ok(())
}

async fn run_sync(
    days: i64,
    api_key: Option<String>,
    db_path: &str,
    external_url: Option<String>,
    import_json: Option<String>,
    import_sqlite: Option<String>,
    export_json: Option<String>,
    kev: bool,
    epss: bool,
    github_mirror: Option<String>,
    github_mirror_url: bool,
    all_sources: bool,
    update_priorities: bool,
) -> Result<()> {
    let mut cve_db = CveDatabase::new(db_path)?;

    // Build list of sources to sync
    let mut sources: Vec<SyncSource> = Vec::new();

    // GitHub mirror first (bulk NVD data)
    if let Some(path) = github_mirror {
        println!("\x1b[1;34mSyncing CVE database from NVD GitHub mirror (local)...\x1b[0m");
        println!("  Path: {}", path);
        sources.push(SyncSource::GithubMirror { path });
    } else if github_mirror_url {
        println!("\x1b[1;34mSyncing CVE database from NVD GitHub mirror (URL)...\x1b[0m");
        sources.push(SyncSource::GithubMirrorUrl);
    }

    // Standard sync sources (if no special flags, use default NVD/external/import)
    if !kev && !epss && !all_sources && sources.is_empty() {
        let source = if let Some(url) = external_url {
            println!("\x1b[1;34mSyncing CVE database from external API...\x1b[0m");
            println!("  URL: {}", url);
            SyncSource::ExternalApi {
                url,
                api_key: api_key.clone(),
                headers: Vec::new(),
            }
        } else if let Some(path) = import_json {
            println!("\x1b[1;34mImporting CVE database from JSON file...\x1b[0m");
            println!("  File: {}", path);
            SyncSource::JsonFile { path }
        } else if let Some(path) = import_sqlite {
            println!("\x1b[1;34mSyncing CVE database from SQLite...\x1b[0m");
            println!("  Source: {}", path);
            SyncSource::SqliteDb { path }
        } else {
            println!("\x1b[1;34mSyncing CVE database from NVD...\x1b[0m");
            println!("  Days: {}", days);
            SyncSource::Nvd { api_key: api_key.clone() }
        };
        sources.push(source);
    }

    // all_sources = NVD delta + KEV + EPSS
    if all_sources {
        if sources.is_empty() {
            // Only add NVD if no mirror was specified
            println!("\x1b[1;34mSyncing all sources (NVD + KEV + EPSS)...\x1b[0m");
            sources.push(SyncSource::Nvd { api_key });
        }
        sources.push(SyncSource::Kev);
        sources.push(SyncSource::Epss);
    } else {
        // Individual KEV/EPSS flags
        if kev {
            println!("\x1b[1;34mSyncing CISA KEV catalog...\x1b[0m");
            sources.push(SyncSource::Kev);
        }
        if epss {
            println!("\x1b[1;34mSyncing EPSS scores (bulk CSV)...\x1b[0m");
            sources.push(SyncSource::Epss);
        }
    }

    // Run each source
    for source in sources {
        let stats = cve_db.sync_from_source(source).await?;

        println!("\n\x1b[32mSync complete: {}\x1b[0m", stats.source);
        println!("  Processed: {}", stats.total_processed);
        println!("  Inserted: {}", stats.inserted);
        println!("  Updated: {}", stats.updated);
        if stats.errors > 0 {
            println!("  \x1b[33mErrors: {}\x1b[0m", stats.errors);
        }
        println!("  Duration: {}ms", stats.duration_ms);
    }

    // Update priority tiers if requested
    if update_priorities {
        println!("\n\x1b[1;34mUpdating priority tiers...\x1b[0m");
        let updated = cve_db.update_priority_tiers()?;
        println!("\x1b[32mUpdated priority tiers for {} CVEs\x1b[0m", updated);
    }

    // Export if requested
    if let Some(export_path) = export_json {
        println!("\n\x1b[1;34mExporting CVE database to JSON...\x1b[0m");
        let count = cve_db.export_to_json(&export_path, None)?;
        println!("\x1b[32mExported {} CVEs to {}\x1b[0m", count, export_path);
    }

    // Show database stats
    let (total, last_sync) = cve_db.stats()?;
    println!("\n\x1b[1mDatabase Statistics:\x1b[0m");
    println!("  Total CVEs: {}", total);
    if let Some(sync_time) = last_sync {
        println!("  Last sync: {}", sync_time.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    Ok(())
}

fn run_search(product: &str, version: Option<&str>, min_severity: &str, db_path: &str) -> Result<()> {
    let cve_db = CveDatabase::new(db_path)?;
    let severity = Severity::from_str(min_severity);

    let vulns = cve_db.search(product, version, severity)?;

    println!("\n\x1b[1;34mCVE Search Results\x1b[0m");
    println!("  Product: {}", product);
    if let Some(v) = version {
        println!("  Version: {}", v);
    }
    println!("  Found: {} vulnerabilities\n", vulns.len());

    if !vulns.is_empty() {
        println!("{:-<80}", "");
        for v in vulns.iter().take(50) {
            println!(
                "\x1b[31m{}\x1b[0m [{:8}] CVSS:{:.1}",
                v.cve_id,
                v.severity.to_string(),
                v.cvss_score
            );
            println!(
                "  {}...\n",
                &v.description[..v.description.len().min(100)]
            );
        }
    }

    Ok(())
}

// ============================================================================
// Step 1: Discover - Fast port scanning
// ============================================================================

async fn run_discover(
    target: &str,
    ports: Option<String>,
    top_ports: usize,
    method: &str,
    db_path: &str,
) -> Result<()> {
    println!("\n\x1b[1;34m[Step 1] Port Discovery\x1b[0m");
    println!("  Target: {}", target);

    let scan_method: ScanMethod = method.parse().unwrap_or(ScanMethod::Auto);

    // Parse ports
    let port_list: Vec<u16> = if let Some(ref p) = ports {
        parse_ports(p)?
    } else {
        PortScanner::TOP_PORTS.iter().take(top_ports).copied().collect()
    };

    println!("  Ports: {} ports", port_list.len());

    // Show scan method
    let method_display = match scan_method {
        ScanMethod::Syn => {
            if SynScanner::check_privileges() {
                "\x1b[32mSYN (fast)\x1b[0m"
            } else {
                "\x1b[36mConnect (no root)\x1b[0m"
            }
        }
        ScanMethod::Connect => "\x1b[36mConnect\x1b[0m",
        ScanMethod::Auto => {
            if SynScanner::check_privileges() {
                "\x1b[32mAuto → SYN\x1b[0m"
            } else {
                "\x1b[36mAuto → Connect\x1b[0m"
            }
        }
    };
    println!("  Method: {}", method_display);

    // Create scan record
    let cve_db = CveDatabase::new(db_path)?;
    let scan_id = cve_db.create_scan(target)?;
    println!("  Scan ID: \x1b[33m{}\x1b[0m", scan_id);

    // Run discovery (without banner grab)
    let discovery = NetworkDiscovery::with_config(1000, 3000, 500)
        .with_scan_method(scan_method);
    let result = discovery.discover(target, Some(port_list), false).await?;

    // Save results
    let mut total_ports = 0;
    for host in &result.hosts {
        cve_db.save_open_ports(
            &scan_id,
            &host.ip.to_string(),
            host.hostname.as_deref(),
            &host.open_ports,
        )?;
        total_ports += host.open_ports.len();
    }

    println!("\n\x1b[32mDiscovery Complete!\x1b[0m");
    println!("  Hosts: {}", result.total_hosts);
    println!("  Open ports: {}", total_ports);
    println!("\n\x1b[1mNext step:\x1b[0m");
    println!("  rsscan grab {}", scan_id);

    Ok(())
}

// ============================================================================
// Step 2: Grab - Banner grabbing
// ============================================================================

async fn run_grab(scan_id: &str, timeout: u64, db_path: &str) -> Result<()> {
    println!("\n\x1b[1;34m[Step 2] Banner Grabbing\x1b[0m");
    println!("  Scan ID: {}", scan_id);

    let cve_db = CveDatabase::new(db_path)?;

    // Get assets from step 1
    let assets = cve_db.get_scan_assets(scan_id)?;
    if assets.is_empty() {
        anyhow::bail!("No assets found for scan ID: {}", scan_id);
    }

    println!("  Assets: {} ports to grab", assets.len());
    println!("  Timeout: {}ms", timeout);

    // Banner grab each asset
    let detector = rsscan::discovery::ServiceDetector::with_timeout(timeout);
    let mut grabbed = 0;

    for (ip, _hostname, port) in &assets {
        let ip_addr: std::net::IpAddr = ip.parse()?;
        match detector.detect(ip_addr, *port).await {
            Ok(info) => {
                // Convert ParsedVersion to ParsedVersionData for database storage
                let parsed_data = info.parsed_version.as_ref().map(|pv| ParsedVersionData {
                    core: pv.core.clone(),
                    major: pv.major,
                    minor: pv.minor,
                    patch: pv.patch,
                    distro: pv.distro.clone(),
                    distro_version: pv.distro_version.clone(),
                    has_backport: pv.has_backport,
                });

                cve_db.save_service_info_parsed(
                    scan_id,
                    ip,
                    *port,
                    &info.service,
                    info.product.as_deref(),
                    info.version.as_deref(),
                    info.banner.as_deref(),
                    parsed_data.as_ref(),
                )?;

                // Display version info with distro if detected
                let version_display = if let Some(ref pv) = info.parsed_version {
                    if let Some(ref distro) = pv.distro {
                        format!("{} ({})", pv.core, distro)
                    } else {
                        pv.core.clone()
                    }
                } else {
                    info.version.clone().unwrap_or_else(|| "-".to_string())
                };

                println!(
                    "  \x1b[32m{}:{}\x1b[0m {} {}",
                    ip, port, info.service, version_display
                );
                grabbed += 1;
            }
            Err(e) => {
                println!("  \x1b[31m{}:{}\x1b[0m error: {}", ip, port, e);
            }
        }
    }

    println!("\n\x1b[32mBanner Grab Complete!\x1b[0m");
    println!("  Services identified: {}", grabbed);
    println!("\n\x1b[1mNext step:\x1b[0m");
    println!("  rsscan match {}", scan_id);

    Ok(())
}

// ============================================================================
// Step 3: Match - CVE matching
// ============================================================================

fn run_match(scan_id: &str, min_severity: &str, db_path: &str, output: Option<String>) -> Result<()> {
    println!("\n\x1b[1;34m[Step 3] CVE Matching\x1b[0m");
    println!("  Scan ID: {}", scan_id);
    println!("  Min severity: {}", min_severity);

    let cve_db = CveDatabase::new(db_path)?;

    // Get services from step 2
    let services = cve_db.get_scan_services(scan_id)?;
    if services.is_empty() {
        anyhow::bail!("No services found for scan ID: {}. Run 'grab' first.", scan_id);
    }

    println!("  Services: {} to check", services.len());

    // Match CVEs
    let matches = cve_db.match_cves_for_scan(scan_id)?;

    // Display results
    if matches.is_empty() {
        println!("\n\x1b[32mNo vulnerabilities found!\x1b[0m");
    } else {
        // Count by severity
        let critical = matches.iter().filter(|m| m.severity == "CRITICAL").count();
        let high = matches.iter().filter(|m| m.severity == "HIGH").count();
        let medium = matches.iter().filter(|m| m.severity == "MEDIUM").count();
        let low = matches.iter().filter(|m| m.severity == "LOW").count();

        println!("\n\x1b[31mVulnerabilities Found: {}\x1b[0m", matches.len());
        println!("  \x1b[31mCritical: {}\x1b[0m", critical);
        println!("  \x1b[33mHigh: {}\x1b[0m", high);
        println!("  \x1b[34mMedium: {}\x1b[0m", medium);
        println!("  Low: {}", low);

        println!("\n\x1b[1mTop Vulnerabilities:\x1b[0m");
        println!("{:-<70}", "");
        for m in matches.iter().take(15) {
            let version = m.version.as_deref().unwrap_or("-");
            println!(
                "  \x1b[31m{}\x1b[0m [{:8}] CVSS:{:.1} - {}:{} ({})",
                m.cve_id, m.severity, m.cvss_score, m.product, version, m.ip
            );
        }
    }

    // Save output
    if let Some(output_path) = output {
        let report = serde_json::json!({
            "scan_id": scan_id,
            "total_vulnerabilities": matches.len(),
            "vulnerabilities": matches,
        });
        std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;
        println!("\n\x1b[32mResults saved to {}\x1b[0m", output_path);
    }

    Ok(())
}

// ============================================================================
// List scans
// ============================================================================

fn run_list_scans(limit: usize, db_path: &str) -> Result<()> {
    let cve_db = CveDatabase::new(db_path)?;
    let scans = cve_db.list_scans(limit)?;

    println!("\n\x1b[1mRecent Scans:\x1b[0m");
    println!("{:-<90}", "");
    println!(
        "{:<36} {:<20} {:>5} {:>6} {:>6} {:>6} {:>8}",
        "SCAN ID", "TARGET", "STEP", "PORTS", "SVCS", "VULNS", "STATUS"
    );
    println!("{:-<90}", "");

    for scan in scans {
        let status_color = match scan.status.as_str() {
            "completed" => "\x1b[32m",
            "running" => "\x1b[33m",
            _ => "\x1b[31m",
        };
        println!(
            "{:<36} {:<20} {:>5} {:>6} {:>6} {:>6} {}{}",
            scan.scan_id,
            &scan.target[..scan.target.len().min(20)],
            scan.step,
            scan.total_ports,
            scan.total_services,
            scan.total_vulns,
            status_color,
            scan.status,
        );
        print!("\x1b[0m");
    }

    Ok(())
}

// ============================================================================
// Show scan status
// ============================================================================

fn run_status(scan_id: &str, db_path: &str, detail: bool) -> Result<()> {
    let cve_db = CveDatabase::new(db_path)?;
    let status = cve_db.get_scan_status(scan_id)?;

    println!("\n\x1b[1mScan Status:\x1b[0m");
    println!("  Scan ID: {}", status.scan_id);
    println!("  Target: {}", status.target);
    println!("  Step: {}/3", status.step);
    println!("  Status: {}", status.status);
    println!("  Started: {}", status.started_at);
    if let Some(completed) = &status.completed_at {
        println!("  Completed: {}", completed);
    }
    println!("\n\x1b[1mResults:\x1b[0m");
    println!("  Open ports: {}", status.total_ports);
    println!("  Services: {}", status.total_services);
    println!("  Vulnerabilities: {}", status.total_vulns);

    if detail {
        // Show services
        let services = cve_db.get_scan_services(scan_id)?;
        if !services.is_empty() {
            println!("\n\x1b[1mDiscovered Services:\x1b[0m");
            println!("{:-<70}", "");
            for svc in &services {
                let product = svc.product.as_deref().unwrap_or("-");
                let version = svc.version.as_deref().unwrap_or("-");
                println!(
                    "  {}:{} - {} {} {}",
                    svc.ip,
                    svc.port,
                    svc.service.as_deref().unwrap_or("unknown"),
                    product,
                    version
                );
            }
        }

        // Show vulnerabilities
        let vulns = cve_db.get_scan_vulns(scan_id)?;
        if !vulns.is_empty() {
            println!("\n\x1b[1mVulnerabilities:\x1b[0m");
            println!("{:-<70}", "");
            for v in &vulns {
                println!(
                    "  \x1b[31m{}\x1b[0m [{:8}] CVSS:{:.1} - {}:{}",
                    v.cve_id,
                    v.severity,
                    v.cvss_score,
                    v.product,
                    v.version.as_deref().unwrap_or("-")
                );
            }
        }
    }

    // Next step hint
    match status.step {
        1 => println!("\n\x1b[1mNext:\x1b[0m rsscan grab {}", scan_id),
        2 => println!("\n\x1b[1mNext:\x1b[0m rsscan match {}", scan_id),
        _ => {}
    }

    Ok(())
}

fn parse_ports(port_str: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].trim().parse()?;
                let end: u16 = range[1].trim().parse()?;
                ports.extend(start..=end);
            }
        } else {
            ports.push(part.trim().parse()?);
        }
    }

    ports.sort();
    ports.dedup();
    Ok(ports)
}

// ============================================================================
// Active vulnerability testing
// ============================================================================

async fn run_active_tests(
    target: &str,
    ports: Option<String>,
    cve: Option<String>,
    id: Option<String>,
    load_tests: Option<std::path::PathBuf>,
    config_path: Option<std::path::PathBuf>,
    max_risk: &str,
    all: bool,
    list: bool,
    json_output: bool,
) -> Result<()> {
    // Load configuration
    let test_config = if let Some(ref path) = config_path {
        println!("\x1b[2mLoading config from {:?}\x1b[0m", path);
        ActiveTestConfig::load_from_file(path)?
    } else {
        let risk: TestRisk = max_risk.parse().unwrap_or(TestRisk::Safe);
        ActiveTestConfig::default().with_max_risk(risk)
    };

    // Create runner with config
    let mut runner = ActiveTestRunner::with_config(test_config);

    // Load built-in tests
    let builtin_count = runner.load_builtin()?;
    info!("Loaded {} built-in tests", builtin_count);

    // Load custom tests if specified
    if let Some(ref tests_file) = load_tests {
        let custom_count = runner.load_from_file(tests_file)?;
        println!("\x1b[2mLoaded {} custom tests from {:?}\x1b[0m", custom_count, tests_file);
    }

    // List mode
    if list {
        println!("\n\x1b[1mAvailable Active Tests:\x1b[0m");
        println!("{:-<70}", "");
        println!(
            "{:<20} {:<15} {:>6} {}",
            "ID", "SERVICE", "RISK", "CVEs"
        );
        println!("{:-<70}", "");

        for (id, test) in runner.tests() {
            let cves = if test.cves.is_empty() {
                "-".to_string()
            } else {
                test.cves.join(", ")
            };
            println!(
                "{:<20} {:<15} {:>6?} {}",
                id, test.service, test.risk, cves
            );
        }
        println!("\nTotal: {} tests", runner.tests().len());
        return Ok(());
    }

    // Parse ports
    let port_list: Vec<u16> = ports
        .map(|p| parse_ports(&p))
        .transpose()?
        .unwrap_or_else(|| vec![80, 443, 22, 21, 25, 6379, 27017, 3306]);

    println!("\n\x1b[1;34mActive Vulnerability Testing\x1b[0m");
    println!("  Target: {}", target);
    println!("  Ports: {:?}", port_list);
    println!("  Max risk: {:?}", runner.config().max_risk);

    // Run tests
    let results = if let Some(cve_id) = cve {
        println!("  Mode: CVE test ({})", cve_id);
        let port = port_list.first().copied().unwrap_or(443);
        runner.run_tests_for_cve(&cve_id, target, port).await
    } else if let Some(test_id) = id {
        println!("  Mode: Single test ({})", test_id);
        let port = port_list.first().copied().unwrap_or(443);
        match runner.run_test_by_id(&test_id, target, port).await {
            Ok(result) => vec![result],
            Err(e) => {
                eprintln!("\x1b[31mError: {}\x1b[0m", e);
                return Err(e);
            }
        }
    } else if all {
        println!("  Mode: All tests");
        runner.run_all_tests(target, &port_list).await
    } else {
        eprintln!("\x1b[33mSpecify --cve, --id, or --all to run tests\x1b[0m");
        eprintln!("Use --list to see available tests");
        return Ok(());
    };

    // Display results
    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("\n\x1b[1mResults:\x1b[0m");
        println!("{:-<70}", "");

        let mut vulnerable = 0;
        let mut safe = 0;
        let mut errors = 0;
        let mut skipped = 0;

        for result in &results {
            let (status_str, color) = match result.status {
                TestStatus::Vulnerable => {
                    vulnerable += 1;
                    ("VULNERABLE", "\x1b[31m")
                }
                TestStatus::NotVulnerable => {
                    safe += 1;
                    ("Safe", "\x1b[32m")
                }
                TestStatus::Inconclusive => {
                    ("Inconclusive", "\x1b[33m")
                }
                TestStatus::Error => {
                    errors += 1;
                    ("Error", "\x1b[31m")
                }
                TestStatus::Skipped => {
                    skipped += 1;
                    ("Skipped", "\x1b[2m")
                }
            };

            println!(
                "{}{:<12}\x1b[0m {:<20} {}:{} ({}ms)",
                color, status_str, result.test_id, result.host, result.port, result.duration_ms
            );

            if !result.cves.is_empty() {
                println!("             CVEs: {}", result.cves.join(", "));
            }

            if !result.details.is_empty() && result.status != TestStatus::NotVulnerable {
                println!("             {}", result.details);
            }
        }

        println!("{:-<70}", "");
        println!(
            "\x1b[1mSummary:\x1b[0m {} tests | \x1b[31m{} vulnerable\x1b[0m | \x1b[32m{} safe\x1b[0m | {} errors | {} skipped",
            results.len(), vulnerable, safe, errors, skipped
        );
    }

    Ok(())
}
