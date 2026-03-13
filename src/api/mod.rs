//! REST API Server
//!
//! FastAPI-like REST API using Axum.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::discovery::NetworkDiscovery;
use crate::vulndb::{CveDatabase, VulnerabilityScanner};

/// Application state
pub struct AppState {
    pub cve_db: Mutex<CveDatabase>,
    pub scans: RwLock<HashMap<String, ScanStatus>>,
    pub agents: RwLock<HashMap<String, AgentInfo>>,
    pub inventory: RwLock<HashMap<String, InventoryData>>,
}

// ============== Request/Response Models ==============

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub ports: Option<Vec<u16>>,
    pub detect_services: Option<bool>,
    pub check_vulnerabilities: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub status: String,
    pub target: String,
    pub progress: u8,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_hosts: usize,
    pub total_vulnerabilities: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<ScanResults>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResults {
    pub hosts: Vec<serde_json::Value>,
    pub vulnerabilities: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AgentRegistration {
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct InventorySubmission {
    pub hostname: String,
    pub collected_at: String,
    pub software: Vec<SoftwareInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    #[serde(rename = "type")]
    pub software_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryData {
    pub agent_id: String,
    pub hostname: String,
    pub collected_at: String,
    pub software: Vec<SoftwareInfo>,
}

#[derive(Debug, Deserialize)]
pub struct CveSearchQuery {
    pub product: String,
    pub version: Option<String>,
    pub min_severity: Option<String>,
}

// ============== API Handlers ==============

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

async fn create_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> impl IntoResponse {
    let scan_id = Uuid::new_v4().to_string();

    let scan_status = ScanStatus {
        scan_id: scan_id.clone(),
        status: "pending".to_string(),
        target: request.target.clone(),
        progress: 0,
        created_at: Utc::now(),
        completed_at: None,
        total_hosts: 0,
        total_vulnerabilities: 0,
        results: None,
    };

    state.scans.write().await.insert(scan_id.clone(), scan_status.clone());

    // Spawn background scan task
    let state_clone = state.clone();
    let scan_id_clone = scan_id.clone();
    tokio::spawn(async move {
        run_scan(state_clone, scan_id_clone, request).await;
    });

    (StatusCode::CREATED, Json(scan_status))
}

async fn run_scan(state: Arc<AppState>, scan_id: String, request: ScanRequest) {
    // Update status to running
    {
        let mut scans = state.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.status = "running".to_string();
        }
    }

    let discovery = NetworkDiscovery::new();
    let detect_services = request.detect_services.unwrap_or(true);

    match discovery.discover(&request.target, request.ports, detect_services).await {
        Ok(result) => {
            let mut vuln_results = Vec::new();

            if request.check_vulnerabilities.unwrap_or(true) {
                let db = state.cve_db.lock().unwrap();
                let scanner = VulnerabilityScanner::new(&db);
                for host in &result.hosts {
                    if let Ok(matches) = scanner.scan_host(host) {
                        for m in matches {
                            vuln_results.push(serde_json::json!({
                                "host": m.host.to_string(),
                                "port": m.port,
                                "service": m.service,
                                "cve_id": m.vulnerability.cve_id,
                                "severity": m.vulnerability.severity.to_string(),
                                "cvss_score": m.vulnerability.cvss_score,
                                "confidence": m.confidence.to_string(),
                            }));
                        }
                    }
                }
            }

            let host_results: Vec<_> = result.hosts.iter().map(|h| {
                serde_json::json!({
                    "ip": h.ip.to_string(),
                    "hostname": h.hostname,
                    "open_ports": h.open_ports,
                    "services": h.services,
                })
            }).collect();

            let mut scans = state.scans.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                scan.status = "completed".to_string();
                scan.progress = 100;
                scan.completed_at = Some(Utc::now());
                scan.total_hosts = result.total_hosts;
                scan.total_vulnerabilities = vuln_results.len();
                scan.results = Some(ScanResults {
                    hosts: host_results,
                    vulnerabilities: vuln_results,
                });
            }
        }
        Err(e) => {
            let mut scans = state.scans.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                scan.status = "failed".to_string();
            }
            tracing::error!("Scan failed: {}", e);
        }
    }
}

async fn get_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.read().await;
    match scans.get(&scan_id) {
        Some(scan) => (StatusCode::OK, Json(serde_json::to_value(scan).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Scan not found"})),
        ),
    }
}

async fn list_scans(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let scans = state.scans.read().await;
    let list: Vec<_> = scans.values().cloned().collect();
    Json(list)
}

async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AgentRegistration>,
) -> impl IntoResponse {
    let agent_id = Uuid::new_v4().to_string();

    let agent = AgentInfo {
        agent_id: agent_id.clone(),
        hostname: request.hostname,
        os_type: request.os_type,
        os_version: request.os_version,
        registered_at: Utc::now(),
        last_seen: Utc::now(),
        status: "active".to_string(),
    };

    state.agents.write().await.insert(agent_id.clone(), agent);

    Json(serde_json::json!({
        "agent_id": agent_id,
        "status": "registered"
    }))
}

async fn submit_inventory(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(request): Json<InventorySubmission>,
) -> impl IntoResponse {
    // Update agent last_seen
    {
        let mut agents = state.agents.write().await;
        if let Some(agent) = agents.get_mut(&agent_id) {
            agent.last_seen = Utc::now();
        } else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    }

    // Store inventory
    let inventory = InventoryData {
        agent_id: agent_id.clone(),
        hostname: request.hostname.clone(),
        collected_at: request.collected_at,
        software: request.software.clone(),
    };

    state.inventory.write().await.insert(request.hostname.clone(), inventory);

    // Check for vulnerabilities
    let mut vulnerabilities = Vec::new();
    for sw in &request.software {
        if let Ok(vulns) = state.cve_db.lock().unwrap().search(&sw.name, Some(&sw.version), crate::vulndb::Severity::Low) {
            for v in vulns.iter().take(5) {
                vulnerabilities.push(serde_json::json!({
                    "software": sw.name,
                    "version": sw.version,
                    "cve_id": v.cve_id,
                    "severity": v.severity.to_string(),
                    "cvss_score": v.cvss_score,
                }));
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "software_count": request.software.len(),
            "vulnerabilities_found": vulnerabilities.len(),
            "vulnerabilities": vulnerabilities
        })),
    )
}

async fn list_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let agents = state.agents.read().await;
    let list: Vec<_> = agents.values().cloned().collect();
    Json(list)
}

async fn search_cve(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CveSearchQuery>,
) -> impl IntoResponse {
    let min_severity = query
        .min_severity
        .as_ref()
        .map(|s| crate::vulndb::Severity::from_str(s))
        .unwrap_or(crate::vulndb::Severity::Low);

    match state.cve_db.lock().unwrap().search(&query.product, query.version.as_deref(), min_severity) {
        Ok(vulns) => {
            let results: Vec<_> = vulns
                .iter()
                .take(100)
                .map(|v| {
                    serde_json::json!({
                        "cve_id": v.cve_id,
                        "severity": v.severity.to_string(),
                        "cvss_score": v.cvss_score,
                        "description": &v.description[..v.description.len().min(500)],
                    })
                })
                .collect();

            Json(serde_json::json!({
                "product": query.product,
                "version": query.version,
                "count": vulns.len(),
                "vulnerabilities": results
            }))
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn dashboard_summary(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let agents = state.agents.read().await;
    let inventory = state.inventory.read().await;
    let scans = state.scans.read().await;

    let active_agents = agents.values().filter(|a| a.status == "active").count();
    let running_scans = scans.values().filter(|s| s.status == "running").count();

    Json(serde_json::json!({
        "hosts": {
            "total": inventory.len(),
        },
        "agents": {
            "total": agents.len(),
            "active": active_agents,
        },
        "scans": {
            "total": scans.len(),
            "running": running_scans,
        }
    }))
}

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/health", get(health))
        // Scans
        .route("/api/v1/scans", post(create_scan).get(list_scans))
        .route("/api/v1/scans/:scan_id", get(get_scan))
        // Agents
        .route("/api/v1/agents/register", post(register_agent))
        .route("/api/v1/agents/:agent_id/inventory", post(submit_inventory))
        .route("/api/v1/agents", get(list_agents))
        // CVE
        .route("/api/v1/cve/search", get(search_cve))
        // Dashboard
        .route("/api/v1/dashboard/summary", get(dashboard_summary))
        .with_state(state)
}

/// Start the API server
pub async fn run_server(db_path: &str, host: &str, port: u16) -> anyhow::Result<()> {
    let cve_db = CveDatabase::new(db_path)?;

    let state = Arc::new(AppState {
        cve_db: Mutex::new(cve_db),
        scans: RwLock::new(HashMap::new()),
        agents: RwLock::new(HashMap::new()),
        inventory: RwLock::new(HashMap::new()),
    });

    let app = create_router(state);

    let addr = format!("{}:{}", host, port);
    info!("Starting API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
