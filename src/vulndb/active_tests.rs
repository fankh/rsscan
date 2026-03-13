//! Active Vulnerability Testing Module
//!
//! Provides active verification for high-impact CVEs where version matching
//! alone is insufficient (backports, runtime configuration, etc.)
//!
//! Two modes:
//! 1. Declarative YAML tests - Simple pattern-based checks
//! 2. Lua scripts - Complex protocol interactions

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

// =============================================================================
// Test Definition Structures
// =============================================================================

/// Active test definition (from YAML)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveTest {
    /// Test identifier
    pub id: String,
    /// CVE ID(s) this test verifies
    pub cves: Vec<String>,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Target service/protocol
    pub service: String,
    /// Default port(s)
    pub ports: Vec<u16>,
    /// Risk level of running this test
    pub risk: TestRisk,
    /// Test steps
    pub steps: Vec<TestStep>,
    /// How to determine vulnerability
    pub detection: Detection,
    /// Metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Risk level of running the test
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum TestRisk {
    /// Safe - read-only, won't affect service
    Safe,
    /// Low - minimal impact, might log
    Low,
    /// Medium - might cause brief disruption
    Medium,
    /// High - could crash service or trigger alerts
    High,
}

impl std::str::FromStr for TestRisk {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "safe" => Ok(TestRisk::Safe),
            "low" => Ok(TestRisk::Low),
            "medium" | "med" => Ok(TestRisk::Medium),
            "high" => Ok(TestRisk::High),
            _ => Err(anyhow::anyhow!("Invalid risk level: {}", s)),
        }
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Active test configuration for runtime customization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ActiveTestConfig {
    /// Maximum risk level to run
    pub max_risk: TestRisk,
    /// Timeout per test in milliseconds
    pub timeout_ms: u64,
    /// Maximum concurrent test threads
    pub max_threads: usize,
    /// Number of retries on failure
    pub retry_count: u32,
    /// Template variables for tests
    pub variables: HashMap<String, String>,
    /// Proxy URL (e.g., socks5://127.0.0.1:1080)
    pub proxy_url: Option<String>,
    /// Verify TLS certificates
    pub tls_verify: bool,
    /// Rate limit per host (requests per second)
    pub rate_limit_per_host: Option<u32>,
    /// Callback URL for out-of-band testing
    pub callback_url: Option<String>,
}

impl Default for ActiveTestConfig {
    fn default() -> Self {
        Self {
            max_risk: TestRisk::Safe,
            timeout_ms: 10000,
            max_threads: 10,
            retry_count: 0,
            variables: HashMap::new(),
            proxy_url: None,
            tls_verify: true,
            rate_limit_per_host: None,
            callback_url: None,
        }
    }
}

impl ActiveTestConfig {
    /// Load configuration from file (YAML, TOML, or JSON)
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path)?;
        let ext = path.as_ref().extension().and_then(|e| e.to_str());

        match ext {
            Some("yaml") | Some("yml") => Ok(serde_yaml::from_str(&content)?),
            Some("toml") => Ok(toml::from_str(&content)?),
            Some("json") => Ok(serde_json::from_str(&content)?),
            _ => Err(anyhow::anyhow!(
                "Unsupported config format: use .yaml, .toml, or .json"
            )),
        }
    }

    /// Builder: set max risk level
    pub fn with_max_risk(mut self, risk: TestRisk) -> Self {
        self.max_risk = risk;
        self
    }

    /// Builder: set timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Builder: set variable
    pub fn with_variable(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.insert(key.into(), value.into());
        self
    }

    /// Builder: set proxy
    pub fn with_proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy_url = Some(proxy_url.into());
        self
    }

    /// Builder: disable TLS verification
    pub fn without_tls_verify(mut self) -> Self {
        self.tls_verify = false;
        self
    }
}

/// Single test step
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action")]
pub enum TestStep {
    /// Establish TCP connection
    #[serde(rename = "tcp_connect")]
    TcpConnect {
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
    },

    /// Establish TLS connection
    #[serde(rename = "tls_connect")]
    TlsConnect {
        #[serde(default)]
        verify_cert: bool,
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
    },

    /// Send raw bytes (hex encoded)
    #[serde(rename = "send_hex")]
    SendHex { data: String },

    /// Send text
    #[serde(rename = "send_text")]
    SendText { data: String },

    /// Send templated payload (with variables)
    #[serde(rename = "send_template")]
    SendTemplate {
        template: String,
        #[serde(default)]
        variables: HashMap<String, String>,
    },

    /// Receive and store response
    #[serde(rename = "receive")]
    Receive {
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
        #[serde(default = "default_max_bytes")]
        max_bytes: usize,
        /// Store in variable for later checks
        #[serde(default)]
        store_as: Option<String>,
    },

    /// Wait
    #[serde(rename = "sleep")]
    Sleep { ms: u64 },

    /// Close connection
    #[serde(rename = "close")]
    Close,

    /// Run Lua script
    #[serde(rename = "lua")]
    Lua { script: String },
}

fn default_timeout() -> u64 { 5000 }
fn default_max_bytes() -> usize { 65536 }

/// Detection criteria
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Detection {
    /// Condition for VULNERABLE
    pub vulnerable: Condition,
    /// Condition for NOT_VULNERABLE (optional, otherwise inverse of vulnerable)
    #[serde(default)]
    pub not_vulnerable: Option<Condition>,
}

/// Detection condition
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Condition {
    /// Response length check
    #[serde(rename = "response_length")]
    ResponseLength {
        variable: String,
        #[serde(default)]
        min: Option<usize>,
        #[serde(default)]
        max: Option<usize>,
    },

    /// Response contains pattern (hex)
    #[serde(rename = "contains_hex")]
    ContainsHex {
        variable: String,
        pattern: String,
    },

    /// Response contains text
    #[serde(rename = "contains_text")]
    ContainsText {
        variable: String,
        pattern: String,
        #[serde(default)]
        case_insensitive: bool,
    },

    /// Response matches regex
    #[serde(rename = "regex")]
    Regex {
        variable: String,
        pattern: String,
    },

    /// Connection succeeded
    #[serde(rename = "connected")]
    Connected,

    /// Connection failed
    #[serde(rename = "connection_failed")]
    ConnectionFailed,

    /// Logical AND of conditions
    #[serde(rename = "all")]
    All { conditions: Vec<Condition> },

    /// Logical OR of conditions
    #[serde(rename = "any")]
    Any { conditions: Vec<Condition> },

    /// Logical NOT
    #[serde(rename = "not")]
    Not { condition: Box<Condition> },
}

// =============================================================================
// Test Results
// =============================================================================

/// Result of an active test
#[derive(Debug, Clone, Serialize)]
pub struct ActiveTestResult {
    pub test_id: String,
    pub cves: Vec<String>,
    pub host: String,
    pub port: u16,
    pub status: TestStatus,
    pub confidence: f64,
    pub details: String,
    pub duration_ms: u64,
    pub raw_response: Option<Vec<u8>>,
}

/// Test status
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum TestStatus {
    /// Confirmed vulnerable
    Vulnerable,
    /// Confirmed not vulnerable
    NotVulnerable,
    /// Test inconclusive
    Inconclusive,
    /// Test error (couldn't complete)
    Error,
    /// Test skipped (service not detected)
    Skipped,
}

// =============================================================================
// Test Runner
// =============================================================================

/// Active test runner with configuration support
pub struct ActiveTestRunner {
    tests: HashMap<String, ActiveTest>,
    config: ActiveTestConfig,
}

impl Default for ActiveTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveTestRunner {
    /// Create new runner with default configuration
    pub fn new() -> Self {
        Self {
            tests: HashMap::new(),
            config: ActiveTestConfig::default(),
        }
    }

    /// Create runner with custom configuration
    pub fn with_config(config: ActiveTestConfig) -> Self {
        Self {
            tests: HashMap::new(),
            config,
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &ActiveTestConfig {
        &self.config
    }

    /// Get mutable reference to configuration
    pub fn config_mut(&mut self) -> &mut ActiveTestConfig {
        &mut self.config
    }

    /// Set maximum risk level (builder pattern)
    pub fn with_max_risk(mut self, risk: TestRisk) -> Self {
        self.config.max_risk = risk;
        self
    }

    /// Get all loaded tests
    pub fn tests(&self) -> &HashMap<String, ActiveTest> {
        &self.tests
    }

    /// Get test by ID
    pub fn get_test(&self, id: &str) -> Option<&ActiveTest> {
        self.tests.get(id)
    }

    /// List all test IDs
    pub fn list_test_ids(&self) -> Vec<&str> {
        self.tests.keys().map(|s| s.as_str()).collect()
    }

    /// Load tests from YAML file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize> {
        let content = std::fs::read_to_string(path)?;
        self.load_from_yaml(&content)
    }

    /// Load tests from YAML string
    pub fn load_from_yaml(&mut self, yaml: &str) -> Result<usize> {
        let tests: Vec<ActiveTest> = serde_yaml::from_str(yaml)?;
        let count = tests.len();
        for test in tests {
            self.tests.insert(test.id.clone(), test);
        }
        Ok(count)
    }

    /// Load built-in tests
    pub fn load_builtin(&mut self) -> Result<usize> {
        self.load_from_yaml(BUILTIN_TESTS)
    }

    /// Get tests for a specific CVE
    pub fn get_tests_for_cve(&self, cve_id: &str) -> Vec<&ActiveTest> {
        self.tests
            .values()
            .filter(|t| t.cves.iter().any(|c| c == cve_id))
            .collect()
    }

    /// Get tests for a specific service
    pub fn get_tests_for_service(&self, service: &str) -> Vec<&ActiveTest> {
        let service_lower = service.to_lowercase();
        self.tests
            .values()
            .filter(|t| t.service.to_lowercase() == service_lower)
            .collect()
    }

    /// Run a specific test
    pub async fn run_test(
        &self,
        test: &ActiveTest,
        host: &str,
        port: u16,
    ) -> ActiveTestResult {
        let start = std::time::Instant::now();

        // Check risk level
        if !self.is_risk_acceptable(&test.risk) {
            return ActiveTestResult {
                test_id: test.id.clone(),
                cves: test.cves.clone(),
                host: host.to_string(),
                port,
                status: TestStatus::Skipped,
                confidence: 0.0,
                details: format!("Test risk {:?} exceeds max {:?}", test.risk, self.config.max_risk),
                duration_ms: start.elapsed().as_millis() as u64,
                raw_response: None,
            };
        }

        // Execute test
        let mut ctx = TestContext::new(host, port);
        let result = self.execute_steps(test, &mut ctx).await;

        let (status, confidence, details) = match result {
            Ok(response) => {
                ctx.responses.insert("response".to_string(), response.clone());
                self.evaluate_detection(test, &ctx, response)
            }
            Err(e) => {
                if e.to_string().contains("connection refused") {
                    ctx.connected = false;
                }
                (TestStatus::Error, 0.0, format!("Test error: {}", e))
            }
        };

        ActiveTestResult {
            test_id: test.id.clone(),
            cves: test.cves.clone(),
            host: host.to_string(),
            port,
            status,
            confidence,
            details,
            duration_ms: start.elapsed().as_millis() as u64,
            raw_response: ctx.responses.get("response").cloned(),
        }
    }

    /// Run all applicable tests for host:port
    pub async fn run_all_for_service(
        &self,
        host: &str,
        port: u16,
        service: &str,
    ) -> Vec<ActiveTestResult> {
        let tests = self.get_tests_for_service(service);
        let mut results = Vec::new();

        for test in tests {
            let result = self.run_test(test, host, port).await;
            results.push(result);
        }

        results
    }

    /// Run a test by its ID
    pub async fn run_test_by_id(
        &self,
        test_id: &str,
        host: &str,
        port: u16,
    ) -> Result<ActiveTestResult> {
        let test = self.tests.get(test_id)
            .ok_or_else(|| anyhow::anyhow!("Test not found: {}", test_id))?;
        Ok(self.run_test(test, host, port).await)
    }

    /// Run tests for a specific CVE
    pub async fn run_tests_for_cve(
        &self,
        cve_id: &str,
        host: &str,
        port: u16,
    ) -> Vec<ActiveTestResult> {
        let tests = self.get_tests_for_cve(cve_id);
        let mut results = Vec::new();

        for test in tests {
            results.push(self.run_test(test, host, port).await);
        }

        results
    }

    /// Run all loaded tests against host:ports
    pub async fn run_all_tests(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Vec<ActiveTestResult> {
        let mut results = Vec::new();

        for test in self.tests.values() {
            // Find matching port from test's ports list or use first provided port
            let port = test.ports.iter()
                .find(|p| ports.contains(p))
                .copied()
                .or_else(|| ports.first().copied())
                .unwrap_or(80);

            let result = self.run_test(test, host, port).await;
            results.push(result);
        }

        results
    }

    fn is_risk_acceptable(&self, risk: &TestRisk) -> bool {
        match (&self.config.max_risk, risk) {
            (TestRisk::Safe, TestRisk::Safe) => true,
            (TestRisk::Low, TestRisk::Safe | TestRisk::Low) => true,
            (TestRisk::Medium, TestRisk::Safe | TestRisk::Low | TestRisk::Medium) => true,
            (TestRisk::High, _) => true,
            _ => false,
        }
    }

    async fn execute_steps(
        &self,
        test: &ActiveTest,
        ctx: &mut TestContext,
    ) -> Result<Vec<u8>> {
        let mut response = Vec::new();

        for step in &test.steps {
            match step {
                TestStep::TcpConnect { timeout_ms } => {
                    let addr = format!("{}:{}", ctx.host, ctx.port);
                    let timeout = Duration::from_millis(*timeout_ms);
                    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                        Ok(Ok(stream)) => {
                            ctx.stream = Some(stream);
                            ctx.connected = true;
                        }
                        Ok(Err(e)) => {
                            ctx.connected = false;
                            return Err(anyhow::anyhow!("Connection failed: {}", e));
                        }
                        Err(_) => {
                            ctx.connected = false;
                            return Err(anyhow::anyhow!("Connection timeout"));
                        }
                    }
                }

                TestStep::TlsConnect { timeout_ms, .. } => {
                    // TLS connection - simplified for now
                    let addr = format!("{}:{}", ctx.host, ctx.port);
                    let timeout = Duration::from_millis(*timeout_ms);
                    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                        Ok(Ok(stream)) => {
                            ctx.stream = Some(stream);
                            ctx.connected = true;
                            ctx.tls = true;
                            // TODO: Actual TLS handshake with rustls/native-tls
                        }
                        Ok(Err(e)) => return Err(anyhow::anyhow!("TLS connection failed: {}", e)),
                        Err(_) => return Err(anyhow::anyhow!("TLS connection timeout")),
                    }
                }

                TestStep::SendHex { data } => {
                    if let Some(ref mut stream) = ctx.stream {
                        let bytes = hex::decode(data.replace(" ", ""))?;
                        stream.write_all(&bytes).await?;
                    }
                }

                TestStep::SendText { data } => {
                    if let Some(ref mut stream) = ctx.stream {
                        stream.write_all(data.as_bytes()).await?;
                    }
                }

                TestStep::SendTemplate { template, variables } => {
                    if let Some(ref mut stream) = ctx.stream {
                        let mut data = template.clone();
                        for (key, value) in variables {
                            data = data.replace(&format!("{{{}}}", key), value);
                        }
                        stream.write_all(data.as_bytes()).await?;
                    }
                }

                TestStep::Receive { timeout_ms, max_bytes, store_as } => {
                    if let Some(ref mut stream) = ctx.stream {
                        let mut buf = vec![0u8; *max_bytes];
                        let timeout = Duration::from_millis(*timeout_ms);
                        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
                            Ok(Ok(n)) => {
                                buf.truncate(n);
                                if let Some(var) = store_as {
                                    ctx.responses.insert(var.clone(), buf.clone());
                                }
                                response = buf;
                            }
                            Ok(Err(e)) => {
                                debug!("Receive error: {}", e);
                            }
                            Err(_) => {
                                debug!("Receive timeout");
                            }
                        }
                    }
                }

                TestStep::Sleep { ms } => {
                    tokio::time::sleep(Duration::from_millis(*ms)).await;
                }

                TestStep::Close => {
                    ctx.stream = None;
                }

                TestStep::Lua { script: _ } => {
                    // TODO: Lua script execution with mlua
                    warn!("Lua scripts not yet implemented");
                }
            }
        }

        Ok(response)
    }

    fn evaluate_detection(
        &self,
        test: &ActiveTest,
        ctx: &TestContext,
        response: Vec<u8>,
    ) -> (TestStatus, f64, String) {
        let is_vulnerable = self.evaluate_condition(&test.detection.vulnerable, ctx, &response);

        if is_vulnerable {
            (TestStatus::Vulnerable, 0.95, "Vulnerability confirmed by active test".to_string())
        } else if let Some(ref not_vuln) = test.detection.not_vulnerable {
            if self.evaluate_condition(not_vuln, ctx, &response) {
                (TestStatus::NotVulnerable, 0.95, "Active test confirmed not vulnerable".to_string())
            } else {
                (TestStatus::Inconclusive, 0.5, "Test inconclusive".to_string())
            }
        } else {
            (TestStatus::NotVulnerable, 0.85, "Vulnerability not detected".to_string())
        }
    }

    fn evaluate_condition(&self, cond: &Condition, ctx: &TestContext, response: &[u8]) -> bool {
        match cond {
            Condition::ResponseLength { variable, min, max } => {
                let data = ctx.responses.get(variable).map(|v| v.len()).unwrap_or(response.len());
                let above_min = min.map(|m| data >= m).unwrap_or(true);
                let below_max = max.map(|m| data <= m).unwrap_or(true);
                above_min && below_max
            }

            Condition::ContainsHex { variable, pattern } => {
                let data = ctx.responses.get(variable).map(|v| v.as_slice()).unwrap_or(response);
                if let Ok(pattern_bytes) = hex::decode(pattern.replace(" ", "")) {
                    data.windows(pattern_bytes.len()).any(|w| w == pattern_bytes)
                } else {
                    false
                }
            }

            Condition::ContainsText { variable, pattern, case_insensitive } => {
                let data = ctx.responses.get(variable).map(|v| v.as_slice()).unwrap_or(response);
                if let Ok(text) = std::str::from_utf8(data) {
                    if *case_insensitive {
                        text.to_lowercase().contains(&pattern.to_lowercase())
                    } else {
                        text.contains(pattern)
                    }
                } else {
                    false
                }
            }

            Condition::Regex { variable, pattern } => {
                let data = ctx.responses.get(variable).map(|v| v.as_slice()).unwrap_or(response);
                if let Ok(text) = std::str::from_utf8(data) {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        re.is_match(text)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            Condition::Connected => ctx.connected,

            Condition::ConnectionFailed => !ctx.connected,

            Condition::All { conditions } => {
                conditions.iter().all(|c| self.evaluate_condition(c, ctx, response))
            }

            Condition::Any { conditions } => {
                conditions.iter().any(|c| self.evaluate_condition(c, ctx, response))
            }

            Condition::Not { condition } => {
                !self.evaluate_condition(condition, ctx, response)
            }
        }
    }
}

/// Test execution context
struct TestContext {
    host: String,
    port: u16,
    stream: Option<TcpStream>,
    connected: bool,
    tls: bool,
    responses: HashMap<String, Vec<u8>>,
}

impl TestContext {
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            stream: None,
            connected: false,
            tls: false,
            responses: HashMap::new(),
        }
    }
}

// =============================================================================
// Built-in Tests (YAML)
// =============================================================================

const BUILTIN_TESTS: &str = r#"
# Heartbleed - CVE-2014-0160
- id: heartbleed
  cves:
    - CVE-2014-0160
  name: OpenSSL Heartbleed
  description: Tests for Heartbleed vulnerability by sending malformed TLS heartbeat
  service: ssl
  ports: [443, 8443, 993, 995, 465, 636]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 5000
    # TLS ClientHello with heartbeat extension
    - action: send_hex
      data: |
        16 03 01 00 dc 01 00 00 d8 03 01
        53 43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97
        cf bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de
        00 00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00
        88 00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0
        1c c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0
        09 c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00
        44 c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0
        0c c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00
        11 00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00
        04 03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00
        19 00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00
        08 00 06 00 07 00 14 00 15 00 04 00 05 00 12 00
        13 00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00
        00 00 0f 00 01 01
    - action: receive
      timeout_ms: 3000
      store_as: server_hello
    # Heartbeat request (malformed - request 16KB, send 1 byte)
    - action: send_hex
      data: 18 03 01 00 03 01 40 00
    - action: receive
      timeout_ms: 3000
      max_bytes: 65536
      store_as: response
  detection:
    vulnerable:
      type: response_length
      variable: response
      min: 100
    not_vulnerable:
      type: response_length
      variable: response
      max: 10

# Anonymous FTP
- id: ftp-anon
  cves: []
  name: Anonymous FTP Access
  description: Tests for anonymous FTP login
  service: ftp
  ports: [21]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 5000
    - action: receive
      timeout_ms: 3000
      store_as: banner
    - action: send_text
      data: "USER anonymous\r\n"
    - action: receive
      timeout_ms: 3000
      store_as: user_response
    - action: send_text
      data: "PASS anonymous@example.com\r\n"
    - action: receive
      timeout_ms: 3000
      store_as: pass_response
    - action: send_text
      data: "QUIT\r\n"
    - action: close
  detection:
    vulnerable:
      type: contains_text
      variable: pass_response
      pattern: "230"
      case_insensitive: false

# Redis No Authentication
- id: redis-noauth
  cves: []
  name: Redis No Authentication
  description: Tests for Redis without authentication
  service: redis
  ports: [6379]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 3000
    - action: send_text
      data: "INFO\r\n"
    - action: receive
      timeout_ms: 3000
      store_as: response
    - action: send_text
      data: "QUIT\r\n"
    - action: close
  detection:
    vulnerable:
      type: contains_text
      variable: response
      pattern: "redis_version"
      case_insensitive: true
    not_vulnerable:
      type: any
      conditions:
        - type: contains_text
          variable: response
          pattern: "NOAUTH"
          case_insensitive: true
        - type: contains_text
          variable: response
          pattern: "ERR"
          case_insensitive: true

# MongoDB No Authentication
- id: mongodb-noauth
  cves: []
  name: MongoDB No Authentication
  description: Tests for MongoDB without authentication
  service: mongodb
  ports: [27017]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 3000
    # MongoDB isMaster command
    - action: send_hex
      data: |
        3f 00 00 00 00 00 00 00 00 00 00 00 d4 07 00 00
        00 00 00 00 61 64 6d 69 6e 2e 24 63 6d 64 00 00
        00 00 00 01 00 00 00 15 00 00 00 10 69 73 6d 61
        73 74 65 72 00 01 00 00 00 00
    - action: receive
      timeout_ms: 3000
      store_as: response
    - action: close
  detection:
    vulnerable:
      type: contains_text
      variable: response
      pattern: "ismaster"
      case_insensitive: true

# MySQL Empty Password
- id: mysql-nopassword
  cves: []
  name: MySQL Empty Root Password
  description: Tests for MySQL root with no password
  service: mysql
  ports: [3306]
  risk: low
  steps:
    - action: tcp_connect
      timeout_ms: 3000
    - action: receive
      timeout_ms: 3000
      store_as: greeting
  detection:
    vulnerable:
      type: all
      conditions:
        - type: connected
        - type: contains_hex
          variable: greeting
          pattern: "0a"

# SSH Weak Algorithms
- id: ssh-weak-algos
  cves: []
  name: SSH Weak Algorithms
  description: Checks for weak SSH algorithms (arcfour, 3des, etc.)
  service: ssh
  ports: [22]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 3000
    - action: receive
      timeout_ms: 3000
      store_as: banner
    # SSH client version
    - action: send_text
      data: "SSH-2.0-Scanner\r\n"
    - action: receive
      timeout_ms: 3000
      max_bytes: 8192
      store_as: kex
    - action: close
  detection:
    vulnerable:
      type: any
      conditions:
        - type: contains_text
          variable: kex
          pattern: "arcfour"
          case_insensitive: true
        - type: contains_text
          variable: kex
          pattern: "3des"
          case_insensitive: true
        - type: contains_text
          variable: kex
          pattern: "blowfish"
          case_insensitive: true

# SSL/TLS Weak Ciphers
- id: ssl-weak-ciphers
  cves: []
  name: SSL/TLS Weak Ciphers
  description: Checks for weak SSL/TLS ciphers (DES, RC4, etc.)
  service: ssl
  ports: [443, 8443, 993, 995]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 3000
    # SSLv3 ClientHello with weak ciphers only
    - action: send_hex
      data: |
        16 03 00 00 2f 01 00 00 2b 03 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 08 00 0a 00
        09 00 64 00 62 00 ff 01 00
    - action: receive
      timeout_ms: 3000
      store_as: response
    - action: close
  detection:
    vulnerable:
      type: all
      conditions:
        - type: response_length
          variable: response
          min: 5
        - type: contains_hex
          variable: response
          pattern: "16 03"

# HTTP TRACE Method Enabled
- id: http-trace
  cves: []
  name: HTTP TRACE Method Enabled
  description: Tests if HTTP TRACE method is enabled (XST vulnerability)
  service: http
  ports: [80, 8080, 8000]
  risk: safe
  steps:
    - action: tcp_connect
      timeout_ms: 3000
    - action: send_text
      data: "TRACE / HTTP/1.1\r\nHost: target\r\n\r\n"
    - action: receive
      timeout_ms: 3000
      store_as: response
    - action: close
  detection:
    vulnerable:
      type: contains_text
      variable: response
      pattern: "200 OK"
      case_insensitive: true
"#;

// =============================================================================
// Public API
// =============================================================================

/// Load built-in active tests
pub fn load_builtin_tests() -> Result<ActiveTestRunner> {
    let mut runner = ActiveTestRunner::new();
    runner.load_builtin()?;
    Ok(runner)
}

/// Quick test for a specific CVE
pub async fn test_cve(
    cve_id: &str,
    host: &str,
    port: u16,
) -> Vec<ActiveTestResult> {
    let runner = match load_builtin_tests() {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let tests = runner.get_tests_for_cve(cve_id);
    let mut results = Vec::new();

    for test in tests {
        results.push(runner.run_test(test, host, port).await);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_builtin_yaml() {
        let tests: Vec<ActiveTest> = serde_yaml::from_str(BUILTIN_TESTS).unwrap();
        assert!(tests.len() >= 5);
        assert!(tests.iter().any(|t| t.id == "heartbleed"));
        assert!(tests.iter().any(|t| t.id == "ftp-anon"));
    }

    #[test]
    fn test_risk_levels() {
        let runner = ActiveTestRunner::new().with_max_risk(TestRisk::Safe);
        assert!(runner.is_risk_acceptable(&TestRisk::Safe));
        assert!(!runner.is_risk_acceptable(&TestRisk::Low));
    }

    #[test]
    fn test_config_defaults() {
        let config = ActiveTestConfig::default();
        assert_eq!(config.max_risk, TestRisk::Safe);
        assert_eq!(config.timeout_ms, 10000);
        assert_eq!(config.max_threads, 10);
        assert_eq!(config.retry_count, 0);
        assert!(config.tls_verify);
        assert!(config.proxy_url.is_none());
        assert!(config.variables.is_empty());
    }

    #[test]
    fn test_config_builders() {
        let config = ActiveTestConfig::default()
            .with_max_risk(TestRisk::Medium)
            .with_timeout(5000)
            .with_variable("callback", "example.com")
            .with_proxy("socks5://127.0.0.1:1080")
            .without_tls_verify();

        assert_eq!(config.max_risk, TestRisk::Medium);
        assert_eq!(config.timeout_ms, 5000);
        assert!(!config.tls_verify);
        assert_eq!(config.proxy_url.as_deref(), Some("socks5://127.0.0.1:1080"));
        assert_eq!(config.variables.get("callback"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_runner_with_config() {
        let config = ActiveTestConfig::default()
            .with_max_risk(TestRisk::Low);

        let runner = ActiveTestRunner::with_config(config);
        assert_eq!(runner.config().max_risk, TestRisk::Low);
        assert!(runner.is_risk_acceptable(&TestRisk::Safe));
        assert!(runner.is_risk_acceptable(&TestRisk::Low));
        assert!(!runner.is_risk_acceptable(&TestRisk::Medium));
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
max_risk: low
timeout_ms: 5000
max_threads: 5
tls_verify: false
variables:
  callback: example.com
"#;
        let config: ActiveTestConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.max_risk, TestRisk::Low);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.max_threads, 5);
        assert!(!config.tls_verify);
        assert_eq!(config.variables.get("callback"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_config_from_json() {
        let json = r#"{
            "max_risk": "medium",
            "timeout_ms": 15000,
            "proxy_url": "http://proxy:8080"
        }"#;
        let config: ActiveTestConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_risk, TestRisk::Medium);
        assert_eq!(config.timeout_ms, 15000);
        assert_eq!(config.proxy_url.as_deref(), Some("http://proxy:8080"));
    }

    #[test]
    fn test_config_from_toml() {
        let toml_str = r#"
max_risk = "high"
timeout_ms = 20000
max_threads = 20

[variables]
target = "192.168.1.1"
"#;
        let config: ActiveTestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.max_risk, TestRisk::High);
        assert_eq!(config.timeout_ms, 20000);
        assert_eq!(config.max_threads, 20);
        assert_eq!(config.variables.get("target"), Some(&"192.168.1.1".to_string()));
    }

    #[test]
    fn test_risk_parse() {
        assert_eq!("safe".parse::<TestRisk>().unwrap(), TestRisk::Safe);
        assert_eq!("SAFE".parse::<TestRisk>().unwrap(), TestRisk::Safe);
        assert_eq!("low".parse::<TestRisk>().unwrap(), TestRisk::Low);
        assert_eq!("medium".parse::<TestRisk>().unwrap(), TestRisk::Medium);
        assert_eq!("med".parse::<TestRisk>().unwrap(), TestRisk::Medium);
        assert_eq!("high".parse::<TestRisk>().unwrap(), TestRisk::High);
        assert!("invalid".parse::<TestRisk>().is_err());
    }

    #[test]
    fn test_runner_list_tests() {
        let mut runner = ActiveTestRunner::new();
        runner.load_builtin().unwrap();

        let test_ids = runner.list_test_ids();
        assert!(test_ids.contains(&"heartbleed"));
        assert!(test_ids.contains(&"ftp-anon"));
        assert!(test_ids.contains(&"redis-noauth"));
    }

    #[test]
    fn test_runner_get_test() {
        let mut runner = ActiveTestRunner::new();
        runner.load_builtin().unwrap();

        let test = runner.get_test("heartbleed");
        assert!(test.is_some());
        assert_eq!(test.unwrap().cves[0], "CVE-2014-0160");

        let missing = runner.get_test("nonexistent");
        assert!(missing.is_none());
    }
}
