# RsScan

A high-performance network vulnerability scanner written in Rust.

## Features

- **Network Scanning** - TCP connect and SYN scanning with configurable concurrency
- **Banner Grabbing** - Service detection for SSH, HTTP, FTP, SMB, MySQL, PostgreSQL, Redis, MongoDB, and more
- **CVE Matching** - NVD database sync with CPE-based version matching and risk scoring
- **Active Testing** - YAML-based vulnerability probes (Heartbleed, FTP anonymous, Redis noauth, etc.)
- **REST API** - Axum-based API server for scan management and CVE search
- **Endpoint Agent** - Cross-platform software inventory collection (dpkg, rpm, pip, npm, Windows Registry)
- **Plugin System** - Extensible protocol detection (Modbus ICS/SCADA included)

## Quick Start

```bash
# Build
cargo build --release

# Sync CVE database from NVD
rsscan sync --days 30

# Scan a target
rsscan scan 192.168.1.0/24

# Scan with service detection
rsscan scan 192.168.1.1 --detect-services

# Search CVE database
rsscan search apache --version 2.4.49

# Run active vulnerability tests
rsscan test 192.168.1.1 --all

# Start REST API server
rsscan server --port 8080

# List available plugins
rsscan plugins --list
```

## Agent Mode

The endpoint agent collects software inventory and reports to a central server.

```bash
# Run once
rsscan-agent --server https://server:8080 --api-key KEY --once

# Run as daemon (default: hourly scans)
rsscan-agent --server https://server:8080 --api-key KEY --interval 3600
```

## CVE Database Sync

```bash
# NVD sync (last 30 days)
rsscan sync --days 30

# Sync all sources (NVD + CISA KEV + EPSS)
rsscan sync --all

# CISA Known Exploited Vulnerabilities
rsscan sync --kev

# EPSS scores
rsscan sync --epss
```

## Risk Scoring

RsScan calculates risk scores using:

```
Risk = CVSS * Confidence * EPSS * Asset Criticality * Multipliers
```

- **CVSS** - Base vulnerability severity
- **Confidence** - Match quality (exact version, range, product-only)
- **EPSS** - Exploit Prediction Scoring System probability
- **KEV multiplier** - Boost for CISA Known Exploited Vulnerabilities
- **Exploit multiplier** - Boost when public exploits exist

## Building

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release
```

Requires root/sudo for SYN scanning (raw sockets).

## License

MIT
