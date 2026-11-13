<div align="center">

# ⚡ ThreatPulse

**Automated Threat Intelligence & SIEM Detection Rule Aggregator**

[![Update Threat Feeds & SIEM Rules](https://github.com/yaasiinaxmed/threatpulse/actions/workflows/update-feeds.yml/badge.svg)](https://github.com/yaasiinaxmed/threatpulse/actions/workflows/update-feeds.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

*Continuously ingests, normalizes, deduplicates, and validates global malicious IP blocklists and Sigma SIEM rules. Auto-updated every 24 hours via GitHub Actions.*

</div>

---

## 📊 Live Feed Statistics (Auto-Updated Daily)

| Metric / Feed Category | Count | Artifact Path |
| :--- | :--- | :--- |
| **Total Malicious IPs** | `<!-- STATS_TOTAL_IPS -->0<!-- END_STATS_TOTAL_IPS -->` | [`dist/ips/all_malicious_ips.txt`](dist/ips/all_malicious_ips.txt) |
| **High Confidence IPs (Score ≥ 4)** | `<!-- STATS_HIGH_CONF -->0<!-- END_STATS_HIGH_CONF -->` | [`dist/ips/high_confidence_ips.txt`](dist/ips/high_confidence_ips.txt) |
| **Collapsed CIDR DROP Ranges** | `<!-- STATS_CIDR_DROPS -->0<!-- END_STATS_CIDR_DROPS -->` | [`dist/ips/cidr_drop.txt`](dist/ips/cidr_drop.txt) |
| **STIX 2.1 Threat Bundle** | `Active` | [`dist/stix/stix2_bundle.json`](dist/stix/stix2_bundle.json) |
| **Compiled Sigma SIEM Rules** | `Categorized` | [`dist/sigma/rules_index.json`](dist/sigma/rules_index.json) |

*Last sync timestamp:* **`<!-- STATS_UPDATED -->Pending initial scheduled run<!-- END_STATS_UPDATED -->`**

---

## 🚀 Key Features

- **⚡ Multi-Source Aggregation:**
  - **stamparm/ipsum** (Multi-source score aggregation with configurable minimum score).
  - **Spamhaus DROP** (v4, v6 JSON feeds with automatic plain-text fallback).
  - **Blocklist.de** (Real-time brute force & SSH attacker IPs).
  - **CrowdSec** (CAPI decisions stream with FireHOL community fallback).
  - **SigmaHQ** (Full SIEM detection rule parser categorized into `linux`, `windows`, `web`, `network`, and `cloud`).

- **🛡️ Strict Sanitization & False Positive Prevention:**
  - Automated bogon and RFC1918 private range removal.
  - Safe-list validation (`allowlist.txt`) guarding Cloudflare Anycast, Google DNS, Quad9, and GitHub networks.
  - Intelligent CIDR collapsing (`ipaddress.collapse_addresses`), removing redundant subnets and individual covered IPs.

- **📦 Enterprise-Ready Export Formats:**
  - Plaintext line-delimited lists for firewall, pfSense, and iptables ingestion.
  - **STIX 2.1 JSON** standard for direct SIEM/SOAR integration (Splunk, Elastic, Sentinel).
  - Modular Sigma rule JSON bundles categorized for detection engineers.

---

## 🛠️ Installation & Usage

### 1. Clone & Setup
```bash
git clone https://github.com/yaasiinaxmed/threatpulse.git
cd threatpulse

# Install with pip / uv
pip install -e ".[dev]"
```

### 2. CLI Commands

#### Update feeds & compile exports:
```bash
threatpulse update --min-score 3 --dist dist
```

#### Check an IP against blocklists:
```bash
threatpulse check-ip 185.220.101.5
```

#### View compiled feed statistics:
```bash
threatpulse stats
```

---

## 🧪 Running Unit Tests
```bash
pytest -v
```

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
