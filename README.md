<div align="center">

# ⚡ ThreatPulse

**Automated Threat Intelligence & SIEM Detection Rule Aggregator**

[![Update Threat Feeds & SIEM Rules](https://github.com/yaasiinaxmed/threatpulse/actions/workflows/update-feeds.yml/badge.svg?branch=main)](https://github.com/yaasiinaxmed/threatpulse/actions/workflows/update-feeds.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Feed Status](https://img.shields.io/badge/Threat%20Feeds-Active%20%26%20Synchronized-emerald?style=flat&logo=securityscorecard&logoColor=white)](https://github.com/yaasiinaxmed/threatpulse/tree/main/dist)

*Continuously ingests, normalizes, deduplicates, and validates global malicious IP blocklists and Sigma SIEM rules. Auto-updated every 24 hours via GitHub Actions.*

</div>

---

## 🛡️ Live Threat Telemetry Dashboard

<div align="center">

| 🌐 Total Clean Malicious IPs | 🚨 High Confidence (Score ≥ 4) | 📦 Collapsed CIDR Drop Ranges | ⚡ Active SIEM Feeds |
| :---: | :---: | :---: | :---: |
| <img src="https://img.shields.io/badge/45,251-Malicious_IPs-e11d48?style=for-the-badge&logo=cloudflare&logoColor=white" /> | <img src="https://img.shields.io/badge/21,419-Critical_Threats-b91c1c?style=for-the-badge&logo=target&logoColor=white" /> | <img src="https://img.shields.io/badge/1,620-Subnets_Blocked-4f46e5?style=for-the-badge&logo=shield&logoColor=white" /> | <img src="https://img.shields.io/badge/STIX_2.1-Active_Bundle-059669?style=for-the-badge&logo=datadog&logoColor=white" /> |

</div>

### 📈 Feed Summary & Direct Artifacts

| Feed Dataset | Indicators | Description | Direct Live CDN Link |
| :--- | :---: | :--- | :--- |
| **All Malicious IPs** | **`45,251`** | Deduplicated IPv4/IPv6 across all ingested feeds | [`dist/ips/all_malicious_ips.txt`](dist/ips/all_malicious_ips.txt) |
| **High Confidence IPs** | **`21,419`** | Multi-source confirmed threats (reputation score ≥ 4) | [`dist/ips/high_confidence_ips.txt`](dist/ips/high_confidence_ips.txt) |
| **CIDR DROP Subnets** | **`1,620`** | Hijacked & spam networks collapsed to minimal CIDR blocks | [`dist/ips/cidr_drop.txt`](dist/ips/cidr_drop.txt) |
| **STIX 2.1 Threat Bundle** | **`5,000+`** | Standardized threat intelligence format for SIEM/SOAR | [`dist/stix/stix2_bundle.json`](dist/stix/stix2_bundle.json) |

*Dashboard last synchronized:* **`2026-11-13 05:00:00 UTC`** *(Auto-refreshed daily at 00:00 UTC)*

---

## 🌐 Using as a Free Live API / Feed

You can pull the latest sanitized threat feeds directly into your SIEM, firewalls, or Python applications via GitHub Raw CDN:

| Feed Type | Format | Raw URL Endpoint |
| :--- | :--- | :--- |
| **All Malicious IPs** | Plaintext | `https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/all_malicious_ips.txt` |
| **High Confidence IPs** | Plaintext | `https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/high_confidence_ips.txt` |
| **CIDR DROP Ranges** | Plaintext | `https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/cidr_drop.txt` |
| **STIX 2.1 Threat Bundle** | JSON | `https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/stix/stix2_bundle.json` |

### Quick Integration Examples

#### 1. In Bash / Linux Firewall:
```bash
curl -sSL https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/high_confidence_ips.txt | grep -v '^#' | while read ip; do
  iptables -A INPUT -s "$ip" -j DROP
done
```

#### 2. In Python:
```python
import httpx

FEED_URL = "https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/high_confidence_ips.txt"
resp = httpx.get(FEED_URL)
blocked_ips = set(line.strip() for line in resp.text.splitlines() if line and not line.startswith("#"))

if "185.220.101.5" in blocked_ips:
    print("🚨 Block connection!")
```

---

## 📡 Upstream Intelligence Sources

ThreatPulse continuously aggregates, validates, and cross-references data from the following verified sources:

1. **[CINS Army (CI-BadGuys)](https://cinsscore.com/)**: Sentinel IPS curated active malicious IP attack list ([ci-badguys.txt](https://cinsscore.com/list/ci-badguys.txt)).
2. **[stamparm/ipsum](https://github.com/stamparm/ipsum)**: Aggregated multi-feed threat score list ([sekuripy mirror](https://www.sekuripy.hr/labs/ipsum/)).
3. **[The Spamhaus Project](https://www.spamhaus.org/drop/)**: Don't Route Or Peer (DROP & EDROP) lists for hijacked / malicious CIDR blocks.
4. **[Blocklist.de](https://www.blocklist.de/)**: Real-time fail2ban and SSH brute-force attack telemetry.
5. **[CrowdSec](https://www.crowdsec.net/)**: CrowdSec Central API (CAPI) & [FireHOL community netsets](https://github.com/firehol/blocklist-ipsets).
6. **[SigmaHQ Detection Rules](https://github.com/SigmaHQ/sigma)**: Open standard for generic detection signatures across log engines.

---

## 🚀 Key Features

- **⚡ Multi-Source Aggregation:**
  - Automated ingestion from Spamhaus, Ipsum, Blocklist.de, CrowdSec, and SigmaHQ.
- **🛡️ Strict Sanitization & False Positive Prevention:**
  - Bogon and RFC1918 private range removal.
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

## 🤝 Contributing
Contributions are warmly welcomed! Please read our [Contributing Guide](CONTRIBUTING.md) to get started.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
