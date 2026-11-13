<div align="center">

# ⚡ ThreatPulse

**Automated Threat Intelligence & SIEM Detection Rule Aggregator**

[![Update Threat Feeds & SIEM Rules](https://github.com/yaasiinaxmed/threatpulse/actions/workflows/update-feeds.yml/badge.svg?branch=main)](https://github.com/yaasiinaxmed/threatpulse/actions/workflows/update-feeds.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Feed Status](https://img.shields.io/badge/Threat%20Feeds-Active%20%26%20Synchronized-emerald?style=flat&logo=securityscorecard&logoColor=white)](https://github.com/yaasiinaxmed/threatpulse/tree/main/dist)

*A unified cybersecurity hub combining **Network Defense (IP Blocklists)** and **Behavioral SIEM Detection (Sigma Rules)** into clean, automated endpoints. Auto-updated every 24 hours via GitHub Actions.*

</div>

---

## 💡 How ThreatPulse Works: Two Defense Layers in One Repo

Modern cybersecurity requires defending against external attackers and catching unauthorized actions inside your systems. ThreatPulse unifies both into a single repository:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             ⚡ ThreatPulse Hub                              │
└──────────────────────┬───────────────────────────────┬──────────────────────┘
                       │                               │
                       ▼                               ▼
      🛡️ LAYER 1: NETWORK DEFENSE (IP Blocklists)     🔍 LAYER 2: LOG & SIEM DETECTION (Sigma)
      "WHO is attacking from the outside"             "WHAT suspicious behavior is happening"
      ──────────────────────────────────────────      ───────────────────────────────────────
      • 45,000+ Cleaned Malicious IPs                 • 3,100+ Detection Rules (more than Elastic!)
      • Drops attacker traffic at the Firewall/Edge   • Detects Ransomware, Privilege Escalation
      • Sources: Spamhaus, CINS Army, Blocklist.de    • Formats: Windows, Linux, Cloud, Web, Network
```

### 1. 🛡️ IP Blocklist Sources (External Threat Intelligence)
- **What it does:** Ingests live attacker IPs and hijacked CIDR networks from multiple global sources (CINS Army, stamparm/ipsum, Spamhaus DROP, Blocklist.de, CrowdSec).
- **The Magic:** Instead of querying 5 different APIs, ThreatPulse deduplicates them, removes private/safe IPs (Google DNS, Cloudflare), and gives you **one clean URL** to plug into firewalls (iptables, pfSense, AWS WAF, Nginx).

### 2. 🔍 Sigma Rules (Internal SIEM Detection Logic)
- **What it does:** Sigma is the open industry standard for detection signatures. ThreatPulse aggregates and normalizes **over 3,160+ Sigma rules** — giving you broader detection coverage than default Elasticsearch rules alone!
- **The Magic:** While IP blocklists catch attackers at the door, Sigma rules inspect log telemetry (Windows Event Logs, Linux Syslog, Cloud audit trails) to catch attackers who are already inside trying to escalate privileges, dump credentials (e.g., Mimikatz), or execute malware.

---

## 📊 Live Threat Telemetry Dashboard

<div align="center">

| 🌐 Total Clean Malicious IPs | 🚨 Critical Threats (Score ≥ 4) | 📦 Collapsed CIDR Drop Ranges | ⚡ Compiled Sigma SIEM Rules |
| :---: | :---: | :---: | :---: |
| <img src="https://img.shields.io/badge/45,623-Malicious_IPs-e11d48?style=for-the-badge&logo=cloudflare&logoColor=white" /> | <img src="https://img.shields.io/badge/21,582-Critical_Threats-b91c1c?style=for-the-badge&logo=target&logoColor=white" /> | <img src="https://img.shields.io/badge/1,620-Subnets_Blocked-4f46e5?style=for-the-badge&logo=shield&logoColor=white" /> | <img src="https://img.shields.io/badge/3,164-SIEM_Rules-059669?style=for-the-badge&logo=datadog&logoColor=white" /> |

</div>

### 📈 Feed Summary & Direct Artifacts

#### 🛡️ Layer 1: Malicious IP Blocklists
| Dataset | Indicators | Description | Direct Live CDN Link |
| :--- | :---: | :--- | :--- |
| **All Malicious IPs** | **`45,623`** | Clean IPv4/IPv6 deduplicated across all feeds | [`dist/ips/all_malicious_ips.txt`](dist/ips/all_malicious_ips.txt) |
| **High Confidence IPs** | **`21,582`** | Confirmed multi-source threats (reputation score ≥ 4) | [`dist/ips/high_confidence_ips.txt`](dist/ips/high_confidence_ips.txt) |
| **CIDR DROP Subnets** | **`1,620`** | Hijacked & spam networks collapsed to minimal CIDR blocks | [`dist/ips/cidr_drop.txt`](dist/ips/cidr_drop.txt) |
| **STIX 2.1 Threat Bundle** | **`5,000+`** | Standardized threat intelligence format for SIEM/SOAR | [`dist/stix/stix2_bundle.json`](dist/stix/stix2_bundle.json) |

#### 🔍 Layer 2: Sigma SIEM Detection Rules (3,160+ Rules)
| Category | Rules Count | Description | Direct Live CDN Link |
| :--- | :---: | :--- | :--- |
| **Complete Rules Index** | **`3,164`** | Complete index with MITRE ATT&CK tags and levels | [`dist/sigma/rules_index.json`](dist/sigma/rules_index.json) |
| **Windows Rules** | **`2,427`** | Process creation, PowerShell, LSASS access, Active Directory | [`dist/sigma/rules_windows.json`](dist/sigma/rules_windows.json) |
| **Linux Rules** | **`280`** | Auditd, Syslog, bash history tampering, SSH anomalies | [`dist/sigma/rules_linux.json`](dist/sigma/rules_linux.json) |
| **Cloud Rules** | **`226`** | AWS CloudTrail, Azure Activity, GCP IAM modifications | [`dist/sigma/rules_cloud.json`](dist/sigma/rules_cloud.json) |
| **Network & Web** | **`99`** | Proxy, DNS tunneling, Web attacks, and SQL injection | [`dist/sigma/rules_network.json`](dist/sigma/rules_network.json) / [`web`](dist/sigma/rules_web.json) |

*Dashboard last synchronized:* **`Auto-refreshed daily at 00:00 UTC`**

---

## 🌐 Using as a Free Live API / Feed

You can pull the latest threat intelligence and SIEM detection rules directly into your environment via GitHub's high-speed Raw CDN:

### Quick Integration Examples

#### 1. In Custom SIEM & SOC Telemetry (Elasticsearch, Wazuh, Splunk, Suricata):

ThreatPulse feeds drop directly into custom SIEM detection pipelines and threat-hunting engines:

- **Elasticsearch / Logstash Ingestion:**
  Ingest the pre-formatted `stix2_bundle.json` or poll the high-confidence feed in Logstash:
  ```ruby
  input {
    http_poller {
      urls => {
        threatpulse => "https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/high_confidence_ips.txt"
      }
      schedule => { cron => "0 1 * * *" }
      codec => "line"
    }
  }
  filter {
    if [message] =~ /^#/ { drop {} }
    mutate { add_field => { "threat.feed" => "threatpulse" "threat.indicator" => "%{message}" } }
  }
  output {
    elasticsearch { hosts => ["http://localhost:9200"] index => "threat-intel-threatpulse" }
  }
  ```

- **Wazuh / Suricata / Snort IP Sets:**
  Use `cidr_drop.txt` and `high_confidence_ips.txt` as a periodic external dynamic list (CDB lists in Wazuh or IP Rep lists in Suricata) to trigger high-severity alerts on inbound SSH or web brute-force attempts.

- **Splunk Threat Intelligence Lookup:**
  Import `high_confidence_ips.txt` directly as an automated daily KV Store lookup table to cross-reference with your firewall and proxy access logs.

#### 2. In Python (SOAR Automation / Security Scripts):
```python
import httpx

FEED_URL = "https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/high_confidence_ips.txt"
resp = httpx.get(FEED_URL)
blocked_ips = set(line.strip() for line in resp.text.splitlines() if line and not line.startswith("#"))

# Real-time incident response / IP lookup in your custom SOC backend
incoming_ip = "185.220.101.5"
if incoming_ip in blocked_ips:
    print(f"🚨 ALERT: Inbound connection from known malicious IP {incoming_ip}!")
    # Trigger SOAR isolation / automated firewall ban
```

#### 3. In Linux Edge Firewall (iptables / UFW):
```bash
curl -sSL https://raw.githubusercontent.com/yaasiinaxmed/threatpulse/main/dist/ips/high_confidence_ips.txt | grep -v '^#' | while read ip; do
  iptables -A INPUT -s "$ip" -j DROP
done
```

---

## 📡 Upstream Intelligence Sources

ThreatPulse continuously aggregates, validates, and cross-references data from the following verified sources:

### IP Threat Intelligence
1. **[CINS Army (CI-BadGuys)](https://cinsscore.com/)**: Sentinel IPS curated active malicious IP attack list ([ci-badguys.txt](https://cinsscore.com/list/ci-badguys.txt)).
2. **[stamparm/ipsum](https://github.com/stamparm/ipsum)**: Aggregated multi-feed threat score list ([sekuripy mirror](https://www.sekuripy.hr/labs/ipsum/)).
3. **[The Spamhaus Project](https://www.spamhaus.org/drop/)**: Don't Route Or Peer (DROP & EDROP) lists for hijacked / malicious CIDR blocks.
4. **[Blocklist.de](https://www.blocklist.de/)**: Real-time fail2ban and SSH brute-force attack telemetry.
5. **[CrowdSec](https://www.crowdsec.net/)**: CrowdSec Central API (CAPI) & [FireHOL community netsets](https://github.com/firehol/blocklist-ipsets).

### SIEM Detection Logic
6. **[SigmaHQ Detection Rules](https://github.com/SigmaHQ/sigma)**: Open standard for generic detection signatures across log engines (3,160+ community-maintained rules mapped to MITRE ATT&CK).

---

## 🚀 Key Features

- **⚡ Multi-Source Aggregation:**
  - Automated ingestion from Spamhaus, Ipsum, Blocklist.de, CrowdSec, CINS Army, and SigmaHQ.
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
