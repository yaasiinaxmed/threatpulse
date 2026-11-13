"""Exporters: Generates normalized plaintext, CIDR drops, STIX 2.1 JSON, and Sigma bundles."""

from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List, Sequence
from uuid import uuid4
from threatpulse.models.indicators import IPIndicator, SigmaRule


def export_indicators(
    single_ips: Sequence[IPIndicator],
    cidr_drops: Sequence[IPIndicator],
    dist_dir: Path,
) -> Dict[str, Path]:
    """Writes IP and CIDR threat lists into dist/ips/ and STIX 2.1 bundle into dist/stix/."""
    ips_dir = dist_dir / "ips"
    stix_dir = dist_dir / "stix"
    ips_dir.mkdir(parents=True, exist_ok=True)
    stix_dir.mkdir(parents=True, exist_ok=True)

    all_ips_path = ips_dir / "all_malicious_ips.txt"
    high_conf_path = ips_dir / "high_confidence_ips.txt"
    cidr_path = ips_dir / "cidr_drop.txt"
    stix_path = stix_dir / "stix2_bundle.json"

    # 1. All Malicious IPs
    with open(all_ips_path, "w", encoding="utf-8") as f:
        f.write(f"# ThreatPulse Aggregated Malicious IPs\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total: {len(single_ips)}\n#\n")
        for ind in single_ips:
            f.write(f"{ind.ip_or_network}\n")

    # 2. High Confidence IPs (Score >= 4)
    high_conf = [ind for ind in single_ips if ind.score >= 4]
    with open(high_conf_path, "w", encoding="utf-8") as f:
        f.write(f"# ThreatPulse High Confidence Malicious IPs (Score >= 4)\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total: {len(high_conf)}\n#\n")
        for ind in high_conf:
            f.write(f"{ind.ip_or_network}\n")

    # 3. CIDR DROP List
    with open(cidr_path, "w", encoding="utf-8") as f:
        f.write(f"# ThreatPulse Collapsed CIDR Drop Networks\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total: {len(cidr_drops)}\n#\n")
        for ind in cidr_drops:
            f.write(f"{ind.ip_or_network}\n")

    # 4. STIX 2.1 Bundle (sample of highest confidence indicators to keep JSON lightweight)
    stix_objects = []
    bundle_id = f"bundle--{uuid4()}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    for ind in high_conf[:5000]:  # Top 5,000 high-confidence for SIEM ingestion
        stix_pattern = (
            f"[ipv4-addr:value = '{ind.ip_or_network}']"
            if ":" not in ind.ip_or_network
            else f"[ipv6-addr:value = '{ind.ip_or_network}']"
        )
        stix_objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Malicious IP {ind.ip_or_network}",
                "pattern": stix_pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": min(100, ind.score * 20),
                "labels": ["malicious-activity", f"source:{ind.source}"],
            }
        )

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects,
    }

    with open(stix_path, "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=2)

    return {
        "all_ips": all_ips_path,
        "high_confidence": high_conf_path,
        "cidr_drop": cidr_path,
        "stix": stix_path,
    }


def export_sigma_rules(
    all_rules: List[SigmaRule],
    categorized: Dict[str, List[SigmaRule]],
    dist_dir: Path,
) -> Dict[str, Path]:
    """Writes compiled Sigma rule bundles and index to dist/sigma/."""
    sigma_dir = dist_dir / "sigma"
    sigma_dir.mkdir(parents=True, exist_ok=True)

    index_path = sigma_dir / "rules_index.json"
    outputs = {"index": index_path}

    index_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(all_rules),
        "categories": {cat: len(rules) for cat, rules in categorized.items()},
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "level": r.level,
                "tags": r.tags,
            }
            for r in all_rules
        ],
    }

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2)

    # Export categorized rule bundles
    for cat, rules in categorized.items():
        cat_file = sigma_dir / f"rules_{cat}.json"
        with open(cat_file, "w", encoding="utf-8") as f:
            json.dump([r.model_dump() for r in rules], f, indent=2)
        outputs[cat] = cat_file

    return outputs
