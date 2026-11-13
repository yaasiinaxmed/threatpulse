"""SIEM Rule Collector: SigmaHQ Detection Rules Parser & Bundler."""

from __future__ import annotations
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Dict, List, Tuple
import yaml
from threatpulse.models.indicators import SigmaRule

logger = logging.getLogger(__name__)

SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"


def clone_or_update_sigma_repo(target_dir: Path) -> bool:
    """Performs a shallow clone (--depth 1) of the SigmaHQ repository."""
    try:
        if target_dir.exists() and (target_dir / "rules").exists():
            return True

        if target_dir.exists():
            shutil.rmtree(target_dir)

        target_dir.parent.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            ["git", "clone", "--depth", "1", SIGMA_REPO_URL, str(target_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
        return res.returncode == 0
    except Exception as exc:
        logger.error(f"Failed to shallow-clone Sigma repository: {exc}")
        return False


def classify_category(file_path: Path) -> str:
    """Maps Sigma directory path to standard SIEM categories: windows, linux, web, network, generic."""
    parts = [p.lower() for p in file_path.parts]
    if "windows" in parts:
        return "windows"
    elif "linux" in parts or "macos" in parts:
        return "linux"
    elif "web" in parts or "proxy" in parts:
        return "web"
    elif "network" in parts or "dns" in parts or "firewall" in parts:
        return "network"
    elif "cloud" in parts:
        return "cloud"
    return "generic"


def parse_sigma_directory(repo_dir: Path) -> Tuple[List[SigmaRule], Dict[str, List[SigmaRule]]]:
    """Iterates through Sigma rules directory and extracts structured SigmaRule objects."""
    rules_dir = repo_dir / "rules"
    if not rules_dir.exists():
        rules_dir = repo_dir

    all_rules: List[SigmaRule] = []
    categorized: Dict[str, List[SigmaRule]] = {
        "windows": [],
        "linux": [],
        "web": [],
        "network": [],
        "cloud": [],
        "generic": [],
    }

    if not rules_dir.exists():
        return all_rules, categorized

    for yml_file in rules_dir.rglob("*.yml"):
        try:
            with open(yml_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                data = yaml.safe_load(content)

            if not isinstance(data, dict):
                continue

            rule_id = str(data.get("id") or yml_file.stem)
            title = str(data.get("title") or yml_file.stem)
            category = classify_category(yml_file)

            rule = SigmaRule(
                id=rule_id,
                title=title,
                status=data.get("status", "test"),
                level=data.get("level", "medium"),
                description=data.get("description"),
                category=category,
                logsource=data.get("logsource") if isinstance(data.get("logsource"), dict) else {},
                tags=data.get("tags") if isinstance(data.get("tags"), list) else [],
            )

            all_rules.append(rule)
            categorized.setdefault(category, []).append(rule)
        except Exception:
            continue

    return all_rules, categorized
