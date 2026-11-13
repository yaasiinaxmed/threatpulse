"""ThreatPulse CLI: Typer + Rich interface for Threat Intelligence Pipeline."""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from typing import Optional
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
import typer
from threatpulse.collectors.blocklist_de import fetch_blocklist_de_feed
from threatpulse.collectors.crowdsec import fetch_crowdsec_feed
from threatpulse.collectors.ipsum import fetch_ipsum_feed
from threatpulse.collectors.sigma import clone_or_update_sigma_repo, parse_sigma_directory
from threatpulse.collectors.spamhaus import fetch_spamhaus_feed
from threatpulse.processors.exporters import export_indicators, export_sigma_rules
from threatpulse.processors.sanitizer import IndicatorSanitizer

app = typer.Typer(
    name="threatpulse",
    help="⚡ ThreatPulse: Automated Threat Intelligence & SIEM Detection Rule Aggregator",
    add_completion=False,
)
console = Console()


async def _run_pipeline(min_score: int, dist_dir: Path, skip_sigma: bool) -> dict:
    """Async coordinator for feed collectors and processors."""
    raw_indicators = []
    feed_counts = {}

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        # Collect IP feeds concurrently
        ipsum_task = fetch_ipsum_feed(client, min_score=min_score)
        spamhaus_task = fetch_spamhaus_feed(client)
        blocklist_task = fetch_blocklist_de_feed(client)
        crowdsec_task = fetch_crowdsec_feed(client)

        results = await asyncio.gather(
            ipsum_task, spamhaus_task, blocklist_task, crowdsec_task, return_exceptions=True
        )

        feed_names = ["ipsum", "spamhaus", "blocklist_de", "crowdsec"]
        for name, res in zip(feed_names, results):
            if isinstance(res, list):
                raw_indicators.extend(res)
                feed_counts[name] = len(res)
            else:
                feed_counts[name] = 0

    # Sanitize and deduplicate
    sanitizer = IndicatorSanitizer()
    clean_ips, clean_cidrs = sanitizer.sanitize_indicators(raw_indicators)

    # Export IP feeds
    export_indicators(clean_ips, clean_cidrs, dist_dir=dist_dir)

    # Sigma processing
    sigma_total = 0
    sigma_categorized_counts = {}
    if not skip_sigma:
        sigma_cache = Path(".sigma_cache")
        cloned = clone_or_update_sigma_repo(sigma_cache)
        if cloned:
            all_rules, categorized = parse_sigma_directory(sigma_cache)
            export_sigma_rules(all_rules, categorized, dist_dir=dist_dir)
            sigma_total = len(all_rules)
            sigma_categorized_counts = {k: len(v) for k, v in categorized.items()}

    return {
        "raw_total": len(raw_indicators),
        "clean_ips": len(clean_ips),
        "high_confidence": len([i for i in clean_ips if i.score >= 4]),
        "cidr_drops": len(clean_cidrs),
        "feed_counts": feed_counts,
        "sigma_total": sigma_total,
        "sigma_categories": sigma_categorized_counts,
    }


@app.command()
def update(
    min_score: int = typer.Option(3, "--min-score", "-s", help="Minimum threat score for ipsum feed"),
    dist: str = typer.Option("dist", "--dist", "-d", help="Output distribution directory"),
    skip_sigma: bool = typer.Option(False, "--skip-sigma", help="Skip fetching and parsing Sigma rules"),
):
    """Fetch all intelligence feeds, sanitize, deduplicate, and compile exports into dist/."""
    dist_path = Path(dist)
    dist_path.mkdir(parents=True, exist_ok=True)

    console.print(
        Panel.fit(
            "[bold cyan]⚡ ThreatPulse Intelligence Pipeline[/bold cyan]\n"
            "[dim]Aggregating global malicious IPs, CIDRs, and SIEM Sigma rules[/dim]",
            border_style="cyan",
        )
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Collecting & processing threat telemetry...", total=None)
        summary = asyncio.run(_run_pipeline(min_score=min_score, dist_dir=dist_path, skip_sigma=skip_sigma))

    table = Table(title="Aggregated Threat Telemetry Summary", style="cyan")
    table.add_column("Metric / Feed", style="bold")
    table.add_column("Count", justify="right", style="green")

    table.add_row("Total Raw Indicators Ingested", str(summary["raw_total"]))
    for feed, count in summary["feed_counts"].items():
        table.add_row(f"  • Feed: {feed}", str(count))

    table.add_row("Unique Cleaned IPs", str(summary["clean_ips"]))
    table.add_row("High-Confidence IPs (Score >= 4)", str(summary["high_confidence"]))
    table.add_row("Collapsed CIDR DROP Networks", str(summary["cidr_drops"]))

    if not skip_sigma:
        table.add_row("Total Sigma SIEM Rules", str(summary["sigma_total"]))
        for cat, count in summary["sigma_categories"].items():
            table.add_row(f"  • Sigma ({cat})", str(count))

    console.print(table)
    console.print(f"[bold green]✔ Exports successfully written to `{dist_path}/`[/bold green]\n")


@app.command()
def check_ip(
    ip: str = typer.Argument(..., help="IP address to evaluate against blocklists and allowlist"),
    dist: str = typer.Option("dist", "--dist", "-d", help="Path to dist directory"),
):
    """Check if a specific IP is flagged in generated blocklists or safe-listed."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        console.print(f"[bold red]Error:[/bold red] '{ip}' is not a valid IPv4 or IPv6 address.")
        raise typer.Exit(code=1)

    sanitizer = IndicatorSanitizer()

    if sanitizer.is_bogon_or_private(ip_obj):
        console.print(f"[yellow]IP {ip} is RFC1918 / Private / Bogon (Safe)[/yellow]")
        return

    if sanitizer.is_allowlisted(ip_obj):
        console.print(f"[bold green]✔ IP {ip} is explicitly ALLOWLISTED (Safe/Infrastructure)[/bold green]")
        return

    # Check against generated local feeds if present
    all_ips_file = Path(dist) / "ips" / "all_malicious_ips.txt"
    high_conf_file = Path(dist) / "ips" / "high_confidence_ips.txt"
    cidr_file = Path(dist) / "ips" / "cidr_drop.txt"

    matches = []
    if all_ips_file.is_file():
        with open(all_ips_file, "r") as f:
            if ip in (line.strip() for line in f if not line.startswith("#")):
                matches.append("Standard Malicious Blocklist")

    if high_conf_file.is_file():
        with open(high_conf_file, "r") as f:
            if ip in (line.strip() for line in f if not line.startswith("#")):
                matches.append("High Confidence Blocklist (Score >= 4)")

    if cidr_file.is_file():
        with open(cidr_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        if ip_obj in net:
                            matches.append(f"DROP CIDR Match: {line}")
                            break
                    except ValueError:
                        continue

    if matches:
        console.print(f"[bold red]🚨 IP {ip} is MALICIOUS / BLOCKED![/bold red]")
        for m in matches:
            console.print(f"  • {m}")
    else:
        console.print(f"[green]IP {ip} is not present in local threat intelligence lists.[/green]")


@app.command()
def stats(
    dist: str = typer.Option("dist", "--dist", "-d", help="Path to dist directory"),
):
    """Display quick stats on current local compiled distribution feeds."""
    dist_path = Path(dist)
    if not dist_path.exists():
        console.print(f"[yellow]No distribution artifacts found in `{dist_path}/`. Run `threatpulse update` first.[/yellow]")
        return

    table = Table(title="ThreatPulse Local Feeds Status", style="blue")
    table.add_column("Feed Artifact", style="bold")
    table.add_column("File Size", justify="right")
    table.add_column("Entries Count", justify="right", style="green")

    for file_path in sorted(dist_path.rglob("*")):
        if file_path.is_file():
            size_kb = f"{file_path.stat().st_size / 1024:.1f} KB"
            if file_path.suffix == ".txt":
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    count = sum(1 for line in f if line.strip() and not line.startswith("#"))
                table.add_row(str(file_path.relative_to(dist_path)), size_kb, str(count))
            elif file_path.suffix == ".json":
                table.add_row(str(file_path.relative_to(dist_path)), size_kb, "JSON Bundle")

    console.print(table)


if __name__ == "__main__":
    app()
