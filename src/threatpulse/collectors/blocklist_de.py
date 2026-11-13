"""Threat Intelligence Collector: Blocklist.de."""

from __future__ import annotations
import logging
from typing import List
import httpx
from threatpulse.models.indicators import IPIndicator

logger = logging.getLogger(__name__)

BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/all.txt"


async def fetch_blocklist_de_feed(client: httpx.AsyncClient) -> List[IPIndicator]:
    """Fetches all reported malicious attack IPs from blocklist.de."""
    indicators: List[IPIndicator] = []

    try:
        resp = await client.get(BLOCKLIST_DE_URL, timeout=25.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                ip = line.strip()
                if not ip or ip.startswith("#"):
                    continue
                indicators.append(
                    IPIndicator(
                        ip_or_network=ip,
                        is_cidr=False,
                        source="blocklist_de",
                        score=3,
                        metadata={"type": "bruteforce_attack"},
                    )
                )
    except Exception as exc:
        logger.warning(f"Failed fetching Blocklist.de feed: {exc}")

    return indicators
