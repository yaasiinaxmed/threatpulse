"""Threat Intelligence Collector: CINS Army (CI-BadGuys)."""

from __future__ import annotations
import logging
from typing import List
import httpx
from threatpulse.models.indicators import IPIndicator

logger = logging.getLogger(__name__)

CINS_ARMY_URL = "https://cinsscore.com/list/ci-badguys.txt"


async def fetch_cins_army_feed(client: httpx.AsyncClient) -> List[IPIndicator]:
    """Fetches Sentinel IPS CINS Army badguys malicious IP list."""
    indicators: List[IPIndicator] = []

    try:
        resp = await client.get(CINS_ARMY_URL, timeout=25.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                ip = line.strip()
                if not ip or ip.startswith("#"):
                    continue
                indicators.append(
                    IPIndicator(
                        ip_or_network=ip,
                        is_cidr=False,
                        source="cins_army",
                        score=4,
                        metadata={"feed_url": CINS_ARMY_URL, "provider": "cinsscore"},
                    )
                )
    except Exception as exc:
        logger.warning(f"Failed fetching CINS Army feed: {exc}")

    return indicators
