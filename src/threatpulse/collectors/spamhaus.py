"""Threat Intelligence Collector: Spamhaus DROP (v4, v6 & fallback)."""

from __future__ import annotations
import logging
from typing import List
import httpx
from threatpulse.models.indicators import IPIndicator

logger = logging.getLogger(__name__)

SPAMHAUS_V4_JSON = "https://www.spamhaus.org/drop/drop_v4.json"
SPAMHAUS_V6_JSON = "https://www.spamhaus.org/drop/drop_v6.json"
SPAMHAUS_FALLBACK_TXT = "https://www.spamhaus.org/drop/drop.txt"


async def fetch_spamhaus_feed(client: httpx.AsyncClient) -> List[IPIndicator]:
    """Fetches Spamhaus Don't Route Or Peer (DROP) lists with JSON metadata and text fallback."""
    indicators: List[IPIndicator] = []

    # Attempt v4 JSON
    try:
        r4 = await client.get(SPAMHAUS_V4_JSON, timeout=20.0)
        if r4.status_code == 200:
            data = r4.json()
            for entry in data:
                cidr = entry.get("cidr")
                sbl = entry.get("sbl", "")
                if cidr:
                    indicators.append(
                        IPIndicator(
                            ip_or_network=cidr,
                            is_cidr=True,
                            source="spamhaus_drop_v4",
                            score=5,
                            metadata={"sbl": sbl, "version": "v4"},
                        )
                    )
    except Exception as exc:
        logger.warning(f"Failed fetching Spamhaus v4 JSON: {exc}")

    # Attempt v6 JSON
    try:
        r6 = await client.get(SPAMHAUS_V6_JSON, timeout=20.0)
        if r6.status_code == 200:
            data = r6.json()
            for entry in data:
                cidr = entry.get("cidr")
                sbl = entry.get("sbl", "")
                if cidr:
                    indicators.append(
                        IPIndicator(
                            ip_or_network=cidr,
                            is_cidr=True,
                            source="spamhaus_drop_v6",
                            score=5,
                            metadata={"sbl": sbl, "version": "v6"},
                        )
                    )
    except Exception as exc:
        logger.warning(f"Failed fetching Spamhaus v6 JSON: {exc}")

    # If JSON endpoints were throttled or unavailable, try fallback text
    if not indicators:
        try:
            r_txt = await client.get(SPAMHAUS_FALLBACK_TXT, timeout=20.0)
            if r_txt.status_code == 200:
                for line in r_txt.text.splitlines():
                    clean = line.strip()
                    if not clean or clean.startswith(";"):
                        continue
                    parts = clean.split(";")
                    cidr = parts[0].strip()
                    sbl = parts[1].strip() if len(parts) > 1 else ""
                    if cidr:
                        indicators.append(
                            IPIndicator(
                                ip_or_network=cidr,
                                is_cidr=True,
                                source="spamhaus_drop_txt",
                                score=5,
                                metadata={"sbl": sbl},
                            )
                        )
        except Exception as exc:
            logger.warning(f"Failed fetching Spamhaus text fallback: {exc}")

    return indicators
