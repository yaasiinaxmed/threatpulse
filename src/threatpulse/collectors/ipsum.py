"""Threat Intelligence Collector: stamparm/ipsum & sekuripy."""

from __future__ import annotations
import logging
from typing import List
import httpx
from threatpulse.models.indicators import IPIndicator

logger = logging.getLogger(__name__)

IPSUM_URLS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://www.sekuripy.hr/labs/ipsum/",
]


async def fetch_ipsum_feed(client: httpx.AsyncClient, min_score: int = 3) -> List[IPIndicator]:
    """Fetches and parses ipsum feed lines into IPIndicators filtering by min_score."""
    indicators: List[IPIndicator] = []

    for url in IPSUM_URLS:
        try:
            resp = await client.get(url, timeout=25.0)
            if resp.status_code != 200:
                continue

            lines = resp.text.splitlines()
            for line in lines:
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue

                parts = clean.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    try:
                        score = int(parts[1].strip())
                    except ValueError:
                        score = 1

                    if score >= min_score:
                        indicators.append(
                            IPIndicator(
                                ip_or_network=ip,
                                is_cidr=False,
                                source="ipsum",
                                score=score,
                                metadata={"ipsum_score": score, "feed_url": url},
                            )
                        )
            if indicators:
                # Successfully retrieved from one mirror
                break
        except Exception as exc:
            logger.warning(f"Failed to fetch ipsum from {url}: {exc}")
            continue

    return indicators
