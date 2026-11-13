"""Threat Intelligence Collector: CrowdSec CAPI & Community Netsets."""

from __future__ import annotations
import logging
import os
from typing import List
import httpx
from threatpulse.models.indicators import IPIndicator

logger = logging.getLogger(__name__)

CROWDSEC_CAPI_URL = "https://api.crowdsec.net/v2/decisions/stream"
CROWDSEC_COMMUNITY_FALLBACK = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/crowdsec_community.netset"


async def fetch_crowdsec_feed(client: httpx.AsyncClient) -> List[IPIndicator]:
    """Fetches CrowdSec decisions stream if CROWDSEC_API_KEY is present, else falls back to community netset."""
    indicators: List[IPIndicator] = []
    api_key = os.environ.get("CROWDSEC_API_KEY")

    if api_key:
        headers = {"X-Api-Key": api_key, "User-Agent": "threatpulse/0.1.0"}
        try:
            resp = await client.get(CROWDSEC_CAPI_URL, headers=headers, timeout=20.0)
            if resp.status_code == 200:
                data = resp.json()
                new_decisions = data.get("new", [])
                for item in new_decisions:
                    val = item.get("value")
                    scenario = item.get("scenario", "crowdsec_decision")
                    scope = item.get("scope", "Ip")
                    if val:
                        is_cidr = "/" in val or scope.lower() == "range"
                        indicators.append(
                            IPIndicator(
                                ip_or_network=val,
                                is_cidr=is_cidr,
                                source="crowdsec_capi",
                                score=4,
                                metadata={"scenario": scenario},
                            )
                        )
                if indicators:
                    return indicators
        except Exception as exc:
            logger.warning(f"Failed fetching CrowdSec CAPI: {exc}")

    # Fallback to CrowdSec community public netset
    try:
        resp = await client.get(CROWDSEC_COMMUNITY_FALLBACK, timeout=25.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                is_cidr = "/" in clean
                indicators.append(
                    IPIndicator(
                        ip_or_network=clean,
                        is_cidr=is_cidr,
                        source="crowdsec_community",
                        score=3,
                        metadata={"feed": "firehol_crowdsec"},
                    )
                )
    except Exception as exc:
        logger.warning(f"Failed fetching CrowdSec community fallback: {exc}")

    return indicators
