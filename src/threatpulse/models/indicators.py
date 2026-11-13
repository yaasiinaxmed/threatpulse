"""Core Pydantic models for threat intelligence and Sigma rules."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IPIndicator(BaseModel):
    """Normalized Malicious IP Indicator model."""
    ip_or_network: str = Field(description="Single IPv4/IPv6 or CIDR notation")
    is_cidr: bool = False
    source: str = Field(description="Origin threat feed identifier")
    score: int = Field(default=1, description="Threat reputation score or severity weight")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SigmaRule(BaseModel):
    """Normalized Sigma SIEM Detection Rule model."""
    id: str
    title: str
    status: Optional[str] = "test"
    level: Optional[str] = "medium"
    description: Optional[str] = None
    category: str = Field(default="generic", description="Target category: linux, windows, web, network")
    logsource: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list, description="MITRE ATT&CK or Sigma taxonomy tags")
    raw_yaml: Optional[str] = None


class AggregatedFeedResult(BaseModel):
    """Container for complete pipeline aggregation result."""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_raw_ips: int = 0
    unique_clean_ips: int = 0
    high_confidence_ips: int = 0
    cidr_drops: int = 0
    sigma_rules_total: int = 0
    sigma_by_category: Dict[str, int] = Field(default_factory=dict)
    feed_breakdown: Dict[str, int] = Field(default_factory=dict)
