"""Sanitizer and Deduplicator for Threat Intelligence Indicators."""

from __future__ import annotations
import ipaddress
from pathlib import Path
from typing import Iterable, List, Set, Tuple, Union
from threatpulse.models.indicators import IPIndicator


def load_allowlist(allowlist_path: Union[str, Path, None] = None) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Loads and parses safe CIDR blocks from an allowlist file."""
    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []

    if allowlist_path is None:
        # Default fallback to repository allowlist.txt
        candidate = Path(__file__).resolve().parents[3] / "allowlist.txt"
        if candidate.exists():
            allowlist_path = candidate
        else:
            allowlist_path = Path("allowlist.txt")

    p = Path(allowlist_path)
    if not p.is_file():
        return networks

    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(clean, strict=False)
                networks.append(net)
            except ValueError:
                continue

    return list(ipaddress.collapse_addresses(networks))


class IndicatorSanitizer:
    """Validates, deduplicates, and sanitizes IP addresses and CIDR networks."""

    def __init__(self, allowlist_path: Union[str, Path, None] = None):
        self.allowed_networks = load_allowlist(allowlist_path)

    def is_bogon_or_private(self, net_or_ip: Union[ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """Checks if an address or network is private, loopback, link-local, multicast, or reserved."""
        return bool(
            net_or_ip.is_private
            or net_or_ip.is_loopback
            or net_or_ip.is_link_local
            or net_or_ip.is_multicast
            or net_or_ip.is_reserved
            or net_or_ip.is_unspecified
        )

    def is_allowlisted(self, net_or_ip: Union[ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """Determines if the given IP/network falls within any allowlisted safe range."""
        if isinstance(net_or_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            target_net = ipaddress.ip_network(f"{net_or_ip}/32" if net_or_ip.version == 4 else f"{net_or_ip}/128")
        else:
            target_net = net_or_ip

        for allowed in self.allowed_networks:
            if target_net.subnet_of(allowed):
                return True
        return False

    def sanitize_indicators(
        self, indicators: Iterable[IPIndicator]
    ) -> Tuple[List[IPIndicator], List[IPIndicator]]:
        """Processes indicators, collapses CIDRs, deduplicates, and splits into clean single IPs vs CIDR blocks."""
        single_ip_map: dict[str, IPIndicator] = {}
        cidr_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        cidr_meta: dict[str, IPIndicator] = {}

        for ind in indicators:
            val = ind.ip_or_network.strip()
            if not val:
                continue

            # Detect CIDR vs single IP
            if "/" in val:
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if self.is_bogon_or_private(net) or self.is_allowlisted(net):
                        continue
                    cidr_networks.append(net)
                    cidr_meta[str(net)] = ind
                except ValueError:
                    continue
            else:
                try:
                    ip = ipaddress.ip_address(val)
                    if self.is_bogon_or_private(ip) or self.is_allowlisted(ip):
                        continue
                    ip_str = str(ip)
                    # Aggregate highest score if duplicate across feeds
                    if ip_str in single_ip_map:
                        existing = single_ip_map[ip_str]
                        existing.score = max(existing.score, ind.score)
                        existing.source = f"{existing.source},{ind.source}"
                    else:
                        single_ip_map[ip_str] = ind
                except ValueError:
                    continue

        # Collapse overlapping CIDRs
        collapsed_cidrs = list(ipaddress.collapse_addresses(cidr_networks))
        clean_cidrs: List[IPIndicator] = []
        for net in collapsed_cidrs:
            net_str = str(net)
            meta = cidr_meta.get(net_str, IPIndicator(ip_or_network=net_str, is_cidr=True, source="collapsed", score=5))
            meta.ip_or_network = net_str
            meta.is_cidr = True
            clean_cidrs.append(meta)

        # Filter out individual IPs that fall under collapsed CIDR drops
        filtered_single_ips: List[IPIndicator] = []
        for ip_str, ind in single_ip_map.items():
            ip_obj = ipaddress.ip_address(ip_str)
            covered_by_cidr = any(ip_obj in net for net in collapsed_cidrs)
            if not covered_by_cidr:
                filtered_single_ips.append(ind)

        # Sort for deterministic output
        filtered_single_ips.sort(key=lambda x: (x.score, x.ip_or_network), reverse=True)
        clean_cidrs.sort(key=lambda x: str(x.ip_or_network))

        return filtered_single_ips, clean_cidrs
