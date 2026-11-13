"""Unit tests for ThreatPulse sanitizer, CIDR deduplication, allowlisting, and edge cases."""

import ipaddress
from pathlib import Path
from threatpulse.models.indicators import IPIndicator
from threatpulse.processors.sanitizer import IndicatorSanitizer, load_allowlist


def test_load_allowlist():
    networks = load_allowlist()
    assert len(networks) > 0
    # Google DNS 8.8.8.8 should be in allowlist
    assert any(net.version == 4 and ipaddress.ip_address("8.8.8.8") in net for net in networks)
    # Cloudflare DNS 1.1.1.1 should be in allowlist
    assert any(net.version == 4 and ipaddress.ip_address("1.1.1.1") in net for net in networks)


def test_bogon_and_private_filtering():
    sanitizer = IndicatorSanitizer()
    assert sanitizer.is_bogon_or_private(ipaddress.ip_address("127.0.0.1"))
    assert sanitizer.is_bogon_or_private(ipaddress.ip_address("192.168.1.1"))
    assert sanitizer.is_bogon_or_private(ipaddress.ip_address("10.0.0.5"))
    assert sanitizer.is_bogon_or_private(ipaddress.ip_address("172.16.0.1"))
    assert not sanitizer.is_bogon_or_private(ipaddress.ip_address("45.33.32.156"))


def test_allowlist_filtering():
    sanitizer = IndicatorSanitizer()
    assert sanitizer.is_allowlisted(ipaddress.ip_address("8.8.8.8"))
    assert sanitizer.is_allowlisted(ipaddress.ip_address("1.1.1.1"))
    assert not sanitizer.is_allowlisted(ipaddress.ip_address("185.220.101.5"))


def test_cidr_collapsing_and_deduplication():
    sanitizer = IndicatorSanitizer()
    indicators = [
        # Subnet 1 (Public IP range)
        IPIndicator(ip_or_network="45.33.32.0/25", source="test1", score=3),
        IPIndicator(ip_or_network="45.33.32.128/25", source="test2", score=4),
        # An individual IP falling inside the collapsed /24
        IPIndicator(ip_or_network="45.33.32.10", source="test3", score=5),
        # Standalone public malicious IP outside that subnet
        IPIndicator(ip_or_network="185.220.101.5", source="test_feed", score=4),
        # Private IP (should be stripped)
        IPIndicator(ip_or_network="10.10.10.10", source="bad_feed", score=5),
        # Allowlisted Google DNS (should be stripped)
        IPIndicator(ip_or_network="8.8.8.8", source="false_positive", score=5),
    ]

    clean_ips, clean_cidrs = sanitizer.sanitize_indicators(indicators)

    # 45.33.32.0/25 and 45.33.32.128/25 should collapse to 45.33.32.0/24
    cidr_strings = [c.ip_or_network for c in clean_cidrs]
    assert "45.33.32.0/24" in cidr_strings

    # 45.33.32.10 should be swallowed by the collapsed CIDR
    clean_ip_strings = [i.ip_or_network for i in clean_ips]
    assert "45.33.32.10" not in clean_ip_strings
    assert "185.220.101.5" in clean_ip_strings
    assert "10.10.10.10" not in clean_ip_strings
    assert "8.8.8.8" not in clean_ip_strings


def test_ip_score_merging():
    sanitizer = IndicatorSanitizer()
    indicators = [
        IPIndicator(ip_or_network="185.220.101.88", source="feed_a", score=2),
        IPIndicator(ip_or_network="185.220.101.88", source="feed_b", score=5),
    ]

    clean_ips, _ = sanitizer.sanitize_indicators(indicators)
    assert len(clean_ips) == 1
    assert clean_ips[0].score == 5
    assert "feed_a" in clean_ips[0].source
    assert "feed_b" in clean_ips[0].source
