"""Tests for deterministic IOC extraction and normalization."""

from __future__ import annotations

import sys

_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.correlator import correlate  # noqa: E402
from src.agent.graph import TriageState, _next_action  # noqa: E402
from src.schemas import SecurityAlert, Severity  # noqa: E402
from src.tools.ioc_parser import (  # noqa: E402
    extract_iocs,
    extract_iocs_from_rows,
    primary_indicator,
)

_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_SHA = "b1a2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f708192a3b4c5d6e7f80"


def test_extracts_ipv4_domains_hashes_and_processes() -> None:
    iocs = extract_iocs(
        f"powershell.exe from 203.0.113.42 to EVIL-C2.Example.Net. "
        f"sha256 {_SHA} md5 {_MD5}; sshd accepted a key"
    )
    assert iocs.ip_addresses == ("203.0.113.42",)
    assert iocs.domains == ("evil-c2.example.net",)
    assert iocs.sha256_hashes == (_SHA,)
    assert iocs.md5_hashes == (_MD5,)
    assert "powershell.exe" in iocs.process_names
    assert "sshd" in iocs.process_names
    assert iocs.hashes == (_SHA, _MD5)


def test_invalid_ipv4_is_dropped_and_order_is_stable() -> None:
    iocs = extract_iocs("from 999.1.1.1 then 198.51.100.7 and 198.51.100.7")
    assert iocs.ip_addresses == ("198.51.100.7",)


def test_secret_like_values_are_not_returned_as_iocs() -> None:
    iocs = extract_iocs(
        f"api_key={_SHA} Bearer abcdefgh12345678 password=hunter2 from 203.0.113.42"
    )
    assert _SHA not in iocs.sha256_hashes
    assert iocs.ip_addresses == ("203.0.113.42",)


def test_rows_aggregate_without_duplicates() -> None:
    rows = [
        {"message": "powershell.exe queried evil.example.net", "source_ip": "203.0.113.10"},
        {"message": "curl to EVIL.example.net from 203.0.113.10", "dest_ip": "203.0.113.11"},
    ]
    iocs = extract_iocs_from_rows(rows)
    assert iocs.domains == ("evil.example.net",)
    assert iocs.ip_addresses == ("203.0.113.10", "203.0.113.11")
    assert set(iocs.process_names) == {"powershell.exe", "curl"}


def test_primary_indicator_prefers_hashes_then_domains_then_ips() -> None:
    assert primary_indicator(extract_iocs("203.0.113.42 evil.example.net")) == "evil.example.net"
    assert primary_indicator(extract_iocs(f"{_SHA} evil.example.net")) == _SHA
    assert primary_indicator(extract_iocs("203.0.113.42")) == "203.0.113.42"
    assert primary_indicator(extract_iocs("powershell.exe")) is None


def test_planner_uses_parsed_indicator() -> None:
    alert = SecurityAlert(
        alert_id="ALT-1",
        severity=Severity.HIGH,
        title="DNS tunnel",
        raw_payload="query to tunnel-c2.example.net",
        hostname="WS-1",
    )
    state = TriageState(
        alert=alert,
        step=1,
        sanitized_payload="<untrusted>query to tunnel-c2.example.net</untrusted>",
    )
    action = _next_action(state)
    assert action is not None
    assert action["tool"] == "check_threat_intel"
    assert action["args"]["indicator"] == "tunnel-c2.example.net"


def test_correlator_matches_domain_from_parser() -> None:
    tool_results = [
        {
            "tool": "query_siem_logs",
            "rows": [
                {
                    "log_id": "L1",
                    "source": "dns",
                    "hostname": "WS-1",
                    "message": "query for evil-c2.example.net from 203.0.113.42",
                }
            ],
        },
        {
            "tool": "check_threat_intel",
            "rows": [
                {
                    "indicator": "evil-c2.example.net",
                    "confidence": 0.9,
                    "mitre_technique": "T1071.004",
                }
            ],
        },
    ]
    summary = correlate(tool_results)
    assert summary.cross_source_matches == 1
    assert summary.matched_indicators[0].indicator == "evil-c2.example.net"
    assert summary.matched_indicators[0].log_count == 1
