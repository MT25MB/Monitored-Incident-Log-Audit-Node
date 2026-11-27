"""Deterministic correlation of evidence collected by the read-only tools.

The correlator reads the same ``tool_results`` the graph already holds. It does
not call a model or change any data. Its summary gives ``synthesize`` a factual
baseline to work from: which indicators appear in both intel and logs, how
critical the affected assets are, how many auth and process anomalies showed
up, and a suggested severity floor.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from pydantic import BaseModel, Field

from src.schemas import Severity
from src.tools.ioc_parser import extract_iocs_from_rows

__all__ = [
    "IndicatorMatch",
    "CorrelationSummary",
    "correlate",
    "max_severity",
]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_AUTH_MARKERS = ("failed login", "authentication failure", "brute", "kerberos", "logon failure")
_PROCESS_MARKERS = ("powershell", "lsass", "process", "schtasks", "wmic", "cmdline")


class IndicatorMatch(BaseModel):
    """One intel indicator and where it appeared in the logs."""

    indicator: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    log_count: int = Field(default=0, ge=0)
    hosts: tuple[str, ...] = ()


class CorrelationSummary(BaseModel):
    """Facts derived from tool output, with a suggested severity floor."""

    event_count: int = Field(default=0, ge=0)
    intel_hit_count: int = Field(default=0, ge=0)
    matched_indicators: tuple[IndicatorMatch, ...] = ()
    cross_source_matches: int = Field(default=0, ge=0)
    asset_criticality: str = "unknown"
    auth_anomaly_count: int = Field(default=0, ge=0)
    process_anomaly_count: int = Field(default=0, ge=0)
    suggested_floor_severity: Severity = Severity.LOW
    rationale: str = ""


def max_severity(left: Severity, right: Severity) -> Severity:
    """Return the more severe of two values."""
    return left if _SEVERITY_RANK[left] >= _SEVERITY_RANK[right] else right


def _rows(tool_results: Sequence[Mapping[str, Any]], tool_name: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for item in tool_results
        if item.get("tool") == tool_name
        for row in item.get("rows", [])
    ]


def _log_indicators(row: Mapping[str, Any]) -> set[str]:
    """Collect IP, domain, and hash indicators from one log row."""
    return set(extract_iocs_from_rows([row]).all_indicators)


def _count_anomalies(logs: Iterable[Mapping[str, Any]]) -> tuple[int, int]:
    auth_count = 0
    process_count = 0
    for row in logs:
        message = str(row.get("message") or "").lower()
        if any(marker in message for marker in _AUTH_MARKERS):
            auth_count += 1
        if any(marker in message for marker in _PROCESS_MARKERS):
            process_count += 1
    return auth_count, process_count


def _highest_criticality(assets: Iterable[Mapping[str, Any]]) -> str:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    best = "unknown"
    for row in assets:
        value = str(row.get("criticality") or "").lower()
        if value in rank and (best not in rank or rank[value] > rank[best]):
            best = value
    return best


def _suggest_floor(
    *,
    max_confidence: float,
    cross_source_matches: int,
    criticality: str,
    auth_anomalies: int,
    process_anomalies: int,
    injection_detected: bool,
) -> Severity:
    if max_confidence >= 0.9 or (max_confidence >= 0.8 and criticality in {"high", "critical"}):
        return Severity.CRITICAL
    if (
        max_confidence >= 0.8
        or cross_source_matches >= 2
        or process_anomalies >= 2
        or auth_anomalies >= 3
        or criticality == "critical"
    ):
        return Severity.HIGH
    if (
        max_confidence >= 0.3
        or criticality == "high"
        or cross_source_matches >= 2
        or injection_detected
    ):
        return Severity.MEDIUM
    return Severity.LOW


def correlate(
    tool_results: Sequence[Mapping[str, Any]],
    *,
    injection_detected: bool = False,
) -> CorrelationSummary:
    """Build a deterministic correlation summary from collected evidence."""
    logs = _rows(tool_results, "query_siem_logs")
    intel = _rows(tool_results, "check_threat_intel")
    assets = _rows(tool_results, "lookup_asset_inventory")

    log_indicators: dict[str, set[str]] = {}
    for row in logs:
        host = str(row.get("hostname") or "")
        for indicator in _log_indicators(row):
            log_indicators.setdefault(indicator, set())
            if host:
                log_indicators[indicator].add(host)

    matches: list[IndicatorMatch] = []
    for row in intel:
        indicator = str(row.get("indicator") or "")
        if not indicator:
            continue
        hosts = log_indicators.get(indicator, set())
        matches.append(
            IndicatorMatch(
                indicator=indicator,
                confidence=float(row.get("confidence") or 0.0),
                log_count=sum(1 for log in logs if indicator in _log_indicators(log)),
                hosts=tuple(sorted(hosts)),
            )
        )
    matches.sort(key=lambda item: (-item.confidence, item.indicator))

    auth_anomalies, process_anomalies = _count_anomalies(logs)
    criticality = _highest_criticality(assets)
    max_confidence = max((item.confidence for item in matches), default=0.0)
    cross_source_matches = sum(1 for item in matches if item.log_count > 0)
    floor = _suggest_floor(
        max_confidence=max_confidence,
        cross_source_matches=cross_source_matches,
        criticality=criticality,
        auth_anomalies=auth_anomalies,
        process_anomalies=process_anomalies,
        injection_detected=injection_detected,
    )

    rationale = (
        f"Threat intel returned {len(matches)} indicator(s); "
        f"{cross_source_matches} also appeared in local logs. "
        f"Highest asset criticality: {criticality}. "
        f"Auth anomalies: {auth_anomalies}; process anomalies: {process_anomalies}. "
        f"Suggested severity floor: {floor.value}."
    )
    return CorrelationSummary(
        event_count=len(logs),
        intel_hit_count=len(intel),
        matched_indicators=tuple(matches),
        cross_source_matches=cross_source_matches,
        asset_criticality=criticality,
        auth_anomaly_count=auth_anomalies,
        process_anomaly_count=process_anomalies,
        suggested_floor_severity=floor,
        rationale=rationale,
    )
