"""Tests for deterministic evidence correlation and its use in synthesis."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.correlator import CorrelationSummary, correlate, max_severity  # noqa: E402
from src.agent.graph import build_graph, start_triage  # noqa: E402
from src.config import InvocationResult  # noqa: E402
from src.schemas import (  # noqa: E402
    Classification,
    SecurityAlert,
    Severity,
    StepTrace,
    TriageReport,
)
from src.tools.siem import init_soc_db  # noqa: E402


def _hostile_evidence() -> list[dict[str, Any]]:
    return [
        {
            "tool": "query_siem_logs",
            "rows": [
                {
                    "log_id": "L1",
                    "source": "auth",
                    "hostname": "WS-1",
                    "source_ip": "203.0.113.10",
                    "message": "failed login from 203.0.113.10 on WS-1",
                    "mitre_technique": "T1110",
                },
                {
                    "log_id": "L2",
                    "source": "sysmon",
                    "hostname": "WS-1",
                    "source_ip": "203.0.113.10",
                    "message": "powershell executed lsass dump from 203.0.113.10",
                    "mitre_technique": "T1003.001",
                },
            ],
            "count": 2,
        },
        {
            "tool": "check_threat_intel",
            "rows": [
                {
                    "indicator": "203.0.113.10",
                    "confidence": 0.95,
                    "mitre_technique": "T1003.001",
                }
            ],
            "count": 1,
        },
        {
            "tool": "lookup_asset_inventory",
            "rows": [
                {
                    "hostname": "WS-1",
                    "criticality": "critical",
                    "ip_address": "10.0.0.5",
                }
            ],
            "count": 1,
        },
    ]


def test_correlate_match_criticity_and_anomalies() -> None:
    summary = correlate(_hostile_evidence())

    assert isinstance(summary, CorrelationSummary)
    assert summary.event_count == 2
    assert summary.intel_hit_count == 1
    assert summary.cross_source_matches == 1
    assert summary.asset_criticality == "critical"
    assert summary.auth_anomaly_count == 1
    assert summary.process_anomaly_count == 1
    assert summary.suggested_floor_severity is Severity.CRITICAL
    assert "Suggested severity floor: critical" in summary.rationale
    assert summary.matched_indicators[0].log_count == 2
    assert summary.matched_indicators[0].hosts == ("WS-1",)
    assert correlate(_hostile_evidence()) == summary


def test_benign_evidence_stays_low() -> None:
    evidence = [
        {
            "tool": "query_siem_logs",
            "rows": [
                {
                    "log_id": "L9",
                    "source": "sysmon",
                    "hostname": "WS-9",
                    "source_ip": "192.0.2.9",
                    "message": "signed installer ran its helper script",
                }
            ],
        },
        {
            "tool": "check_threat_intel",
            "rows": [{"indicator": "192.0.2.9", "confidence": 0.01}],
        },
        {
            "tool": "lookup_asset_inventory",
            "rows": [{"hostname": "WS-9", "criticality": "low"}],
        },
    ]
    summary = correlate(evidence)
    assert summary.suggested_floor_severity is Severity.LOW
    assert summary.auth_anomaly_count == 0


def test_injection_without_intel_raises_floor_to_medium() -> None:
    summary = correlate([], injection_detected=True)
    assert summary.suggested_floor_severity is Severity.MEDIUM
    assert summary.event_count == 0
    assert summary.matched_indicators == ()


def test_max_severity_returns_higher_value() -> None:
    assert max_severity(Severity.LOW, Severity.HIGH) is Severity.HIGH
    assert max_severity(Severity.CRITICAL, Severity.MEDIUM) is Severity.CRITICAL


def test_synthesis_uses_floor_and_passes_correlation_to_llm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, str] = {}

    def fake_llm(*args: Any, **kwargs: Any) -> InvocationResult[TriageReport]:
        captured["system"] = kwargs["system_prompt"]
        captured["user"] = kwargs["user_prompt"]
        report = TriageReport(
            alert_id="stub",
            classification=Classification.MALICIOUS,
            severity=Severity.LOW,
            confidence=0.95,
            summary="stub",
            evidence_summary="",
        )
        trace = StepTrace(step=kwargs.get("step", 0), name="synthesize_llm", success=True)
        return InvocationResult(data=report, trace=trace)

    monkeypatch.setattr("src.agent.graph.invoke_structured", fake_llm)

    db = init_soc_db(tmp_path / "soc.duckdb")
    audit = tmp_path / "audit.db"
    graph = build_graph(db_path=str(db), audit_db_path=str(audit), enrich_with_llm=True)
    alert = SecurityAlert(
        alert_id="ALT-1001",
        severity=Severity.LOW,
        title="C2 beacon",
        raw_payload="powershell from 203.0.113.42 to WS-FIN-014",
        source_ip="203.0.113.42",
        hostname="WS-FIN-014",
    )

    paused = start_triage(graph, alert, "correlation-1")

    assert paused["report"].severity is Severity.CRITICAL
    assert "correlation" in captured["user"]
    assert "Suggested severity floor" in captured["user"]
    assert "Suggested severity floor" in paused["report"].evidence_summary
    assert "suggested floor" in captured["system"]
