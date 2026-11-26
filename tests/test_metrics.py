"""Tests for aggregate metrics computed from the SQLite audit store."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.graph import MAX_INVESTIGATION_STEPS  # noqa: E402
from src.cli import main  # noqa: E402
from src.monitoring.metrics import STEP_CAP, compute_metrics, metrics_to_dict  # noqa: E402
from src.monitoring.store import (  # noqa: E402
    RunRecord,
    init_audit_db,
    record_hitl_decisions,
    record_run,
)
from src.schemas import StepTrace  # noqa: E402


class _Action:
    def __init__(self, action: str, target: str) -> None:
        self.action = action
        self.target = target


def _trace(step: int, *, tool: bool, provider: str, fallback: bool = False) -> dict:
    return StepTrace(
        step=step,
        name="execute_tool" if tool else "synthesize_llm",
        provider=provider,
        model="stub",
        latency_ms=10.0,
        tool_name="query_siem_logs" if tool else None,
        fallback_triggered=fallback,
        fallback_from="gemini" if fallback else None,
        success=True,
    ).model_dump(mode="json")


@pytest.fixture()
def audit_db(tmp_path: Path) -> Path:
    db = init_audit_db(tmp_path / "audit.db")
    traces_one = [_trace(index, tool=True, provider="local") for index in range(4)]
    traces_one.append(_trace(4, tool=False, provider="fake", fallback=True))
    traces_two = [_trace(0, tool=False, provider="gemini", fallback=True)]

    record_run(
        RunRecord(
            run_id="run-1",
            alert_id="ALT-1",
            verdict="malicious",
            severity="high",
            injection_detected=True,
            total_latency_ms=100.0,
            step_count=4,
            provider_used="fake",
            fallback_count=1,
            traces_json=json.dumps(traces_one),
            status="completed",
            hitl_decision="approved",
        ),
        db_path=db,
    )
    record_run(
        RunRecord(
            run_id="run-2",
            alert_id="ALT-2",
            verdict="benign",
            severity="low",
            total_latency_ms=300.0,
            step_count=7,
            provider_used="gemini",
            fallback_count=1,
            traces_json=json.dumps(traces_two),
            status="completed",
            hitl_decision="rejected",
        ),
        db_path=db,
    )
    record_run(
        RunRecord(
            run_id="run-3",
            alert_id="ALT-3",
            verdict="suspicious",
            total_latency_ms=50.0,
            step_count=2,
            traces_json="[]",
            status="paused",
        ),
        db_path=db,
    )
    for run_id, alert_id, decision in (
        ("run-1", "ALT-1", "approved"),
        ("run-2", "ALT-2", "rejected"),
    ):
        record_hitl_decisions(
            run_id=run_id,
            alert_id=alert_id,
            actions=[_Action("isolate_host", "WS-1")],
            decision=decision,
            reviewer="analyst",
            db_path=db,
        )
    return db


def test_step_cap_constant_matches_graph() -> None:
    assert STEP_CAP == MAX_INVESTIGATION_STEPS


def test_empty_store_returns_zeroed_metrics(tmp_path: Path) -> None:
    db = init_audit_db(tmp_path / "empty.db")
    summary = compute_metrics(db_path=db)
    assert summary.total_runs == 0
    assert summary.mttt_ms == 0.0
    assert summary.p50_latency_ms == 0.0
    assert summary.p95_latency_ms == 0.0
    assert summary.fallback_rate == 0.0
    assert summary.estimated_cost_usd == 0.0
    assert summary.provider_usage == {}


def test_metrics_from_stored_runs(audit_db: Path) -> None:
    metrics = compute_metrics(db_path=audit_db)

    assert metrics.total_runs == 3
    assert metrics.completed_runs == 2
    assert metrics.paused_runs == 1
    assert metrics.mttt_ms == 200.0
    assert metrics.p50_latency_ms == 100.0
    assert metrics.p95_latency_ms == 300.0
    assert metrics.tool_calls_total == 4
    assert metrics.avg_steps_per_alert == 4.33
    assert metrics.step_cap_compliant == 2
    assert metrics.step_cap_violations == 1
    assert metrics.provider_usage == {"fake": 1, "gemini": 1, "local": 4}
    assert metrics.fallback_events == 2
    assert metrics.fallback_rate == 0.3333
    assert metrics.estimated_cost_usd == 0.0
    assert metrics.injection_flagged_runs == 1
    assert metrics.injection_flag_rate == 0.3333
    assert metrics.hitl_approved == 1
    assert metrics.hitl_rejected == 1


def test_metrics_to_dict_is_json_ready(audit_db: Path) -> None:
    payload = metrics_to_dict(compute_metrics(db_path=audit_db))
    assert json.loads(json.dumps(payload))["provider_usage"]["local"] == 4


def test_cli_metrics_command(audit_db: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "metrics.json"
    exit_code = main(["metrics", "--audit-db", str(audit_db), "--output-json", str(out)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "MILAN monitoring summary" in output
    assert "MTTT: 200.0 ms" in output
    assert "Cap <=6: 2 ok, 1 violations" in output
    assert "Cost: $0.00" in output
    assert json.loads(out.read_text(encoding="utf-8"))["hitl_rejected"] == 1
