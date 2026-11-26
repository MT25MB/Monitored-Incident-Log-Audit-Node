"""Offline tests for SQLite run telemetry and the append-only HITL audit log."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.graph import build_graph, resume_triage, start_triage  # noqa: E402
from src.monitoring.store import (  # noqa: E402
    RunRecord,
    get_hitl_audit,
    get_recent_runs,
    get_run_metrics,
    init_audit_db,
    record_hitl_decisions,
    record_run,
    traces_from_json,
)
from src.schemas import SecurityAlert, Severity  # noqa: E402
from src.tools.siem import init_soc_db  # noqa: E402


@pytest.fixture()
def audit_db(tmp_path: Path) -> Path:
    return init_audit_db(tmp_path / "audit.db")


def test_init_audit_db_is_idempotent(audit_db: Path) -> None:
    init_audit_db(audit_db)
    with sqlite3.connect(audit_db) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {"investigation_runs", "hitl_audit_log"} <= tables


def test_record_run_upserts_single_row(audit_db: Path) -> None:
    record = RunRecord(
        run_id="run-1",
        alert_id="ALT-1",
        verdict="malicious",
        severity="high",
        total_latency_ms=120.0,
        step_count=4,
        traces_json='[{"name": "synthesize"}]',
        status="paused",
    )
    record_run(record, db_path=audit_db)
    record_run(
        RunRecord(**{**record.__dict__, "status": "completed", "hitl_decision": "rejected"}),
        db_path=audit_db,
    )

    runs = get_recent_runs(db_path=audit_db)
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert runs[0]["hitl_decision"] == "rejected"


def test_hitl_audit_is_append_only_and_deduplicated(audit_db: Path) -> None:
    class Action:
        action = "block_ip"
        target = "203.0.113.42"

    for _ in range(2):
        inserted = record_hitl_decisions(
            run_id="run-1",
            alert_id="ALT-1",
            actions=[Action()],
            decision="approved",
            reviewer="analyst",
            db_path=audit_db,
        )
        assert inserted in (0, 1)

    entries = get_hitl_audit(db_path=audit_db)
    assert len(entries) == 1
    assert entries[0].action_type == "block_ip"
    assert entries[0].decision == "approved"

    # A repeated decision with different values must not overwrite history.
    record_hitl_decisions(
        run_id="run-1",
        alert_id="ALT-1",
        actions=[Action()],
        decision="rejected",
        reviewer="someone_else",
        db_path=audit_db,
    )
    entries = get_hitl_audit(db_path=audit_db)
    assert len(entries) == 1
    assert entries[0].decision == "approved"
    assert entries[0].reviewer == "analyst"


def test_metrics_aggregate_from_stored_runs(audit_db: Path) -> None:
    for index, latency in enumerate((100.0, 200.0, 300.0), start=1):
        record_run(
            RunRecord(
                run_id=f"run-{index}",
                alert_id=f"ALT-{index}",
                verdict="benign",
                total_latency_ms=latency,
                fallback_count=1 if index == 1 else 0,
                injection_detected=1 if index == 2 else 0,
                status="completed",
            ),
            db_path=audit_db,
        )

    metrics = get_run_metrics(db_path=audit_db)
    assert metrics.total_runs == 3
    assert metrics.completed_runs == 3
    assert metrics.mttt_ms == pytest.approx(200.0)
    assert metrics.p95_latency_ms == 300.0
    assert metrics.fallback_rate == pytest.approx(1 / 3)
    assert metrics.injection_detections == 1


def test_graph_persists_one_run_across_hitl_resume(
    tmp_path: Path, audit_db: Path
) -> None:
    siem_db = init_soc_db(tmp_path / "siem.duckdb")
    alert = SecurityAlert(
        alert_id="ALT-1001",
        severity=Severity.CRITICAL,
        title="C2 beacon",
        raw_payload="powershell from 203.0.113.42 on WS-FIN-014",
        source_ip="203.0.113.42",
        hostname="WS-FIN-014",
    )
    graph = build_graph(db_path=str(siem_db), audit_db_path=str(audit_db))
    start_triage(graph, alert, "persist-1")
    assert get_recent_runs(db_path=audit_db)[0]["status"] == "paused"

    resume_triage(graph, "persist-1", "approved", decided_by="analyst")
    runs = get_recent_runs(db_path=audit_db)
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert runs[0]["hitl_decision"] == "approved"
    assert len(get_hitl_audit(db_path=audit_db)) == 2

    with sqlite3.connect(audit_db) as connection:
        traces_json = connection.execute(
            "SELECT traces_json FROM investigation_runs WHERE run_id = ?",
            (runs[0]["run_id"],),
        ).fetchone()[0]
    assert any(
        item["name"] == "hitl_gate" for item in traces_from_json(traces_json)
    )
