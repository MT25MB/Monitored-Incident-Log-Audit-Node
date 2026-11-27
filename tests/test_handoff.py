"""Tests for shift handoff generation from the audit store."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.handoff import build_handoff, render_handoff  # noqa: E402
from src.cli import main  # noqa: E402
from src.monitoring.store import (  # noqa: E402
    RunRecord,
    get_recent_runs,
    init_audit_db,
    record_hitl_decisions,
    record_run,
)


class _Action:
    def __init__(self, action: str, target: str) -> None:
        self.action = action
        self.target = target


@pytest.fixture()
def audit_db(tmp_path: Path) -> Path:
    db = init_audit_db(tmp_path / "audit.db")
    record_run(
        RunRecord(
            run_id="run-1",
            alert_id="ALT-1001",
            verdict="malicious",
            severity="critical",
            total_latency_ms=120.0,
            step_count=4,
            status="completed",
            hitl_decision="approved",
        ),
        db_path=db,
    )
    record_run(
        RunRecord(
            run_id="run-2",
            alert_id="ALT-1003",
            verdict="suspicious",
            severity="high",
            injection_detected=True,
            status="paused",
            pending_actions_json=json.dumps(
                [
                    {
                        "action": "block_ip",
                        "target": "198.51.100.77",
                        "approval_status": "pending",
                    }
                ]
            ),
        ),
        db_path=db,
    )
    record_hitl_decisions(
        run_id="run-1",
        alert_id="ALT-1001",
        actions=[_Action("isolate_host", "WS-FIN-014")],
        decision="approved",
        reviewer="analyst",
        db_path=db,
    )
    return db


def test_pending_actions_are_stored_with_paused_runs(audit_db: Path) -> None:
    paused = [run for run in get_recent_runs(db_path=audit_db) if run["status"] == "paused"]
    assert len(paused) == 1
    actions = json.loads(paused[0]["pending_actions_json"])
    assert actions[0]["action"] == "block_ip"


def test_handoff_collects_all_three_sections(audit_db: Path) -> None:
    summary = build_handoff(db_path=audit_db)

    assert len(summary.completed) == 1
    assert summary.completed[0]["alert_id"] == "ALT-1001"
    assert len(summary.pending) == 1
    assert summary.pending[0]["target"] == "198.51.100.77"
    assert len(summary.injections) == 1
    assert summary.injections[0]["alert_id"] == "ALT-1003"
    assert summary.decisions[0]["decision"] == "approved"


def test_render_markdown_and_text(audit_db: Path) -> None:
    summary = build_handoff(db_path=audit_db)
    markdown = render_handoff(summary, fmt="markdown")
    text = render_handoff(summary, fmt="text")

    assert markdown.startswith("# SOC shift handoff")
    assert "ALT-1001: malicious" in markdown
    assert "block_ip on 198.51.100.77 is pending" in markdown
    assert "ALT-1003: injection detected" in markdown
    assert "approved by analyst" in markdown
    assert text.startswith("SOC shift handoff")
    assert "#" not in text


def test_render_empty_handoff_is_plain(tmp_path: Path) -> None:
    db = init_audit_db(tmp_path / "empty.db")
    report = render_handoff(build_handoff(db_path=db), fmt="text")
    assert "No completed triage runs" in report
    assert "No containment actions" in report
    assert "No injection attempts" in report


def test_cli_handoff_writes_output(audit_db: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "handoff.md"
    exit_code = main(
        ["handoff", "--audit-db", str(audit_db), "--format", "markdown", "--output", str(out)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Handoff written to" in captured.out
    assert "# SOC shift handoff" in out.read_text(encoding="utf-8")


def test_audit_db_migrates_pending_column(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as connection:
        connection.execute(
            """
            CREATE TABLE investigation_runs (
                run_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                verdict TEXT, severity TEXT, injection_detected INTEGER NOT NULL DEFAULT 0,
                total_latency_ms REAL NOT NULL DEFAULT 0.0,
                step_count INTEGER NOT NULL DEFAULT 0, provider_used TEXT,
                fallback_count INTEGER NOT NULL DEFAULT 0,
                traces_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'paused', hitl_decision TEXT
            )
            """
        )
    init_audit_db(db)
    with sqlite3.connect(db) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(investigation_runs)")}
    assert "pending_actions_json" in columns
