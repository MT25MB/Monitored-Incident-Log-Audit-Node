"""Offline tests for the MILAN command-line entry point."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.cli import main  # noqa: E402
from src.monitoring.store import get_hitl_audit  # noqa: E402

_ALERT = {
    "alert_id": "ALT-1001",
    "severity": "critical",
    "title": "Encoded PowerShell and C2 beacon",
    "raw_payload": "powershell.exe -enc JABz from 203.0.113.42 to WS-FIN-014",
    "source_ip": "203.0.113.42",
    "hostname": "WS-FIN-014",
}


def test_init_db_creates_seeded_store(tmp_path: Path, capsys) -> None:
    db = tmp_path / "soc.duckdb"
    assert main(["init-db", "--db-path", str(db)]) == 0
    assert db.exists()
    output = capsys.readouterr().out
    assert "siem_logs=" in output
    assert "Idempotent" in output


def test_triage_prints_summary_and_records_decision(tmp_path: Path, capsys) -> None:
    db = tmp_path / "soc.duckdb"
    audit = tmp_path / "audit.db"
    exit_code = main(
        [
            "triage",
            "--json",
            json.dumps(_ALERT),
            "--hitl",
            "reject",
            "--db-path",
            str(db),
            "--audit-db",
            str(audit),
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Verdict: malicious" in output
    assert "Severity: critical" in output
    assert "MITRE:" in output
    assert "Injection detected: no" in output
    assert "Estimated cost: $0.00" in output
    assert "HITL decision: rejected" in output
    assert any(entry.decision == "rejected" for entry in get_hitl_audit(db_path=audit))


def test_triage_instructions_mode_does_not_execute(tmp_path: Path, capsys) -> None:
    audit = tmp_path / "audit.db"
    exit_code = main(
        [
            "triage",
            "--json",
            json.dumps(_ALERT),
            "--hitl",
            "instructions",
            "--db-path",
            str(tmp_path / "soc.duckdb"),
            "--audit-db",
            str(audit),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "No action executed" in output
    assert get_hitl_audit(db_path=audit) == ()


def test_batch_limits_and_writes_results(tmp_path: Path, capsys) -> None:
    dataset = tmp_path / "alerts.jsonl"
    dataset.write_text(
        "\n".join(json.dumps({"alert": dict(_ALERT, alert_id=f"ALT-{index}")}) for index in (1, 2))
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "batch.json"
    exit_code = main(
        [
            "batch",
            str(dataset),
            "--limit",
            "1",
            "--output-json",
            str(out),
            "--db-path",
            str(tmp_path / "soc.duckdb"),
            "--audit-db",
            str(tmp_path / "audit.db"),
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Processed 1 alert(s)" in output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["total"] == 1
    assert len(payload["cases"]) == 1
    assert payload["cases"][0]["verdict"] == "malicious"
