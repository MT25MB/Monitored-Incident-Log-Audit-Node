"""Tests for schema-validated, secret-safe run exports."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.graph import build_graph, resume_triage, start_triage  # noqa: E402
from src.cli import main  # noqa: E402
from src.export import (  # noqa: E402
    SCHEMA_VERSION,
    ExportBundle,
    build_export,
    scrub_text,
    write_export,
)
from src.schemas import SecurityAlert, Severity  # noqa: E402
from src.tools.siem import init_soc_db  # noqa: E402


@pytest.fixture()
def completed_state(tmp_path: Path) -> dict:
    db = init_soc_db(tmp_path / "soc.duckdb")
    graph = build_graph(db_path=str(db), audit_db_path=str(tmp_path / "audit.db"))
    alert = SecurityAlert(
        alert_id="ALT-1001",
        severity=Severity.CRITICAL,
        title="C2 beacon",
        raw_payload=(
            "powershell from 203.0.113.42 to WS-FIN-014 password=hunter2 AKIAIOSFODNN7EXAMPLE"
        ),
        source_ip="203.0.113.42",
        hostname="WS-FIN-014",
    )
    start_triage(graph, alert, "export-1")
    return resume_triage(graph, "export-1", "approved", decided_by="analyst@local")


def test_scrub_text_redacts_secrets() -> None:
    cleaned = scrub_text("token=abcdefgh12345678 password=hunter2 SSN 123-45-6789")
    assert "hunter2" not in cleaned
    assert "123-45-6789" not in cleaned
    assert "[REDACTED]" in cleaned


def test_build_export_contains_all_sections(completed_state: dict) -> None:
    bundle = build_export(completed_state)

    assert bundle.schema_version == SCHEMA_VERSION
    assert bundle.alert_id == "ALT-1001"
    assert bundle.report.classification.value == "malicious"
    assert bundle.correlation.event_count > 0
    assert bundle.hitl.decision == "approved"
    assert bundle.hitl.reviewer == "analyst@local"
    assert bundle.hitl.actions
    assert bundle.traces


def test_export_does_not_leak_raw_secrets(completed_state: dict) -> None:
    text = build_export(completed_state).model_dump_json()
    assert "hunter2" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "untrusted_log_payload" not in text


def test_write_export_creates_valid_json(completed_state: dict, tmp_path: Path) -> None:
    destination = tmp_path / "exports"
    path = write_export(completed_state, output_dir=destination)

    assert path.exists()
    assert path.parent == destination
    parsed = ExportBundle.model_validate_json(path.read_text(encoding="utf-8"))
    assert parsed.alert_id == "ALT-1001"
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == SCHEMA_VERSION


def test_build_export_requires_a_report() -> None:
    with pytest.raises(ValueError, match="without a TriageReport"):
        build_export({"alert_id": "ALT-1"})


def test_export_bundle_rejects_missing_fields() -> None:
    with pytest.raises(ValidationError):
        ExportBundle.model_validate({"schema_version": SCHEMA_VERSION})


def test_cli_triage_can_write_export(tmp_path: Path, capsys) -> None:
    export_dir = tmp_path / "cli-exports"
    exit_code = main(
        [
            "triage",
            "--json",
            json.dumps(
                {
                    "alert_id": "ALT-1001",
                    "severity": "critical",
                    "title": "C2",
                    "raw_payload": "powershell from 203.0.113.42 to WS-FIN-014",
                    "source_ip": "203.0.113.42",
                    "hostname": "WS-FIN-014",
                }
            ),
            "--hitl",
            "reject",
            "--db-path",
            str(tmp_path / "soc.duckdb"),
            "--audit-db",
            str(tmp_path / "audit.db"),
            "--export-dir",
            str(export_dir),
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Export written to" in output
    files = list(export_dir.glob("*.json"))
    assert len(files) == 1
    assert (
        ExportBundle.model_validate_json(files[0].read_text(encoding="utf-8")).alert_id
        == "ALT-1001"
    )
