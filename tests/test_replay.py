"""Tests for filtered, ordered alert replay."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.cli import main  # noqa: E402
from src.monitoring.store import get_recent_runs  # noqa: E402
from src.replay import iter_replay_alerts, replay_dataset  # noqa: E402
from src.tools.siem import init_soc_db  # noqa: E402


@pytest.fixture()
def dataset(tmp_path: Path) -> Path:
    cases = [
        ("GEN-1", "sysmon", "ALT-7001", False),
        ("GEN-2", "cloudtrail", "ALT-7002", True),
        ("GEN-3", "suricata", "ALT-7003", True),
        ("GEN-4", "auth", "ALT-7004", False),
        ("GEN-5", "sysmon", "ALT-7005", True),
    ]
    lines = []
    for case_id, source, alert_id, adversarial in cases:
        lines.append(
            json.dumps(
                {
                    "case_id": case_id,
                    "alert": {
                        "alert_id": alert_id,
                        "source": source,
                        "severity": "high",
                        "title": "Replay sample",
                        "raw_payload": "event from 203.0.113.42 to WS-FIN-014",
                        "source_ip": "203.0.113.42",
                        "hostname": "WS-FIN-014",
                    },
                    "expected": {
                        "classification": "malicious",
                        "mitre": ["T1071.001"],
                        "injection_expected": adversarial,
                    },
                }
            )
        )
    path = tmp_path / "replay.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_iter_replay_alerts_preserves_order(dataset: Path) -> None:
    assert [record.case_id for record in iter_replay_alerts(dataset)] == [
        "GEN-1",
        "GEN-2",
        "GEN-3",
        "GEN-4",
        "GEN-5",
    ]


def test_iter_replay_alerts_filters(dataset: Path) -> None:
    assert [r.case_id for r in iter_replay_alerts(dataset, source="sysmon")] == [
        "GEN-1",
        "GEN-5",
    ]
    assert [r.case_id for r in iter_replay_alerts(dataset, adversarial_only=True)] == [
        "GEN-2",
        "GEN-3",
        "GEN-5",
    ]
    assert [
        r.case_id
        for r in iter_replay_alerts(dataset, source="sysmon", adversarial_only=True)
    ] == ["GEN-5"]
    assert [r.case_id for r in iter_replay_alerts(dataset, limit=2)] == ["GEN-1", "GEN-2"]


def test_replay_records_runs_and_delays_between_alerts(tmp_path: Path, dataset: Path) -> None:
    soc_db = init_soc_db(tmp_path / "soc.duckdb")
    audit_db = tmp_path / "audit.db"
    sleeps: list[float] = []

    summary = replay_dataset(
        dataset,
        delay_sec=0.25,
        limit=2,
        db_path=str(soc_db),
        audit_db_path=str(audit_db),
        sleep_fn=sleeps.append,
    )

    assert summary.total == 2
    assert summary.errors == 0
    assert summary.adversarial_count == 1
    assert summary.counts == {"malicious": 2}
    assert [row["case_id"] for row in summary.records] == ["GEN-1", "GEN-2"]
    assert sleeps == [0.25]

    runs = get_recent_runs(db_path=audit_db)
    assert len(runs) == 2
    assert all(run["status"] == "completed" for run in runs)
    assert all(run["hitl_decision"] == "rejected" for run in runs)


def test_cli_replay_subcommand(tmp_path: Path, dataset: Path, capsys) -> None:
    exit_code = main(
        [
            "replay",
            str(dataset),
            "--source",
            "sysmon",
            "--limit",
            "1",
            "--db-path",
            str(tmp_path / "soc.duckdb"),
            "--audit-db",
            str(tmp_path / "audit.db"),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "[1] GEN-1 (sysmon)" in output
    assert "Replayed 1 alert(s)" in output
