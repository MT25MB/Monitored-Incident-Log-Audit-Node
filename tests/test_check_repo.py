"""Tests for the repository check script."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.check_repo import (  # noqa: E402
    CheckResult,
    Report,
    check_dataset,
    check_links,
    main,
    render_checklist,
    run_checks,
)

_MINIMAL_ALERT = {
    "alert_id": "ALT-1",
    "severity": "medium",
    "title": "Synthetic alert",
    "raw_payload": "event from 203.0.113.42",
}


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "evals/datasets").mkdir(parents=True)
    (tmp_path / "README.md").write_text("# Test\n\n![Logo](docs/logo.png)\n", encoding="utf-8")
    (tmp_path / "docs/README.md").write_text("# Docs\n", encoding="utf-8")
    (tmp_path / "docs/index.html").write_text(
        '<html><body><img src="logo.png" alt="logo">'
        '<link rel="stylesheet" href="styles.css"></body></html>',
        encoding="utf-8",
    )
    (tmp_path / "docs/logo.png").write_bytes(b"fake")
    (tmp_path / "docs/styles.css").write_text("body {}", encoding="utf-8")
    (tmp_path / "evals/datasets/full_benchmark.jsonl").write_text(
        json.dumps({"case_id": "C1", "alert": _MINIMAL_ALERT}) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_check_links_passes_with_local_assets(tmp_path: Path) -> None:
    result = check_links(_make_repo(tmp_path))
    assert result.passed is True
    assert "local reference(s) resolved" in result.detail


def test_check_links_detects_missing_asset(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    (root / "docs/logo.png").unlink()
    result = check_links(root)
    assert result.passed is False
    assert "README.md -> docs/logo.png" in result.detail


def test_check_dataset_validates_cases(tmp_path: Path) -> None:
    path = tmp_path / "cases.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"alert": _MINIMAL_ALERT}),
                json.dumps({"alert": dict(_MINIMAL_ALERT, alert_id="ALT-2")}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = check_dataset(path)
    assert result.passed is True
    assert "2 case(s) validated" in result.detail


def test_check_dataset_reports_bad_json_and_schema(tmp_path: Path) -> None:
    bad_json = tmp_path / "bad.jsonl"
    bad_json.write_text("{not json\n", encoding="utf-8")
    assert check_dataset(bad_json).passed is False

    bad_schema = tmp_path / "bad_schema.jsonl"
    bad_schema.write_text(json.dumps({"alert": {"alert_id": "ALT-1"}}) + "\n", encoding="utf-8")
    assert "invalid SecurityAlert" in check_dataset(bad_schema).detail


def test_render_checklist_and_cli(tmp_path: Path, capsys) -> None:
    root = _make_repo(tmp_path)
    report = run_checks(root=root)
    assert report.passed is True

    output = render_checklist(report)
    assert "[PASS] local links" in output
    assert "Overall: PASS" in output

    assert main(["--root", str(root)]) == 0
    assert "Overall: PASS" in capsys.readouterr().out


def test_report_fails_when_one_check_fails() -> None:
    report = Report(
        checks=(
            CheckResult("local links", True),
            CheckResult("benchmark dataset", False, "bad line"),
        )
    )
    assert report.passed is False
    assert "Overall: FAIL" in render_checklist(report)
