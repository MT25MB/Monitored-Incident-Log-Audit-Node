"""Regression tests for defects found during the security and QA audit.

Each test targets a concrete runtime failure discovered in Phase 1. They are
written before the fixes so the suite demonstrates the defect first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.handoff import HandoffSummary, render_handoff  # noqa: E402
from src.config import _extract_json_object  # noqa: E402
from src.tools.siem import init_soc_db, seed_generated_scenarios  # noqa: E402


def test_handoff_render_survives_malformed_pending_action() -> None:
    """A corrupted pending row must not crash the shift handoff."""
    summary = HandoffSummary(pending=({"alert_id": "ALT-1"},))  # type: ignore[arg-type]
    report = render_handoff(summary, fmt="text")
    assert "pending a human decision" in report


def test_handoff_render_survives_malformed_injection_and_decision() -> None:
    """Corrupted injection and decision rows must not crash rendering either."""
    summary = HandoffSummary(
        injections=({"alert_id": "ALT-2"},),  # type: ignore[arg-type]
        decisions=({"alert_id": "ALT-3"},),  # type: ignore[arg-type]
    )
    report = render_handoff(summary, fmt="text")
    assert "injection detected" in report
    assert "approved by" not in report


def test_malformed_generated_scenario_is_skipped(tmp_path: Path) -> None:
    """An alert id without a numeric suffix must not abort seeding."""
    db = init_soc_db(tmp_path / "soc.duckdb")
    scenarios = [
        {
            "alert": {
                "alert_id": "ALT-1",
                "severity": "low",
                "title": "Synthetic",
                "raw_payload": "event",
            },
            "seed": {
                "hostname": "WS-1",
                "indicator": "203.0.113.10",
                "indicator_type": "ip",
                "source": "sysmon",
            },
        },
        {
            "alert": {
                "alert_id": "BROKEN-ID",
                "severity": "low",
                "title": "Synthetic",
                "raw_payload": "event",
            },
            "seed": {
                "hostname": "WS-2",
                "indicator": "198.51.100.10",
                "indicator_type": "ip",
                "source": "sysmon",
            },
        },
        {
            "alert": {
                "alert_id": "ALT-2",
                "severity": "low",
                "title": "Synthetic",
                "raw_payload": "event",
            },
            "seed": {
                "hostname": "WS-3",
                "indicator": "192.0.2.10",
                "indicator_type": "ip",
                "source": "sysmon",
            },
        },
    ]
    assert seed_generated_scenarios(scenarios, db_path=db) == 2


def test_json_object_is_extracted_despite_trailing_noise() -> None:
    """A valid JSON object must be found even when the response has trailing text."""
    payload = json.dumps({"verdict": "malicious", "confidence": 0.9})
    assert _extract_json_object(f"analysis: {payload} thanks }}") == {
        "verdict": "malicious",
        "confidence": 0.9,
    }


def test_json_object_prefers_first_complete_object() -> None:
    """Greedy matching must not swallow a second object in trailing chatter."""
    first = json.dumps({"verdict": "benign"})
    second = json.dumps({"verdict": "malicious"})
    assert _extract_json_object(f"{first} note: {second}") == {"verdict": "benign"}


def test_invalid_json_still_raises_schema_error() -> None:
    """The tolerant path must still reject responses with no JSON object."""
    from src.config import SchemaParseError

    with pytest.raises(SchemaParseError):
        _extract_json_object("no structured data here")
