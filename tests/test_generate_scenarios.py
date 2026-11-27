"""Tests for deterministic synthetic scenario generation and DuckDB seeding."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evals.generate_scenarios import generate, main  # noqa: E402
from evals.run_eval import EvalCase  # noqa: E402
from src.guardrails.sanitizer import detect_injections  # noqa: E402
from src.tools.siem import (  # noqa: E402
    check_threat_intel,
    init_soc_db,
    lookup_asset_inventory,
    query_siem_logs,
    seed_generated_scenarios,
)


def test_generation_is_deterministic() -> None:
    first = generate(count=12, seed=7)
    second = generate(count=12, seed=7)
    assert json.dumps(first) == json.dumps(second)
    assert first != generate(count=12, seed=8)


def test_cases_validate_and_cover_all_families() -> None:
    cases = generate(count=12, seed=7)
    for case in cases:
        EvalCase.model_validate(case)

    classifications = {case["expected"]["classification"] for case in cases}
    assert {"malicious", "benign", "suspicious"} <= classifications
    assert len({case["case_id"] for case in cases}) == 12
    assert len({case["alert"]["alert_id"] for case in cases}) == 12
    assert len({case["seed"]["indicator"] for case in cases}) == 12
    assert len({case["seed"]["hostname"] for case in cases}) == 12
    assert any(case["expected"]["injection_expected"] for case in cases)


def test_adversarial_payloads_are_detected() -> None:
    hostile = [
        case for case in generate(count=12, seed=7) if case["expected"]["injection_expected"]
    ]
    assert hostile
    for case in hostile:
        assert detect_injections(case["alert"]["raw_payload"])


def test_append_mode_deduplicates(tmp_path: Path) -> None:
    target = tmp_path / "generated.jsonl"
    arguments = ["--output", str(target), "--count", "12", "--seed", "7", "--append"]

    assert main(arguments) == 0
    first_lines = len(target.read_text(encoding="utf-8").splitlines())
    assert main(arguments) == 0
    assert len(target.read_text(encoding="utf-8").splitlines()) == first_lines


def test_generated_scenarios_seed_into_duckdb(tmp_path: Path) -> None:
    cases = generate(count=12, seed=7)
    db = init_soc_db(tmp_path / "soc.duckdb")

    assert seed_generated_scenarios(cases, db_path=db) == 12
    case = cases[0]
    assert query_siem_logs(alert_id=case["alert"]["alert_id"], db_path=db).count == 1
    assert check_threat_intel(case["seed"]["indicator"], db_path=db).count == 1
    assert lookup_asset_inventory(hostname=case["seed"]["hostname"], db_path=db).count == 1

    # Re-seeding is idempotent.
    seed_generated_scenarios(cases, db_path=db)
    assert query_siem_logs(alert_id=case["alert"]["alert_id"], db_path=db).count == 1
    assert check_threat_intel(case["seed"]["indicator"], db_path=db).count == 1
