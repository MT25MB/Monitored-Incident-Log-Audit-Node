"""Tests for the evaluation artifact comparison utility."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evals.compare_runs import (  # noqa: E402
    case_passed,
    compare_artifacts,
    load_artifact,
    main,
    render_markdown,
)
from evals.run_eval import CaseResult, RunArtifact  # noqa: E402


def _case(
    case_id: str,
    *,
    verdict: bool = True,
    mitre: bool = True,
    injection: bool = True,
    steps: bool = True,
    grounded: bool = True,
    actual: str = "malicious",
) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        alert_id=f"ALT-{case_id}",
        expected_classification="malicious",
        actual_classification=actual,
        verdict_pass=verdict,
        mitre_pass=mitre,
        injection_pass=injection,
        step_cap_pass=steps,
        grounded=grounded,
        latency_ms=100.0,
    )


def _artifact(cases: tuple[CaseResult, ...], **summary: float) -> RunArtifact:
    base = {
        "total_cases": len(cases),
        "triage_classification_accuracy": 1.0,
        "mitre_exact_match": 1.0,
        "injection_block_rate": 1.0,
        "p50_latency_ms": 0.036,
        "p95_latency_ms": 29.758,
    }
    base.update(summary)
    return RunArtifact(
        generated_at="2026-11-26T00:00:00+00:00",
        dataset="full_benchmark.jsonl",
        summary=base,
        cases=cases,
    )


def _write(path: Path, artifact: RunArtifact) -> Path:
    path.write_text(artifact.model_dump_json(), encoding="utf-8")
    return path


def test_case_passed_checks_all_dimensions() -> None:
    assert case_passed(_case("C1")) is True
    assert case_passed(_case("C2", mitre=False)) is False


def test_compare_reports_deltas_and_flips() -> None:
    baseline = _artifact(
        (_case("C1"), _case("C2", mitre=False), _case("C3")),
        triage_classification_accuracy=1.0,
        mitre_exact_match=0.667,
    )
    candidate = _artifact(
        (_case("C1", verdict=False, actual="benign"), _case("C2"), _case("C3")),
        triage_classification_accuracy=0.667,
        mitre_exact_match=1.0,
        p95_latency_ms=31.5,
    )

    result = compare_artifacts(baseline, candidate)

    by_name = {metric.name: metric for metric in result.metrics}
    assert by_name["Triage Classification Accuracy"].delta == "-33 pp"
    assert by_name["MITRE ATT&CK Match"].delta == "+33 pp"
    assert by_name["Prompt-Injection Resistance"].delta == "+0 pp"
    assert by_name["p95 step latency"].delta == "+1.742 ms"

    assert [(flip.direction, flip.case_id) for flip in result.flips] == [
        ("fail -> pass", "C2"),
        ("pass -> fail", "C1"),
    ]
    assert result.only_baseline == ()
    assert result.only_candidate == ()


def test_render_markdown_contains_sections() -> None:
    baseline = _artifact((_case("C1"),))
    candidate = _artifact((_case("C1", steps=False), _case("C2")))
    result = compare_artifacts(baseline, candidate)
    report = render_markdown(result)

    assert "| Metric | Baseline | Candidate | Delta |" in report
    assert "Triage Classification Accuracy" in report
    assert "pass -> fail" in report
    assert "Only in candidate: C2" in report

    same = compare_artifacts(baseline, baseline)
    assert "No cases changed overall pass/fail status." in render_markdown(same)


def test_cli_writes_markdown_report(tmp_path: Path, capsys) -> None:
    baseline = _write(tmp_path / "baseline.json", _artifact((_case("C1"),)))
    candidate = _write(
        tmp_path / "candidate.json", _artifact((_case("C1", mitre=False),))
    )
    output = tmp_path / "comparison.md"

    exit_code = main([str(baseline), str(candidate), "--output-md", str(output)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Report written to" in captured.out
    text = output.read_text(encoding="utf-8")
    assert "# MILAN run comparison" in text
    assert "pass -> fail" in text
    assert load_artifact(baseline).dataset == "full_benchmark.jsonl"


def test_cli_rejects_invalid_json(tmp_path: Path, capsys) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    good = _write(tmp_path / "good.json", _artifact((_case("C1"),)))

    assert main([str(bad), str(good)]) == 2
    assert "ERROR" in capsys.readouterr().out
