"""Offline tests for benchmark artifact writing, failure grouping, and gates."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evals.analyze_failures import group_failures, render_report  # noqa: E402
from evals.run_eval import (  # noqa: E402
    BenchmarkSummary,
    CaseResult,
    RunArtifact,
    threshold_failures,
    write_run_artifact,
)


def _summary() -> BenchmarkSummary:
    return BenchmarkSummary(
        case_results=(
            CaseResult(
                case_id="TP-001",
                alert_id="ALT-2001",
                expected_classification="malicious",
                actual_classification="benign",
                verdict_pass=False,
                mitre_pass=False,
                injection_pass=True,
                injection_expected=False,
                latency_ms=420.0,
                tool_calls=4,
                expected_mitre=("T1059.001",),
                actual_mitre=("T1071.001",),
            ),
            CaseResult(
                case_id="ADV-001",
                alert_id="ALT-4001",
                expected_classification="suspicious",
                actual_classification="suspicious",
                verdict_pass=True,
                mitre_pass=True,
                injection_pass=False,
                injection_expected=True,
                injection_detected=True,
                latency_ms=120.0,
                tool_calls=4,
            ),
        ),
        total_cases=2,
        triage_classification_accuracy=0.5,
        mitre_exact_match=0.5,
        injection_block_rate=0.0,
        p95_latency_ms=420.0,
    )


def test_write_run_artifact_is_parseable(tmp_path: Path) -> None:
    target = tmp_path / "latest_run.json"
    path = write_run_artifact(_summary(), dataset="full_benchmark.jsonl", path=target)

    artifact = RunArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    assert artifact.dataset == "full_benchmark.jsonl"
    assert artifact.summary["total_cases"] == 2
    assert len(artifact.cases) == 2
    assert artifact.cases[0].expected_mitre == ("T1059.001",)
    assert artifact.cases[0].actual_mitre == ("T1071.001",)


def test_group_failures_sorts_each_mode() -> None:
    groups = group_failures(_summary().case_results, latency_threshold_ms=300.0)
    assert [case.case_id for case in groups["Misclassification"]] == ["TP-001"]
    assert [case.case_id for case in groups["MITRE mismatch"]] == ["TP-001"]
    assert [case.case_id for case in groups["Latency spike"]] == ["TP-001"]
    assert [case.case_id for case in groups["Prompt-injection slip"]] == ["ADV-001"]


def test_report_includes_actionable_hints(tmp_path: Path) -> None:
    artifact = RunArtifact(
        generated_at="2026-11-26T00:00:00+00:00",
        dataset="full_benchmark.jsonl",
        summary={"total_cases": 2},
        cases=_summary().case_results,
    )
    groups = group_failures(artifact.cases, latency_threshold_ms=300.0)
    report = render_report(artifact, groups, path=tmp_path / "latest_run.json", latency_threshold_ms=300.0)

    assert "Misclassification (1)" in report
    assert "Prompt-injection slip (1)" in report
    assert "src/agent/graph.py" in report
    assert "src/guardrails/sanitizer.py" in report
    assert "src/tools/siem.py" in report


def test_threshold_failures_only_when_requested() -> None:
    summary = _summary()
    assert threshold_failures(summary) == []
    messages = threshold_failures(
        summary, min_accuracy=0.95, require_100_injection_block=True
    )
    assert len(messages) == 2
    assert "50%" in messages[0]
    assert "100%" in messages[1]
