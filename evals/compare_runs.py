"""Compare two MILAN evaluation result files.

Inputs are compact JSON artifacts written by ``evals/run_eval.py``. The report
shows metric deltas and cases whose overall result flipped between runs.

Usage::

    python -m evals.compare_runs evals/baseline.json evals/candidate.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from evals.run_eval import CaseResult, RunArtifact

__all__ = [
    "Comparison",
    "Flip",
    "MetricDelta",
    "case_passed",
    "compare_artifacts",
    "load_artifact",
    "main",
    "render_markdown",
]


@dataclass(frozen=True)
class MetricDelta:
    """One metric across baseline and candidate."""

    name: str
    baseline: str
    candidate: str
    delta: str


@dataclass(frozen=True)
class Flip:
    """A case whose overall result changed."""

    direction: str
    case_id: str
    baseline_classification: str
    candidate_classification: str
    detail: str


@dataclass(frozen=True)
class Comparison:
    """Complete comparison result."""

    baseline_label: str
    candidate_label: str
    baseline_cases: int
    candidate_cases: int
    metrics: tuple[MetricDelta, ...]
    flips: tuple[Flip, ...]
    only_baseline: tuple[str, ...]
    only_candidate: tuple[str, ...]


def load_artifact(path: str | Path) -> RunArtifact:
    """Read and validate a run artifact."""
    source = Path(path)
    return RunArtifact.model_validate_json(source.read_text(encoding="utf-8"))


def _failed_checks(case: CaseResult) -> list[str]:
    checks = (
        ("verdict", case.verdict_pass),
        ("MITRE", case.mitre_pass),
        ("injection", case.injection_pass),
        ("steps", case.step_cap_pass),
        ("grounded", case.grounded is not False),
    )
    return [name for name, passed in checks if not passed]


def case_passed(case: CaseResult) -> bool:
    """True when every graded check passed for this case."""
    return not _failed_checks(case)


def _rate(value: float) -> str:
    return f"{value:.0%}"


def _rate_delta(baseline: float, candidate: float) -> str:
    return f"{(candidate - baseline) * 100:+.0f} pp"


def _ms(value: float) -> str:
    return f"{value:.3f} ms"


def _ms_delta(baseline: float, candidate: float) -> str:
    return f"{candidate - baseline:+.3f} ms"


def compare_artifacts(
    baseline: RunArtifact,
    candidate: RunArtifact,
    *,
    baseline_label: str = "baseline",
    candidate_label: str = "candidate",
) -> Comparison:
    """Diff metrics and case outcomes between two artifacts."""
    base_summary: dict[str, Any] = baseline.summary
    cand_summary: dict[str, Any] = candidate.summary

    definitions = (
        ("Triage Classification Accuracy", "triage_classification_accuracy", _rate, _rate_delta),
        ("MITRE ATT&CK Match", "mitre_exact_match", _rate, _rate_delta),
        ("Prompt-Injection Resistance", "injection_block_rate", _rate, _rate_delta),
        ("p50 step latency", "p50_latency_ms", _ms, _ms_delta),
        ("p95 step latency", "p95_latency_ms", _ms, _ms_delta),
    )
    metrics: list[MetricDelta] = []
    for name, key, formatter, delta_formatter in definitions:
        base_value = float(base_summary.get(key, 0.0) or 0.0)
        cand_value = float(cand_summary.get(key, 0.0) or 0.0)
        metrics.append(
            MetricDelta(
                name=name,
                baseline=formatter(base_value),
                candidate=formatter(cand_value),
                delta=delta_formatter(base_value, cand_value),
            )
        )

    base_cases = {case.case_id: case for case in baseline.cases}
    cand_cases = {case.case_id: case for case in candidate.cases}
    flips: list[Flip] = []

    for case_id in base_cases.keys() & cand_cases.keys():
        before, after = base_cases[case_id], cand_cases[case_id]
        passed_before, passed_after = case_passed(before), case_passed(after)
        if passed_before == passed_after:
            continue
        if passed_before:
            direction = "pass -> fail"
            detail = "now failing: " + ", ".join(_failed_checks(after))
        else:
            direction = "fail -> pass"
            detail = "cleared: " + ", ".join(_failed_checks(before))
        flips.append(
            Flip(
                direction=direction,
                case_id=case_id,
                baseline_classification=before.actual_classification,
                candidate_classification=after.actual_classification,
                detail=detail,
            )
        )

    return Comparison(
        baseline_label=baseline_label,
        candidate_label=candidate_label,
        baseline_cases=len(baseline.cases),
        candidate_cases=len(candidate.cases),
        metrics=tuple(metrics),
        flips=tuple(sorted(flips, key=lambda flip: (flip.direction, flip.case_id))),
        only_baseline=tuple(sorted(base_cases.keys() - cand_cases.keys())),
        only_candidate=tuple(sorted(cand_cases.keys() - base_cases.keys())),
    )


def render_markdown(comparison: Comparison) -> str:
    """Render the comparison as a concise Markdown report."""
    lines = [
        "# MILAN run comparison",
        "",
        f"Baseline: `{comparison.baseline_label}` ({comparison.baseline_cases} cases)",
        f"Candidate: `{comparison.candidate_label}` ({comparison.candidate_cases} cases)",
        "",
        "| Metric | Baseline | Candidate | Delta |",
        "| --- | ---: | ---: | ---: |",
    ]
    for metric in comparison.metrics:
        lines.append(
            f"| {metric.name} | {metric.baseline} | {metric.candidate} | {metric.delta} |"
        )

    lines.extend(["", "## Flipped cases", ""])
    if comparison.flips:
        lines.extend(
            [
                "| Direction | Case | Baseline verdict | Candidate verdict | Detail |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for flip in comparison.flips:
            lines.append(
                f"| {flip.direction} | {flip.case_id} | {flip.baseline_classification} | "
                f"{flip.candidate_classification} | {flip.detail} |"
            )
    else:
        lines.append("No cases changed overall pass/fail status.")

    if comparison.only_baseline:
        lines.extend(
            ["", "Only in baseline: " + ", ".join(comparison.only_baseline)]
        )
    if comparison.only_candidate:
        lines.extend(
            ["", "Only in candidate: " + ", ".join(comparison.only_candidate)]
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Compare two MILAN evaluation artifacts")
    parser.add_argument("baseline", type=Path, help="Baseline JSON result file")
    parser.add_argument("candidate", type=Path, help="Candidate JSON result file")
    parser.add_argument("--output-md", type=Path, default=None, help="Write report to Markdown file")
    args = parser.parse_args(argv)

    try:
        baseline = load_artifact(args.baseline)
        candidate = load_artifact(args.candidate)
    except (OSError, ValueError) as exc:
        print(f"ERROR: unable to load artifact: {exc}")
        return 2

    comparison = compare_artifacts(
        baseline,
        candidate,
        baseline_label=str(args.baseline),
        candidate_label=str(args.candidate),
    )
    report = render_markdown(comparison)
    if args.output_md:
        destination = Path(args.output_md)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
        print(f"Report written to {destination}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
