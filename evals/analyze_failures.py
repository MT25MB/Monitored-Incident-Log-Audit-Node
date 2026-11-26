"""Summarise failed benchmark cases by failure mode.

Reads the compact JSON artifact written by ``evals/run_eval.py`` and groups
failures into misclassification, MITRE mismatch, latency spike, and injection
slip. Each group ends with a pointer to the code most likely responsible.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evals.run_eval import DEFAULT_JSON, CaseResult, RunArtifact  # noqa: E402

__all__ = ["group_failures", "main", "render_report"]


_HINTS: dict[str, str] = {
    "Misclassification": (
        "Check the classification thresholds in synthesize() (src/agent/graph.py) "
        "and the indicator's confidence in check_threat_intel() (src/tools/siem.py)."
    ),
    "MITRE mismatch": (
        "Check _build_mitre() (src/agent/graph.py), the technique ID validator in "
        "MitreMapping (src/schemas.py), and mitre_technique values in the seeded logs."
    ),
    "Latency spike": (
        "Check per-step StepTrace records, DuckDB row limits (src/tools/siem.py), "
        "and pacing or fallback retries (src/config.py)."
    ),
    "Prompt-injection slip": (
        "Check INJECTION_PHRASE_PATTERNS and DELIMITER_BREAKOUT_PATTERNS in "
        "src/guardrails/sanitizer.py, then the fail-closed HITL gate in src/agent/graph.py."
    ),
}


def group_failures(
    cases: Sequence[CaseResult], *, latency_threshold_ms: float
) -> dict[str, list[CaseResult]]:
    """Sort cases into the four failure modes; a case can appear in several."""
    groups: dict[str, list[CaseResult]] = {key: [] for key in _HINTS}
    for case in cases:
        if not case.verdict_pass:
            groups["Misclassification"].append(case)
        if not case.mitre_pass:
            groups["MITRE mismatch"].append(case)
        if case.latency_ms > latency_threshold_ms:
            groups["Latency spike"].append(case)
        if case.injection_expected and not case.injection_pass:
            groups["Prompt-injection slip"].append(case)
    return groups


def _case_line(case: CaseResult, mode: str) -> str:
    if mode == "Misclassification":
        detail = f"expected {case.expected_classification}, got {case.actual_classification}"
    elif mode == "MITRE mismatch":
        detail = (
            f"expected {','.join(case.expected_mitre) or 'none'}, "
            f"got {','.join(case.actual_mitre) or 'none'}"
        )
    elif mode == "Latency spike":
        detail = f"{case.latency_ms:.3f} ms across {case.tool_calls} tool calls"
    else:
        detail = (
            f"detected={case.injection_detected}, "
            f"blocked={case.injection_pass}"
        )
    suffix = f"; error: {case.error}" if case.error else ""
    return f"  - {case.case_id} ({case.alert_id}): {detail}{suffix}"


def render_report(
    artifact: RunArtifact,
    groups: dict[str, list[CaseResult]],
    *,
    path: Path,
    latency_threshold_ms: float,
) -> str:
    """Render a concise Markdown-free terminal report."""
    lines = [
        f"Failure breakdown: {path}",
        f"Run: {artifact.generated_at} | Cases: {artifact.summary.get('total_cases', len(artifact.cases))}",
    ]
    if latency_threshold_ms:
        lines.append(f"Latency threshold: {latency_threshold_ms:.3f} ms")

    total = sum(len(cases) for cases in groups.values())
    if total == 0:
        lines.extend(["", "No failures in the groups checked."])
        return "\n".join(lines)

    for mode, cases in groups.items():
        title = mode
        if mode == "Latency spike":
            title = f"{mode} (> {latency_threshold_ms:.3f} ms)"
        lines.extend(["", f"{title} ({len(cases)})"])
        for case in cases:
            lines.append(_case_line(case, mode))
        lines.append(f"  Hint: {_HINTS[mode]}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Analyse MILAN benchmark failures")
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_JSON,
        help="Benchmark JSON artifact (default: evals/latest_run.json)",
    )
    parser.add_argument(
        "--latency-ms",
        type=float,
        default=300.0,
        help="Latency above this many milliseconds counts as a spike",
    )
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"ERROR: no benchmark artifact at {args.path}", file=sys.stderr)
        print("Run python -m evals.run_eval first.", file=sys.stderr)
        return 1

    try:
        artifact = RunArtifact.model_validate_json(
            args.path.read_text(encoding="utf-8")
        )
    except (ValidationError, ValueError) as exc:
        print(f"ERROR: invalid benchmark artifact: {exc}", file=sys.stderr)
        return 1

    groups = group_failures(
        artifact.cases, latency_threshold_ms=args.latency_ms
    )
    print(
        render_report(
            artifact,
            groups,
            path=args.path,
            latency_threshold_ms=args.latency_ms,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
