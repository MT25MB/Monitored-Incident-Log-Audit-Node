"""Aggregate metrics from the SQLite audit/trace store.

Run-level fields come from ``investigation_runs``. Provider, fallback, tool,
and cost figures are read from the JSON ``traces_json`` column written by the
graph, so the numbers describe what actually ran rather than what was planned.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.monitoring.store import _resolve_path, init_audit_db

__all__ = ["MetricsSummary", "STEP_CAP", "compute_metrics", "metrics_to_dict"]

#: Mirrors ``src.agent.graph.MAX_INVESTIGATION_STEPS``. Kept local so the
#: metrics module can be imported without loading the graph package.
STEP_CAP = 6


@dataclass(frozen=True)
class MetricsSummary:
    """Operational metrics across stored investigations."""

    total_runs: int = 0
    completed_runs: int = 0
    paused_runs: int = 0
    mttt_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    tool_calls_total: int = 0
    avg_steps_per_alert: float = 0.0
    step_cap_compliant: int = 0
    step_cap_violations: int = 0
    provider_usage: dict[str, int] = field(default_factory=dict)
    fallback_events: int = 0
    fallback_rate: float = 0.0
    estimated_cost_usd: float = 0.0
    injection_flagged_runs: int = 0
    injection_flag_rate: float = 0.0
    hitl_approved: int = 0
    hitl_rejected: int = 0
    hitl_not_required: int = 0


def _percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return ordered[index]


def _decode_traces(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in value if isinstance(item, dict)]


def compute_metrics(*, db_path: str | Path | None = None) -> MetricsSummary:
    """Compute the full metrics summary from the audit database."""
    path = init_audit_db(db_path)
    with sqlite3.connect(_resolve_path(path)) as connection:
        connection.row_factory = sqlite3.Row
        runs = [dict(row) for row in connection.execute("SELECT * FROM investigation_runs")]
        decisions = [
            dict(row)
            for row in connection.execute(
                "SELECT decision, COUNT(*) AS total FROM hitl_audit_log GROUP BY decision"
            )
        ]

    completed = [run for run in runs if run.get("status") == "completed"]
    latencies = [float(run.get("total_latency_ms") or 0.0) for run in completed]
    step_counts = [int(run.get("step_count") or 0) for run in runs]

    provider_usage: dict[str, int] = {}
    tool_calls = 0
    fallback_events = 0
    trace_count = 0
    total_cost = 0.0

    for run in runs:
        for trace in _decode_traces(run.get("traces_json")):
            trace_count += 1
            provider = str(trace.get("provider") or "local")
            provider_usage[provider] = provider_usage.get(provider, 0) + 1
            if trace.get("tool_name"):
                tool_calls += 1
            if trace.get("fallback_triggered") is True:
                fallback_events += 1
            total_cost += float(trace.get("estimated_cost_usd") or 0.0)

    decision_counts = {row["decision"]: int(row["total"]) for row in decisions}
    flagged = sum(int(run.get("injection_detected") or 0) for run in runs)
    total = len(runs)

    return MetricsSummary(
        total_runs=total,
        completed_runs=len(completed),
        paused_runs=sum(1 for run in runs if run.get("status") == "paused"),
        mttt_ms=round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        p50_latency_ms=round(_percentile(latencies, 0.50), 3),
        p95_latency_ms=round(_percentile(latencies, 0.95), 3),
        tool_calls_total=tool_calls,
        avg_steps_per_alert=round(sum(step_counts) / total, 2) if total else 0.0,
        step_cap_compliant=sum(1 for count in step_counts if count <= STEP_CAP),
        step_cap_violations=sum(1 for count in step_counts if count > STEP_CAP),
        provider_usage=dict(sorted(provider_usage.items())),
        fallback_events=fallback_events,
        fallback_rate=round(fallback_events / trace_count, 4) if trace_count else 0.0,
        estimated_cost_usd=round(total_cost, 6),
        injection_flagged_runs=flagged,
        injection_flag_rate=round(flagged / total, 4) if total else 0.0,
        hitl_approved=decision_counts.get("approved", 0),
        hitl_rejected=decision_counts.get("rejected", 0),
        hitl_not_required=sum(1 for run in runs if run.get("hitl_decision") == "not_required"),
    )


def metrics_to_dict(summary: MetricsSummary) -> dict[str, Any]:
    """Return a JSON-friendly view of a metrics summary."""
    return {
        "total_runs": summary.total_runs,
        "completed_runs": summary.completed_runs,
        "paused_runs": summary.paused_runs,
        "mttt_ms": summary.mttt_ms,
        "p50_latency_ms": summary.p50_latency_ms,
        "p95_latency_ms": summary.p95_latency_ms,
        "tool_calls_total": summary.tool_calls_total,
        "avg_steps_per_alert": summary.avg_steps_per_alert,
        "step_cap_compliant": summary.step_cap_compliant,
        "step_cap_violations": summary.step_cap_violations,
        "provider_usage": summary.provider_usage,
        "fallback_events": summary.fallback_events,
        "fallback_rate": summary.fallback_rate,
        "estimated_cost_usd": summary.estimated_cost_usd,
        "injection_flagged_runs": summary.injection_flagged_runs,
        "injection_flag_rate": summary.injection_flag_rate,
        "hitl_approved": summary.hitl_approved,
        "hitl_rejected": summary.hitl_rejected,
        "hitl_not_required": summary.hitl_not_required,
    }
