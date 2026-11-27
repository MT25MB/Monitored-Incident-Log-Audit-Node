"""Shift handoff built from the local audit store.

The summary answers three questions a incoming analyst has: what finished,
what is still waiting for a person, and which alerts carried injection attempts.
It reads only the SQLite audit store and writes nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from src.monitoring.store import get_hitl_audit, get_recent_runs, init_audit_db

__all__ = ["HandoffSummary", "build_handoff", "render_handoff"]


@dataclass(frozen=True)
class HandoffSummary:
    """Facts collected for one shift handoff."""

    completed: tuple[dict[str, Any], ...] = ()
    pending: tuple[dict[str, Any], ...] = ()
    injections: tuple[dict[str, Any], ...] = ()
    decisions: tuple[dict[str, Any], ...] = ()


def _decode_pending(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in value if isinstance(item, dict)]


def build_handoff(*, db_path: str | Path | None = None, limit: int = 50) -> HandoffSummary:
    """Collect completed runs, pending actions, and injection flags."""
    if limit < 1:
        raise ValueError("limit must be >= 1")
    init_audit_db(db_path)
    runs = get_recent_runs(limit=limit, db_path=db_path)

    completed: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    injections: list[dict[str, Any]] = []

    for run in runs:
        if run.get("status") == "completed":
            completed.append(run)
        if run.get("status") == "paused":
            for action in _decode_pending(run.get("pending_actions_json")):
                if action.get("approval_status") == "pending":
                    pending.append(
                        {
                            "alert_id": run.get("alert_id"),
                            "action": action.get("action"),
                            "target": action.get("target"),
                        }
                    )
        if run.get("injection_detected"):
            injections.append(
                {
                    "alert_id": run.get("alert_id"),
                    "verdict": run.get("verdict"),
                    "timestamp": run.get("timestamp"),
                }
            )

    decisions = tuple(
        {
            "alert_id": entry.alert_id,
            "action": entry.action_type,
            "target": entry.target,
            "decision": entry.decision,
            "reviewer": entry.reviewer,
            "decided_at": entry.decided_at,
        }
        for entry in get_hitl_audit(limit=limit, db_path=db_path)
    )
    return HandoffSummary(
        completed=tuple(completed),
        pending=tuple(pending),
        injections=tuple(injections),
        decisions=decisions,
    )


def render_handoff(
    summary: HandoffSummary,
    *,
    fmt: Literal["markdown", "text"] = "markdown",
) -> str:
    """Render a concise, human-readable handoff."""
    lines: list[str] = []
    heading = "# SOC shift handoff" if fmt == "markdown" else "SOC shift handoff"
    lines.append(heading)

    lines.append("" if fmt == "markdown" else "")
    lines.append("## Completed triage" if fmt == "markdown" else "Completed triage")
    if summary.completed:
        for run in summary.completed:
            lines.append(
                f"- {run.get('alert_id')}: {run.get('verdict')}, "
                f"{run.get('severity')} severity, "
                f"{run.get('tool_calls', run.get('step_count', 0))} steps, "
                f"{float(run.get('total_latency_ms') or 0):.1f} ms"
            )
    else:
        lines.append("- No completed triage runs in this window.")

    lines.append("" if fmt == "markdown" else "")
    lines.append("## Waiting on HITL" if fmt == "markdown" else "Waiting on HITL")
    if summary.pending:
        for item in summary.pending:
            lines.append(
                f"- {item.get('alert_id', 'unknown')}: "
                f"{item.get('action', 'unspecified action')} on "
                f"{item.get('target', 'unspecified target')} "
                "is pending a human decision"
            )
    else:
        lines.append("- No containment actions are waiting for approval.")

    lines.append("" if fmt == "markdown" else "")
    lines.append("## Prompt-injection flags" if fmt == "markdown" else "Prompt-injection flags")
    if summary.injections:
        for item in summary.injections:
            lines.append(
                f"- {item.get('alert_id', 'unknown')}: injection detected, "
                f"verdict {item.get('verdict', 'unknown')}"
            )
    else:
        lines.append("- No injection attempts were flagged.")

    lines.append("" if fmt == "markdown" else "")
    lines.append("## Recent decisions" if fmt == "markdown" else "Recent decisions")
    if summary.decisions:
        for item in summary.decisions[:10]:
            lines.append(
                f"- {item.get('alert_id', 'unknown')}: "
                f"{item.get('action', 'unspecified action')} on "
                f"{item.get('target', 'unspecified target')} "
                f"{item.get('decision', 'unknown')} by "
                f"{item.get('reviewer', 'unknown')}"
            )
    else:
        lines.append("- No human decisions were recorded in this window.")

    return "\n".join(lines).rstrip() + "\n"
