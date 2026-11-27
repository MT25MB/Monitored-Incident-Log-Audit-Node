"""Stream alerts from a JSONL dataset through the MILAN graph.

Replay is sequential and deliberate: each alert gets its own LangGraph thread,
is triaged read-only, and is completed with a recorded ``rejected`` HITL
decision. The graph already writes every paused/completed run and its step
traces to SQLite, so no extra audit write is needed here.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.agent.graph import build_graph, resume_triage, start_triage
from src.schemas import SecurityAlert

__all__ = ["ReplayRecord", "ReplaySummary", "iter_replay_alerts", "replay_dataset"]


@dataclass(frozen=True)
class ReplayRecord:
    """One alert selected for replay, with its dataset metadata."""

    alert: SecurityAlert
    case_id: str
    source: str
    adversarial: bool


@dataclass(frozen=True)
class ReplaySummary:
    """Aggregate result of a replay run."""

    total: int = 0
    counts: dict[str, int] | None = None
    adversarial_count: int = 0
    errors: int = 0
    records: tuple[dict[str, Any], ...] = ()


def iter_replay_alerts(
    dataset: str | Path,
    *,
    source: str | None = None,
    adversarial_only: bool = False,
    limit: int | None = None,
) -> Iterator[ReplayRecord]:
    """Yield alerts in file order, applying optional filters.

    Records may be bare ``SecurityAlert`` objects or benchmark cases with an
    ``alert`` wrapper and ``expected.injection_expected`` flag.
    """
    if limit is not None and limit < 1:
        raise ValueError("limit must be >= 1")

    selected = 0
    with Path(dataset).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON: {exc}") from exc

            alert_payload = payload.get("alert", payload) if isinstance(payload, dict) else payload
            try:
                alert = SecurityAlert.model_validate(alert_payload)
            except Exception as exc:
                raise ValueError(f"line {line_number}: invalid alert: {exc}") from exc

            expected = payload.get("expected") or {} if isinstance(payload, dict) else {}
            record = ReplayRecord(
                alert=alert,
                case_id=str(payload.get("case_id", alert.alert_id))
                if isinstance(payload, dict)
                else alert.alert_id,
                source=alert.source,
                adversarial=bool(expected.get("injection_expected", False)),
            )

            if source and record.source != source:
                continue
            if adversarial_only and not record.adversarial:
                continue

            yield record
            selected += 1
            if limit is not None and selected >= limit:
                return


def replay_dataset(
    dataset: str | Path,
    *,
    delay_sec: float = 0.0,
    source: str | None = None,
    adversarial_only: bool = False,
    limit: int | None = None,
    db_path: str | None = None,
    audit_db_path: str | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    on_record: Callable[[int, dict[str, Any]], None] | None = None,
) -> ReplaySummary:
    """Replay selected alerts sequentially and collect a compact summary."""
    if delay_sec < 0:
        raise ValueError("delay_sec must be >= 0")

    graph = build_graph(db_path=db_path, audit_db_path=audit_db_path)
    records: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    adversarial_count = 0
    errors = 0

    for index, item in enumerate(
        iter_replay_alerts(dataset, source=source, adversarial_only=adversarial_only, limit=limit),
        start=1,
    ):
        if index > 1 and delay_sec:
            sleep_fn(delay_sec)
        if item.adversarial:
            adversarial_count += 1

        thread_id = f"replay-{uuid.uuid4().hex[:8]}"
        try:
            start_triage(graph, item.alert, thread_id)
            final = resume_triage(graph, thread_id, "rejected", decided_by="replay-harness")
            report = final["report"]
            verdict = report.classification.value
            counts[verdict] = counts.get(verdict, 0) + 1
            traces = final.get("traces", [])
            row: dict[str, Any] = {
                "case_id": item.case_id,
                "alert_id": item.alert.alert_id,
                "source": item.source,
                "adversarial": item.adversarial,
                "verdict": verdict,
                "severity": report.severity.value,
                "mitre": [mapping.technique_id for mapping in report.mitre],
                "injection_detected": bool(final.get("injection_detected")),
                "tool_calls": final.get("tool_calls", 0),
                "latency_ms": round(sum(float(trace.latency_ms) for trace in traces), 3),
                "cost_usd": sum(float(trace.estimated_cost_usd) for trace in traces),
                "hitl_decision": final.get("hitl_decision"),
            }
        except Exception as exc:
            errors += 1
            row = {
                "case_id": item.case_id,
                "alert_id": item.alert.alert_id,
                "source": item.source,
                "adversarial": item.adversarial,
                "error": f"{type(exc).__name__}: {exc}",
            }

        records.append(row)
        if on_record is not None:
            on_record(index, row)

    return ReplaySummary(
        total=len(records),
        counts=counts,
        adversarial_count=adversarial_count,
        errors=errors,
        records=tuple(records),
    )
