"""Export a completed MILAN run as a schema-validated JSON bundle.

The export contains the triage report, the deterministic correlation summary,
HITL decision metadata, and step traces. It deliberately excludes raw log
payloads and runs the same secret/PII redaction used before LLM calls over the
free-text fields, so an export cannot leak credentials from a synthetic alert.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field, field_validator

from src.agent.correlator import CorrelationSummary, correlate
from src.guardrails.sanitizer import redact_secrets
from src.schemas import StepTrace, TriageReport

__all__ = [
    "SCHEMA_VERSION",
    "ExportBundle",
    "HitlAction",
    "HitlMetadata",
    "build_export",
    "scrub_text",
    "write_export",
]


SCHEMA_VERSION = "1.0"
_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPORT_DIR = _ROOT / "data" / "exports"


class HitlAction(BaseModel):
    """One containment action as it stood after human review."""

    action: str
    target: str
    approval_status: str
    decided_by: str | None = None
    decided_at: datetime | None = None


class HitlMetadata(BaseModel):
    """Who decided, what they decided, and which actions were involved."""

    decision: str | None = None
    reviewer: str | None = None
    actions: tuple[HitlAction, ...] = ()
    context: tuple[dict[str, Any], ...] = ()


class ExportBundle(BaseModel):
    """Complete, validated export of one investigation run."""

    schema_version: str = SCHEMA_VERSION
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    run_id: str
    alert_id: str
    report: TriageReport
    correlation: CorrelationSummary
    hitl: HitlMetadata
    traces: tuple[StepTrace, ...] = ()

    @field_validator("run_id", "alert_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("run_id and alert_id must be non-empty")
        return clean


def scrub_text(text: str) -> str:
    """Redact secret-like spans from free text included in an export."""
    return redact_secrets(text or "")[0]


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value).strip("._")[:80] or "run"


def build_export(
    state: Mapping[str, Any],
    *,
    run_id: str | None = None,
    exported_at: datetime | None = None,
) -> ExportBundle:
    """Build a validated export bundle from graph state.

    Raises:
        ValueError: if the state has no report to export.
    """
    report = state.get("report")
    if report is None:
        raise ValueError("cannot export a run without a TriageReport")

    correlation_raw = state.get("correlation_summary")
    if correlation_raw:
        correlation = CorrelationSummary.model_validate(correlation_raw)
    else:
        correlation = correlate(state.get("tool_results") or ())
    correlation = correlation.model_copy(
        update={"rationale": scrub_text(correlation.rationale)}
    )

    actions = tuple(
        HitlAction(
            action=action.action.value,
            target=action.target,
            approval_status=action.approval_status.value,
            decided_by=action.approved_by,
            decided_at=action.decided_at,
        )
        for action in report.recommended_actions
    )
    first_action = report.recommended_actions[0] if report.recommended_actions else None
    decision = state.get("hitl_decision")
    if decision is None and first_action is not None:
        status = first_action.approval_status.value
        decision = None if status == "pending" else status
    reviewer = state.get("reviewer") or (
        first_action.approved_by if first_action is not None else None
    )

    scrubbed_report = report.model_copy(
        update={
            "summary": scrub_text(report.summary),
            "evidence_summary": scrub_text(report.evidence_summary),
            "recommended_actions": [
                action.model_copy(update={"rationale": scrub_text(action.rationale)})
                for action in report.recommended_actions
            ],
        }
    )
    traces = tuple(
        StepTrace.model_validate(trace).model_copy(
            update={"error": scrub_text(trace.error) if trace.error else None}
        )
        for trace in state.get("traces") or ()
    )

    bundle = ExportBundle(
        exported_at=exported_at or datetime.now(timezone.utc),
        run_id=run_id or state.get("run_id") or uuid.uuid4().hex,
        alert_id=scrubbed_report.alert_id,
        report=scrubbed_report,
        correlation=correlation,
        hitl=HitlMetadata(
            decision=decision,
            reviewer=reviewer,
            actions=actions,
            context=tuple(state.get("hitl_context") or ()),
        ),
        traces=traces,
    )
    return bundle


def write_export(
    state: Mapping[str, Any],
    *,
    output_dir: str | Path = DEFAULT_EXPORT_DIR,
    filename: str | None = None,
    run_id: str | None = None,
) -> Path:
    """Write a validated JSON export and return its path."""
    bundle = build_export(state, run_id=run_id)
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    name = filename or f"{_safe_name(bundle.alert_id)}-{_safe_name(bundle.run_id)[:8]}.json"
    destination = directory / name
    destination.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return destination
