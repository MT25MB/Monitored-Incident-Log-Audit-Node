"""LangGraph triage state machine for MILAN.

Pipeline::

    ingest_and_sanitize -> plan_step <-> execute_tool -> synthesize -> hitl_gate -> END

``plan_step`` and ``execute_tool`` form a bounded investigation loop. No more
than :data:`MAX_INVESTIGATION_STEPS` read-only tool calls may be made per alert.
The graph is compiled with ``interrupt_before=["hitl_gate"]`` and a checkpointer,
so execution pauses for human review and resumes without losing any state.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import Any, Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

from src.config import LLMError, Settings, invoke_structured
from src.guardrails.sanitizer import sanitize
from src.monitoring.store import RunRecord, record_hitl_decisions, record_run
from src.schemas import (
    ApprovalStatus,
    Classification,
    ContainmentAction,
    ContainmentProposal,
    ExtractedIOCs,
    MitreMapping,
    SecurityAlert,
    StepTrace,
    TriageReport,
)
from src.tools.siem import (
    check_threat_intel,
    init_soc_db,
    lookup_asset_inventory,
    query_siem_logs,
)

__all__ = [
    "MAX_INVESTIGATION_STEPS",
    "TriageState",
    "build_graph",
    "resume_triage",
    "start_triage",
]

logger = logging.getLogger(__name__)

#: Hard cap on read-only tool calls for a single alert.
MAX_INVESTIGATION_STEPS = 6


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TriageState(BaseModel):
    """Mutable state carried between graph nodes.

    The sanitized payload is stored as plain text (not the sanitizer dataclass)
    so that any checkpointer can serialise it without custom hooks.
    """

    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    alert: SecurityAlert | None = None
    sanitized_payload: str | None = None
    trusted_system_instruction: str = ""
    injection_detected: bool = False
    injection_flags: list[dict[str, str]] = Field(default_factory=list)
    redaction_count: int = 0

    step: int = 0
    plan: str = ""
    next_action: dict[str, Any] | None = None
    tool_calls: int = 0
    tool_results: list[dict[str, Any]] = Field(default_factory=list)
    traces: list[StepTrace] = Field(default_factory=list)

    report: TriageReport | None = None
    human_decision: str | None = None
    decided_by: str | None = None
    hitl_decision: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Static lookup helpers (synthetic data only)
# ---------------------------------------------------------------------------

_MITRE_METADATA: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:example\.net|example\.com|example\.org)\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_HOSTNAME_RE = re.compile(r"\b(?:WS|SRV|DC)-[A-Z]+-\d+\b")


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text or "")
    return match.group(0) if match else None


def _first_hostname(state: TriageState) -> str | None:
    """Prefer the structured alert field, then scan the sanitized payload."""
    if state.alert and state.alert.hostname:
        return state.alert.hostname
    return _first_match(_HOSTNAME_RE, state.sanitized_payload or "")


def _max_confidence(rows: list[dict[str, Any]]) -> float:
    values = [float(row.get("confidence") or 0.0) for row in rows]
    return max(values, default=0.0)


def _intel_rows(state: TriageState) -> list[dict[str, Any]]:
    return [
        row
        for item in state.tool_results
        if item.get("tool") == "check_threat_intel"
        for row in item.get("rows", [])
    ]


def _evidence_rows(state: TriageState, tool_name: str) -> list[dict[str, Any]]:
    return [
        row
        for item in state.tool_results
        if item.get("tool") == tool_name
        for row in item.get("rows", [])
    ]


# ---------------------------------------------------------------------------
# Telemetry helper
# ---------------------------------------------------------------------------


def _trace(
    step: int,
    name: str,
    started: float,
    *,
    success: bool = True,
    error: str | None = None,
) -> StepTrace:
    """Create a token-free StepTrace for a local graph node."""
    return StepTrace(
        step=step,
        name=name,
        latency_ms=round((time.perf_counter() - started) * 1000.0, 3),
        attempts=1,
        success=success and error is None,
        error=error,
    )


def _persist_run(
    state: TriageState,
    report: TriageReport,
    *,
    status: str,
    decision: str | None = None,
    db_path: str | Path | None = None,
) -> None:
    """Upsert run telemetry. Monitoring must never break triage."""
    try:
        traces = list(report.traces) or list(state.traces)
        record_run(
            RunRecord(
                run_id=state.run_id,
                alert_id=report.alert_id,
                verdict=report.classification.value,
                severity=report.severity.value,
                injection_detected=state.injection_detected,
                total_latency_ms=round(sum(trace.latency_ms for trace in traces), 3),
                step_count=state.step,
                provider_used=next(
                    (trace.provider for trace in traces if trace.provider), "local"
                ),
                fallback_count=sum(1 for trace in traces if trace.fallback_from),
                traces_json=json.dumps(
                    [trace.model_dump(mode="json") for trace in traces]
                ),
                status=status,
                hitl_decision=decision,
            ),
            db_path=db_path,
        )
    except Exception as exc:  # pragma: no cover - monitoring is best-effort
        logger.warning("could not persist run %s: %s", state.run_id, exc)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def ingest_and_sanitize(state: TriageState, *, db_path: str | None = None) -> dict[str, Any]:
    """Initialise the local DB and sanitize the alert payload before LLM use."""
    started = time.perf_counter()
    if state.alert is None:
        error = "no SecurityAlert supplied to the graph"
        return {
            "error": error,
            "traces": state.traces + [_trace(0, "ingest_and_sanitize", started, success=False, error=error)],
        }

    init_soc_db(db_path)
    sanitized = sanitize(state.alert.raw_payload)
    return {
        "run_id": state.run_id,
        "sanitized_payload": sanitized.text,
        "trusted_system_instruction": sanitized.trusted_system_instruction(),
        "injection_detected": sanitized.injection_detected,
        "injection_flags": [asdict(finding) for finding in sanitized.injections],
        "redaction_count": sanitized.redaction_count,
        "traces": state.traces + [_trace(0, "ingest_and_sanitize", started)],
    }


def _next_action(state: TriageState) -> dict[str, Any] | None:
    """Deterministically choose the next read-only investigation step."""
    payload = state.sanitized_payload or ""
    alert = state.alert

    if state.step == 0 and alert is not None:
        return {
            "tool": "query_siem_logs",
            "args": {"alert_id": alert.alert_id},
            "description": "Collect all SIEM events for the alert",
        }
    if state.step == 1:
        indicator = (
            _first_match(_HASH_RE, payload)
            or _first_match(_DOMAIN_RE, payload)
            or _first_match(_IP_RE, payload)
        )
        if indicator:
            return {
                "tool": "check_threat_intel",
                "args": {"indicator": indicator},
                "description": f"Check threat intel for {indicator}",
            }
    if state.step == 2:
        hostname = _first_hostname(state)
        if hostname:
            return {
                "tool": "lookup_asset_inventory",
                "args": {"hostname": hostname},
                "description": f"Look up asset criticality for {hostname}",
            }
    if state.step == 3:
        hostname = _first_hostname(state)
        if hostname:
            return {
                "tool": "query_siem_logs",
                "args": {"hostname": hostname},
                "description": f"Correlate additional events for {hostname}",
            }
    return None


def plan_step(state: TriageState) -> dict[str, Any]:
    """Select the next bounded, read-only tool action."""
    started = time.perf_counter()
    if state.error or state.tool_calls >= MAX_INVESTIGATION_STEPS:
        return {"next_action": None, "plan": "investigation complete or aborted"}

    action = _next_action(state)
    description = action["description"] if action else "no further tools needed"
    return {
        "step": state.step + 1,
        "next_action": action,
        "plan": description,
        "traces": state.traces + [_trace(state.step + 1, "plan_step", started)],
    }


def execute_tool(
    state: TriageState,
    *,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Execute the planned read-only tool and append its result and trace."""
    started = time.perf_counter()
    action = state.next_action
    if not action:
        return {"traces": state.traces + [_trace(state.step, "execute_tool", started)]}

    tool_name = str(action.get("tool", ""))
    args = dict(action.get("args") or {})
    dispatch: dict[str, Callable[..., Any]] = {
        "query_siem_logs": query_siem_logs,
        "check_threat_intel": check_threat_intel,
        "lookup_asset_inventory": lookup_asset_inventory,
    }
    tool = dispatch.get(tool_name)
    if tool is None:
        error = f"blocked unauthorised tool: {tool_name!r}"
        return {
            "tool_calls": state.tool_calls + 1,
            "traces": state.traces + [_trace(state.step, "execute_tool", started, success=False, error=error)],
        }

    result = tool(step=state.step, db_path=db_path, **args)
    return {
        "tool_calls": state.tool_calls + 1,
        "tool_results": state.tool_results
        + [
            {
                "tool": tool_name,
                "args": args,
                "rows": list(result.rows),
                "count": result.count,
            }
        ],
        "traces": state.traces + [result.trace],
    }


def _build_mitre(state: TriageState) -> list[MitreMapping]:
    """Derive validated MITRE mappings from log and intel evidence."""
    techniques: list[str] = []
    for row in _evidence_rows(state, "query_siem_logs") + _intel_rows(state):
        technique = row.get("mitre_technique")
        if isinstance(technique, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            if technique not in techniques:
                techniques.append(technique)

    mappings: list[MitreMapping] = []
    for technique in techniques:
        name, tactic = _MITRE_METADATA.get(technique, (f"Technique {technique}", "Unknown"))
        mappings.append(
            MitreMapping(
                technique_id=technique,
                technique_name=name,
                tactic=tactic,
                confidence=0.85,
            )
        )
    return mappings


def _build_evidence_summary(state: TriageState) -> str:
    """Build a factual summary using only values returned by the read-only tools."""
    parts: list[str] = []
    for item in state.tool_results:
        for row in item.get("rows", []):
            if "log_id" in row:
                parts.append(
                    f"log {row['log_id']} from {row.get('source')} on "
                    f"{row.get('hostname')} with technique {row.get('mitre_technique')}"
                )
            elif "indicator" in row:
                parts.append(
                    f"indicator {row['indicator']} ({row.get('indicator_type')}) "
                    f"confidence {row.get('confidence')}"
                )
            elif "hostname" in row:
                parts.append(
                    f"asset {row['hostname']} ({row.get('ip_address')}) "
                    f"criticality {row.get('criticality')}"
                )
    return " ".join(parts) if parts else "No tool evidence collected."


def _build_proposals(
    state: TriageState,
    classification: Classification,
    confidence: float,
) -> list[ContainmentProposal]:
    """Create HITL-gated containment proposals for non-benign findings."""
    if classification is Classification.BENIGN:
        return []

    proposals: list[ContainmentProposal] = []
    payload = state.sanitized_payload or ""
    target_ip = (state.alert.source_ip if state.alert else None) or _first_match(_IP_RE, payload)
    if target_ip:
        proposals.append(
            ContainmentProposal(
                action=ContainmentAction.BLOCK_IP,
                target=target_ip,
                rationale=(
                    f"Threat-intel correlation confidence {confidence:.2f}; "
                    "requires human approval before blocking"
                ),
            )
        )

    hostname = _first_hostname(state)
    if hostname:
        proposals.append(
            ContainmentProposal(
                action=ContainmentAction.ISOLATE_HOST,
                target=hostname,
                rationale="Suspicious activity observed on this asset; human approval required",
            )
        )
    return proposals


def synthesize(
    state: TriageState,
    *,
    enrich_with_llm: bool = False,
    settings: Settings | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Produce a validated :class:`TriageReport` from collected evidence."""
    started = time.perf_counter()
    if state.alert is None:
        error = "cannot synthesize without an alert"
        return {
            "error": error,
            "traces": state.traces + [_trace(state.step, "synthesize", started, success=False, error=error)],
        }

    intel = _intel_rows(state)
    max_confidence = _max_confidence(intel)
    if max_confidence >= 0.8:
        classification = Classification.MALICIOUS
    elif state.injection_detected or max_confidence >= 0.3:
        classification = Classification.SUSPICIOUS
    else:
        classification = Classification.BENIGN

    confidence = round(min(0.99, max(max_confidence, 0.35)), 2)
    payload_text = state.sanitized_payload or ""
    first_ip = _first_match(_IP_RE, payload_text)
    first_domain = _first_match(_DOMAIN_RE, payload_text)
    first_hash = _first_match(_HASH_RE, payload_text)
    iocs = ExtractedIOCs(
        ip_addresses=[first_ip] if first_ip else [],
        domains=[first_domain] if first_domain else [],
        file_hashes=[first_hash] if first_hash else [],
    )

    mitre = _build_mitre(state)
    proposals = _build_proposals(state, classification, confidence)

    parts = [
        f"Alert {state.alert.alert_id} classified as {classification.value} "
        f"after {state.tool_calls} read-only tool calls."
    ]
    if state.injection_detected:
        parts.append("Prompt-injection indicators were detected and isolated in the raw payload.")
    if max_confidence:
        parts.append(f"Peak threat-intel confidence: {max_confidence:.2f}.")
    if not state.tool_results:
        parts.append("No tool evidence was collected.")
    summary = " ".join(parts)

    traces = state.traces + [_trace(state.step, "synthesize", started)]
    evidence_summary = _build_evidence_summary(state)
    report = TriageReport(
        alert_id=state.alert.alert_id,
        classification=classification,
        severity=state.alert.severity,
        confidence=confidence,
        summary=summary,
        evidence_summary=evidence_summary,
        iocs=iocs,
        mitre=mitre,
        recommended_actions=proposals,
        step_count=state.step,
        traces=traces,
    )

    if enrich_with_llm:
        try:
            result = invoke_structured(
                TriageReport,
                system_prompt=(
                    "You are a SOC triage analyst. Refine the classification, "
                    "confidence, summary, and MITRE mapping using the evidence."
                ),
                user_prompt=json.dumps(
                    {
                        "classification": classification.value,
                        "confidence": confidence,
                        "summary": summary,
                        "mitre": [item.model_dump(mode="json") for item in mitre],
                        "evidence": state.tool_results,
                    },
                    default=str,
                ),
                untrusted_payload=state.alert.raw_payload,
                step=state.step,
                step_name="synthesize_llm",
                settings=settings,
                sink=MemorySink(),
            )
            llm_traces = traces + [result.trace]
            report = result.data.model_copy(
                update={
                    "alert_id": state.alert.alert_id,
                    "evidence_summary": evidence_summary,
                    "recommended_actions": proposals,
                    "step_count": state.step,
                    "traces": llm_traces,
                }
            )
            traces = llm_traces
        except LLMError as exc:
            traces = traces + [
                _trace(state.step, "synthesize_llm", started, success=False, error=str(exc))
            ]
            report = report.model_copy(update={"traces": traces})

    _persist_run(state, report, status="paused", db_path=audit_db_path)
    return {"report": report, "traces": traces}


class MemorySink:
    """Disposable telemetry sink for optional LLM enrichment."""

    def __init__(self) -> None:
        self.traces: list[StepTrace] = []

    def record(self, trace: StepTrace) -> None:
        self.traces.append(trace)


def hitl_gate(
    state: TriageState, *, audit_db_path: str | Path | None = None
) -> dict[str, Any]:
    """Apply the human approval/rejection after the graph resumes.

    An absent or invalid decision is treated as **rejected** — a fail-safe that
    prevents containment actions from executing by default.
    """
    started = time.perf_counter()
    raw = (state.human_decision or "rejected").strip().lower()
    decision = raw if raw in {"approved", "rejected"} else "rejected"
    status = ApprovalStatus.APPROVED if decision == "approved" else ApprovalStatus.REJECTED
    decided_by = (state.decided_by or "unknown").strip() or "unknown"

    report = state.report
    if report is not None:
        decided_actions = [
            action.with_decision(status, decided_by=decided_by)
            for action in report.recommended_actions
        ]
        report = report.model_copy(update={"recommended_actions": decided_actions})
        hitl_decision = decision if decided_actions else "not_required"
    else:
        hitl_decision = "not_required"

    traces = state.traces + [_trace(state.step + 1, "hitl_gate", started)]
    if report is not None:
        report = report.model_copy(update={"traces": traces})
        _persist_run(
            state,
            report,
            status="completed",
            decision=hitl_decision,
            db_path=audit_db_path,
        )
        try:
            first_action = report.recommended_actions[0] if report.recommended_actions else None
            record_hitl_decisions(
                run_id=state.run_id,
                alert_id=report.alert_id,
                actions=report.recommended_actions,
                decision=decision,
                reviewer=decided_by,
                decided_at=(
                    first_action.decided_at.isoformat()
                    if first_action is not None and first_action.decided_at
                    else None
                ),
                db_path=audit_db_path,
            )
        except Exception as exc:  # pragma: no cover - audit is best-effort
            logger.warning("could not record HITL audit for %s: %s", state.run_id, exc)

    return {
        "report": report,
        "hitl_decision": hitl_decision,
        "traces": traces,
    }


# ---------------------------------------------------------------------------
# Routing and graph construction
# ---------------------------------------------------------------------------


def _route_after_plan(state: TriageState) -> str:
    """Continue the bounded loop or move to synthesis."""
    if state.error or state.next_action is None:
        return "synthesize"
    if state.tool_calls >= MAX_INVESTIGATION_STEPS or state.step >= MAX_INVESTIGATION_STEPS:
        return "synthesize"
    return "execute_tool"


#: Types stored in checkpointed state. Explicitly allowlisted so future
#: LangGraph versions do not need unrestricted object deserialization.
_SERIALISABLE_TYPES: tuple[str, ...] = (
    "Severity",
    "SecurityAlert",
    "StepTrace",
    "Classification",
    "ContainmentAction",
    "ApprovalStatus",
    "TriageReport",
    "ContainmentProposal",
    "ExtractedIOCs",
    "MitreMapping",
)


def _default_checkpointer() -> Any:
    """Create an in-memory checkpointer with an explicit type allowlist."""
    try:
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

        serde = JsonPlusSerializer(
            allowed_msgpack_modules=[("src.schemas", name) for name in _SERIALISABLE_TYPES]
        )
        return MemorySaver(serde=serde)
    except (ImportError, TypeError):
        # Older LangGraph releases do not expose allowed_msgpack_modules.
        return MemorySaver()


def build_graph(
    checkpointer: Any | None = None,
    *,
    enrich_with_llm: bool = False,
    settings: Settings | None = None,
    db_path: str | None = None,
    audit_db_path: str | Path | None = None,
) -> Any:
    """Build and compile the MILAN triage graph.

    Args:
        checkpointer: LangGraph checkpointer. Defaults to in-memory, which is
            sufficient for local runs; supply a durable one for production.
        enrich_with_llm: Optionally refine the report via the free-tier LLM
            chain. Disabled by default so the pipeline is fully offline-capable.
        settings: Settings used for optional LLM enrichment.
        db_path: Optional DuckDB path override for the read-only tools.
        audit_db_path: Optional SQLite audit database override.

    Returns:
        A compiled graph paused before ``hitl_gate`` for human review.
    """
    builder = StateGraph(TriageState)
    builder.add_node("ingest_and_sanitize", partial(ingest_and_sanitize, db_path=db_path))
    builder.add_node("plan_step", plan_step)
    builder.add_node("execute_tool", partial(execute_tool, db_path=db_path))
    builder.add_node(
        "synthesize",
        partial(
            synthesize,
            enrich_with_llm=enrich_with_llm,
            settings=settings,
            audit_db_path=audit_db_path,
        ),
    )
    builder.add_node("hitl_gate", partial(hitl_gate, audit_db_path=audit_db_path))

    builder.set_entry_point("ingest_and_sanitize")
    builder.add_edge("ingest_and_sanitize", "plan_step")
    builder.add_conditional_edges(
        "plan_step",
        _route_after_plan,
        {"execute_tool": "execute_tool", "synthesize": "synthesize"},
    )
    builder.add_edge("execute_tool", "plan_step")
    builder.add_edge("synthesize", "hitl_gate")
    builder.add_edge("hitl_gate", END)

    return builder.compile(
        checkpointer=checkpointer or _default_checkpointer(),
        interrupt_before=["hitl_gate"],
    )


def _thread_config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}}


def start_triage(graph: Any, alert: SecurityAlert, thread_id: str) -> dict[str, Any]:
    """Run an alert up to (but not including) the HITL checkpoint."""
    return graph.invoke({"alert": alert}, config=_thread_config(thread_id))


def resume_triage(
    graph: Any,
    thread_id: str,
    decision: str,
    *,
    decided_by: str,
) -> dict[str, Any]:
    """Resume a paused graph with a human approval or rejection."""
    config = _thread_config(thread_id)
    graph.update_state(config, {"human_decision": decision, "decided_by": decided_by})
    return graph.invoke(None, config=config)
