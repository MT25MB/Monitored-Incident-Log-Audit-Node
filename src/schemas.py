"""Pydantic domain schemas for MILAN.

These models are the contract between the LangGraph nodes, the guardrails, and
the evaluation harness. They intentionally use ``extra="forbid"`` so that
unexpected keys in LLM-generated structured output are rejected rather than
silently ignored — a small but useful defence against prompt-injection payloads
that try to smuggle extra fields into a report.

All text fields that may originate from a log are marked as untrusted in their
docstrings. They must be passed through
:func:`src.guardrails.sanitizer.sanitize` before being sent to an external LLM.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "ApprovalStatus",
    "Classification",
    "ContainmentAction",
    "ContainmentProposal",
    "ExtractedIOCs",
    "MitreMapping",
    "SecurityAlert",
    "Severity",
    "StepTrace",
    "TriageReport",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Alert severity, aligned with common SOC triage vocabulary."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(str, Enum):
    """Final disposition of an alert after triage."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ApprovalStatus(str, Enum):
    """Human-in-the-loop decision state for a containment proposal."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ContainmentAction(str, Enum):
    """Actions that change state and therefore require HITL approval."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    REVOKE_TOKEN = "revoke_token"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: MITRE ATT&CK technique IDs: ``T1059`` or sub-technique ``T1059.001``.
MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Alert and IOC models
# ---------------------------------------------------------------------------


class SecurityAlert(BaseModel):
    """A single SOC alert ingested from the local mock SIEM.

    ``raw_payload`` is **untrusted data**. Treat it as opaque text; never
    interpolate it into a trusted system prompt without sanitization.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alert_id: str = Field(..., min_length=1, description="Stable identifier for this alert")
    timestamp: datetime = Field(default_factory=_utc_now)
    severity: Severity
    source: str = Field(default="mock-siem", description="Emitting system (mock in MILAN)")
    title: str = Field(..., min_length=1)
    raw_payload: str = Field(
        ...,
        description="UNTRUSTED raw log payload; sanitize before any LLM call",
    )
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalise_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        seen: set[str] = set()
        result: list[str] = []
        for tag in value:
            if not isinstance(tag, str):
                continue
            clean = tag.strip()
            if clean and clean not in seen:
                seen.add(clean)
                result.append(clean)
        return result


class ExtractedIOCs(BaseModel):
    """Indicators of compromise extracted from a sanitized alert payload."""

    model_config = ConfigDict(extra="forbid")

    ip_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)

    @field_validator(
        "ip_addresses",
        "domains",
        "urls",
        "file_hashes",
        "email_addresses",
        "file_paths",
        mode="before",
    )
    @classmethod
    def _dedupe(cls, value: Any) -> list[str]:
        """Coerce to a de-duplicated list of stripped strings, preserving order."""
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        seen: set[str] = set()
        result: list[str] = []
        for item in value:
            if not isinstance(item, str):
                continue
            clean = item.strip()
            if clean and clean not in seen:
                seen.add(clean)
                result.append(clean)
        return result

    @property
    def total(self) -> int:
        """Total number of indicators across all categories."""
        return sum(
            len(items)
            for items in (
                self.ip_addresses,
                self.domains,
                self.urls,
                self.file_hashes,
                self.email_addresses,
                self.file_paths,
            )
        )


class MitreMapping(BaseModel):
    """A single MITRE ATT&CK technique attribution.

    ``technique_id`` must match ``T####`` or ``T####.###`` (case-insensitive on
    input, normalized to upper case). This prevents free-form or malformed IDs
    from reaching the evaluation grader.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK ID, e.g. T1059 or T1059.001",
    )
    technique_name: str = Field(..., min_length=1)
    tactic: str = Field(..., min_length=1)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    @field_validator("technique_id", mode="before")
    @classmethod
    def _validate_technique_id(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("technique_id must be a string")
        normalised = value.strip().upper()
        if not MITRE_TECHNIQUE_RE.fullmatch(normalised):
            raise ValueError(
                f"invalid MITRE technique ID {value!r}; expected 'T####' or 'T####.###'"
            )
        return normalised


# ---------------------------------------------------------------------------
# Containment and telemetry models
# ---------------------------------------------------------------------------


class ContainmentProposal(BaseModel):
    """A proposed state-changing action, always gated behind a human decision.

    ``requires_hitl`` is a ``Literal[True]``: it is impossible to construct a
    proposal that claims not to need approval. An action may only be executed
    once ``approval_status`` is ``approved`` (see :attr:`is_executable`).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: ContainmentAction
    target: str = Field(..., min_length=1, description="Host, IP, account, or token to act on")
    rationale: str = Field(default="", max_length=2000)
    requires_hitl: Literal[True] = Field(
        default=True,
        frozen=True,
        description="Immutable: containment always requires human approval",
    )
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: str | None = None
    decided_at: datetime | None = None

    @model_validator(mode="after")
    def _enforce_hitl(self) -> ContainmentProposal:
        if self.requires_hitl is not True:  # defensive; Literal[True] already enforces this
            raise ValueError("containment proposals must always require HITL")
        return self

    @property
    def is_executable(self) -> bool:
        """True only after an explicit human approval."""
        return self.approval_status is ApprovalStatus.APPROVED and self.requires_hitl is True

    def with_decision(
        self,
        status: ApprovalStatus,
        *,
        decided_by: str,
        decided_at: datetime | None = None,
    ) -> ContainmentProposal:
        """Return a copy carrying a human approval or rejection decision."""
        if status is ApprovalStatus.PENDING:
            raise ValueError("a decision must be APPROVED or REJECTED, not PENDING")
        if not decided_by.strip():
            raise ValueError("decided_by is required for auditability")
        return self.model_copy(
            update={
                "approval_status": status,
                "approved_by": decided_by.strip(),
                "decided_at": decided_at or _utc_now(),
            }
        )


class StepTrace(BaseModel):
    """Observability record for one pipeline step or one LLM invocation."""

    model_config = ConfigDict(extra="forbid")

    step: int = Field(..., ge=0, description="Zero-based step index within the alert run")
    name: str = Field(..., min_length=1, description="Human-readable step name")
    provider: str | None = None
    model: str | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float = Field(
        default=0.0,
        ge=0.0,
        description="Always 0.0 on free tiers; reserved for future accounting",
    )
    fallback_from: str | None = Field(
        default=None,
        description="Provider name that failed before this one succeeded",
    )
    fallback_triggered: bool = Field(
        default=False,
        description="True when an earlier provider failed and another was tried",
    )
    attempts: int = Field(default=1, ge=1)
    tool_name: str | None = None
    redaction_count: int = Field(default=0, ge=0)
    injection_detected: bool = False
    success: bool = True
    error: str | None = None

    @property
    def total_tokens(self) -> int:
        """Prompt plus completion tokens for this step."""
        return self.input_tokens + self.output_tokens


class TriageReport(BaseModel):
    """Final structured output of the triage graph for one alert."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alert_id: str = Field(..., min_length=1)
    classification: Classification
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., min_length=1)
    evidence_summary: str = Field(
        default="",
        description="Factual observations taken verbatim from read-only tool results",
    )
    iocs: ExtractedIOCs = Field(default_factory=ExtractedIOCs)
    mitre: list[MitreMapping] = Field(default_factory=list)
    recommended_actions: list[ContainmentProposal] = Field(default_factory=list)
    step_count: int = Field(default=0, ge=0)
    traces: list[StepTrace] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=_utc_now)

    @field_validator("mitre", mode="before")
    @classmethod
    def _dedupe_mitre(cls, value: Any) -> list[Any]:
        """Drop duplicate technique IDs while preserving the first occurrence."""
        if value is None:
            return []
        seen: set[str] = set()
        result: list[Any] = []
        for item in value:
            key = item.get("technique_id") if isinstance(item, dict) else getattr(item, "technique_id", None)
            if isinstance(key, str):
                key = key.strip().upper()
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @model_validator(mode="after")
    def _check_action_gate(self) -> TriageReport:
        for action in self.recommended_actions:
            if action.requires_hitl is not True:
                raise ValueError("every containment proposal must require HITL")
        return self

    @property
    def executable_actions(self) -> list[ContainmentProposal]:
        """Actions that have passed human review and may be executed."""
        return [action for action in self.recommended_actions if action.is_executable]
