"""SQLite-backed run telemetry and append-only HITL audit log.

Every paused or completed investigation run is upserted into
``investigation_runs``. Every human approval/rejection is written to
``hitl_audit_log`` with ``INSERT OR IGNORE`` on a deterministic audit id, so
retries cannot create duplicate entries and the table is never updated or
deleted from.

The default database lives at ``data/milan_audit.db`` in the project root.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

__all__ = [
    "HITLAuditEntry",
    "MonitoringMetrics",
    "RunRecord",
    "get_hitl_audit",
    "get_recent_runs",
    "get_run_metrics",
    "init_audit_db",
    "record_hitl_decisions",
    "record_run",
    "traces_from_json",
]


_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = _ROOT / "data" / "milan_audit.db"


def _resolve_path(db_path: str | Path | None) -> Path:
    raw = db_path if db_path is not None else os.getenv("MILAN_AUDIT_DB", str(DEFAULT_DB_PATH))
    return Path(raw).expanduser().resolve()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# Record types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunRecord:
    """One persisted investigation run."""

    run_id: str
    alert_id: str
    timestamp: str = field(default_factory=_utc_now)
    verdict: str | None = None
    severity: str | None = None
    injection_detected: bool = False
    total_latency_ms: float = 0.0
    step_count: int = 0
    provider_used: str | None = None
    fallback_count: int = 0
    traces_json: str = "[]"
    pending_actions_json: str = "[]"
    status: str = "paused"
    hitl_decision: str | None = None

    def params(self) -> tuple[Any, ...]:
        """Return values in column order for insertion."""
        return (
            self.run_id,
            self.alert_id,
            self.timestamp,
            self.verdict,
            self.severity,
            int(self.injection_detected),
            float(self.total_latency_ms),
            int(self.step_count),
            self.provider_used,
            int(self.fallback_count),
            self.traces_json,
            self.pending_actions_json,
            self.status,
            self.hitl_decision,
        )


@dataclass(frozen=True)
class HITLAuditEntry:
    """One immutable human decision row."""

    audit_id: str
    alert_id: str
    action_type: str
    target: str
    decision: str
    reviewer: str
    decided_at: str


@dataclass(frozen=True)
class MonitoringMetrics:
    """Aggregated monitoring metrics across stored runs."""

    total_runs: int = 0
    completed_runs: int = 0
    mttt_ms: float = 0.0
    p95_latency_ms: float = 0.0
    fallback_rate: float = 0.0
    injection_detections: int = 0


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS investigation_runs (
        run_id             TEXT PRIMARY KEY,
        alert_id           TEXT NOT NULL,
        timestamp          TEXT NOT NULL,
        verdict            TEXT,
        severity           TEXT,
        injection_detected INTEGER NOT NULL DEFAULT 0,
        total_latency_ms   REAL NOT NULL DEFAULT 0.0,
        step_count         INTEGER NOT NULL DEFAULT 0,
        provider_used      TEXT,
        fallback_count     INTEGER NOT NULL DEFAULT 0,
        traces_json        TEXT NOT NULL DEFAULT '[]',
        pending_actions_json TEXT NOT NULL DEFAULT '[]',
        status             TEXT NOT NULL DEFAULT 'paused',
        hitl_decision      TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON investigation_runs(timestamp)",
    """
    CREATE TABLE IF NOT EXISTS hitl_audit_log (
        audit_id    TEXT PRIMARY KEY,
        alert_id    TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target      TEXT NOT NULL,
        decision    TEXT NOT NULL,
        reviewer    TEXT NOT NULL,
        decided_at  TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_hitl_decided_at ON hitl_audit_log(decided_at)",
)


def init_audit_db(db_path: str | Path | None = None) -> Path:
    """Create the audit database and tables if needed. Idempotent."""
    path = _resolve_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        for statement in _DDL:
            connection.execute(statement)
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(investigation_runs)")
        }
        if "pending_actions_json" not in columns:
            connection.execute(
                "ALTER TABLE investigation_runs "
                "ADD COLUMN pending_actions_json TEXT NOT NULL DEFAULT '[]'"
            )
    return path


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


_UPSERT_RUN = """
INSERT INTO investigation_runs (
    run_id, alert_id, timestamp, verdict, severity, injection_detected,
    total_latency_ms, step_count, provider_used, fallback_count,
    traces_json, pending_actions_json, status, hitl_decision
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(run_id) DO UPDATE SET
    verdict = excluded.verdict,
    severity = excluded.severity,
    injection_detected = excluded.injection_detected,
    total_latency_ms = excluded.total_latency_ms,
    step_count = excluded.step_count,
    provider_used = excluded.provider_used,
    fallback_count = excluded.fallback_count,
    traces_json = excluded.traces_json,
    pending_actions_json = excluded.pending_actions_json,
    status = excluded.status,
    hitl_decision = excluded.hitl_decision
"""


def record_run(record: RunRecord, *, db_path: str | Path | None = None) -> None:
    """Insert or update one investigation run."""
    init_audit_db(db_path)
    with sqlite3.connect(_resolve_path(db_path)) as connection:
        connection.execute(_UPSERT_RUN, record.params())


def record_hitl_decisions(
    *,
    run_id: str,
    alert_id: str,
    actions: Sequence[Any],
    decision: str,
    reviewer: str,
    decided_at: str | None = None,
    db_path: str | Path | None = None,
) -> int:
    """Append one audit row per containment action. Never modifies existing rows.

    Returns the number of newly inserted audit rows.
    """
    init_audit_db(db_path)
    timestamp = decided_at or _utc_now()
    inserted = 0
    with sqlite3.connect(_resolve_path(db_path)) as connection:
        for index, action in enumerate(actions):
            audit_id = f"AUD-{run_id}-{index}"
            action_value = getattr(action, "action", action)
            action_type = getattr(action_value, "value", str(action_value))
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO hitl_audit_log (
                    audit_id, alert_id, action_type, target, decision,
                    reviewer, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    alert_id,
                    action_type,
                    str(getattr(action, "target", "")),
                    decision,
                    reviewer,
                    timestamp,
                ),
            )
            inserted += cursor.rowcount
    return inserted


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def _percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return ordered[index]


def get_run_metrics(*, db_path: str | Path | None = None) -> MonitoringMetrics:
    """Aggregate MTTT, p95 latency, fallback rate, and injection detections."""
    init_audit_db(db_path)
    with sqlite3.connect(_resolve_path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT status, total_latency_ms, fallback_count, injection_detected
            FROM investigation_runs
            """
        ).fetchall()

    total = len(rows)
    completed = [row for row in rows if row[0] == "completed"]
    latencies = [float(row[1]) for row in completed if row[1] is not None]
    fallbacks = [int(row[2] or 0) for row in rows]
    return MonitoringMetrics(
        total_runs=total,
        completed_runs=len(completed),
        mttt_ms=sum(latencies) / len(latencies) if latencies else 0.0,
        p95_latency_ms=_percentile(latencies, 0.95),
        fallback_rate=sum(1 for value in fallbacks if value > 0) / total if total else 0.0,
        injection_detections=sum(int(row[3] or 0) for row in rows),
    )


def get_hitl_audit(
    *, limit: int = 200, db_path: str | Path | None = None
) -> tuple[HITLAuditEntry, ...]:
    """Return the append-only HITL audit log, newest first."""
    init_audit_db(db_path)
    with sqlite3.connect(_resolve_path(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT audit_id, alert_id, action_type, target, decision,
                   reviewer, decided_at
            FROM hitl_audit_log ORDER BY decided_at DESC LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    return tuple(HITLAuditEntry(*row) for row in rows)


def get_recent_runs(
    *, limit: int = 50, db_path: str | Path | None = None
) -> tuple[dict[str, Any], ...]:
    """Return recent runs without the (large) JSON traces column."""
    init_audit_db(db_path)
    with sqlite3.connect(_resolve_path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT run_id, alert_id, timestamp, verdict, severity,
                   injection_detected, total_latency_ms, step_count,
                   provider_used, fallback_count, pending_actions_json,
                   status, hitl_decision
            FROM investigation_runs ORDER BY timestamp DESC LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    return tuple(dict(row) for row in rows)


def traces_from_json(traces_json: str) -> list[dict[str, Any]]:
    """Decode stored traces for display or replay."""
    try:
        value = json.loads(traces_json)
    except (TypeError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []
