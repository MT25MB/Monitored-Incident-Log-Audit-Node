"""Group related alerts into incident contexts for triage.

Alerts belong to the same incident when they share an entity (hostname,
username, source IP, or correlation key) and fall inside a fixed time window.
Grouping is deterministic: input order does not change the incidents or their
identifiers.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from src.schemas import SecurityAlert, Severity

__all__ = [
    "IncidentContext",
    "bundle_alerts",
    "extract_entities",
]


_USER_RE = re.compile(
    r"\b(?:user|username|account)\s*[=:]\s*([A-Za-z0-9_.-]{2,64})\b",
    re.IGNORECASE,
)
_TAG_PREFIXES = {
    "user:": "user",
    "username:": "user",
    "corr:": "corr",
    "correlation:": "corr",
    "event:": "corr",
}
_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass
class _Component:
    """Working set of alert indices for one incident during grouping."""

    indices: list[int]
    entities: set[str]
    first: datetime
    last: datetime


@dataclass(frozen=True)
class IncidentContext:
    """A stable group of alerts that appear to describe one incident."""

    incident_id: str
    alerts: tuple[SecurityAlert, ...]
    entities: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    severity: Severity
    summary: str

    @property
    def alert_ids(self) -> tuple[str, ...]:
        return tuple(alert.alert_id for alert in self.alerts)

    def to_dict(self) -> dict[str, object]:
        """JSON-friendly view for reports and exports."""
        return {
            "incident_id": self.incident_id,
            "alert_ids": list(self.alert_ids),
            "entities": list(self.entities),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "severity": self.severity.value,
            "summary": self.summary,
        }


def _as_utc(value: datetime) -> datetime:
    normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc)


def extract_entities(alert: SecurityAlert) -> frozenset[str]:
    """Return normalized entity keys for one alert."""
    entities: set[str] = set()
    if alert.hostname:
        entities.add(f"hostname:{alert.hostname.strip().lower()}")
    if alert.source_ip:
        entities.add(f"ip:{alert.source_ip.strip()}")

    for tag in alert.tags:
        for prefix, kind in _TAG_PREFIXES.items():
            if tag.lower().startswith(prefix):
                value = tag[len(prefix) :].strip().lower()
                if value:
                    entities.add(f"{kind}:{value}")

    for match in _USER_RE.findall(alert.raw_payload or ""):
        entities.add(f"user:{match.lower()}")
    return frozenset(entities)


def _incident_id(alert_ids: Sequence[str]) -> str:
    digest = hashlib.sha1("|".join(sorted(alert_ids)).encode("utf-8")).hexdigest()
    return f"INC-{digest[:10]}"


def _summarize(alerts: Sequence[SecurityAlert], entities: Sequence[str]) -> str:
    count = len(alerts)
    plural = "alert" if count == 1 else "alerts"
    ids = ", ".join(alert.alert_id for alert in alerts[:3])
    if count > 3:
        ids += f", +{count - 3} more"

    readable = [entity.split(":", 1)[-1] for entity in entities[:3]]
    shared = ", ".join(readable) if readable else "no shared entity"
    severity = max((alert.severity for alert in alerts), key=lambda item: _SEVERITY_RANK[item])
    return f"{count} {plural} ({ids}) share {shared}. Highest severity: {severity.value}."


def bundle_alerts(
    alerts: Iterable[SecurityAlert],
    *,
    window_seconds: float = 600.0,
) -> tuple[IncidentContext, ...]:
    """Bundle alerts by shared entity within ``window_seconds``.

    The window limits the span from the first alert in an incident to the last,
    so an incident never grows longer than the configured interval.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")
    window = timedelta(seconds=window_seconds)

    ordered = sorted(
        alerts,
        key=lambda alert: (_as_utc(alert.timestamp), alert.alert_id),
    )
    if not ordered:
        return ()

    components: list[_Component] = []

    for index, alert in enumerate(ordered):
        when = _as_utc(alert.timestamp)
        entities = extract_entities(alert)
        matches = [
            component
            for component in components
            if when - component.first <= window
            and not entities.isdisjoint(component.entities)
        ]

        if matches:
            # Merge every matching component so one bridging alert cannot leave
            # two overlapping incidents behind.
            matched_ids = {id(component) for component in matches}
            merged = _Component(
                indices=[item for component in matches for item in component.indices]
                + [index],
                entities=set().union(
                    *(component.entities for component in matches), entities
                ),
                first=min(component.first for component in matches),
                last=when,
            )
            components = [c for c in components if id(c) not in matched_ids] + [merged]
        else:
            components.append(_Component([index], set(entities), when, when))

    incidents: list[IncidentContext] = []
    for component in components:
        indices = sorted(set(component.indices))
        members = tuple(ordered[index] for index in indices)
        entity_keys = tuple(sorted(component.entities))
        severity = max(
            (alert.severity for alert in members), key=lambda item: _SEVERITY_RANK[item]
        )
        incidents.append(
            IncidentContext(
                incident_id=_incident_id(tuple(alert.alert_id for alert in members)),
                alerts=members,
                entities=entity_keys,
                first_seen=component.first,
                last_seen=component.last,
                severity=severity,
                summary=_summarize(members, entity_keys),
            )
        )

    return tuple(
        sorted(incidents, key=lambda incident: (incident.first_seen, incident.incident_id))
    )
