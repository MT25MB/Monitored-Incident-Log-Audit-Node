"""Tests for deterministic incident bundling."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import pytest

_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.incident_bundler import bundle_alerts, extract_entities  # noqa: E402
from src.schemas import SecurityAlert, Severity  # noqa: E402


_T0 = datetime(2026, 11, 25, 9, 0, tzinfo=timezone.utc)


def _alert(
    alert_id: str,
    minutes: float,
    *,
    hostname: str | None = None,
    source_ip: str | None = None,
    tags: tuple[str, ...] = (),
    raw_payload: str = "synthetic event",
    severity: Severity = Severity.MEDIUM,
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=alert_id,
        timestamp=_T0 + timedelta(minutes=minutes),
        severity=severity,
        title="Synthetic alert",
        raw_payload=raw_payload,
        hostname=hostname,
        source_ip=source_ip,
        tags=list(tags),
    )


def test_extract_entities_normalizes_keys() -> None:
    entities = extract_entities(
        _alert(
            "ALT-1",
            0,
            hostname="WS-FIN-014",
            source_ip="203.0.113.42",
            tags=("user:Alice", "corr:INC-9"),
            raw_payload="user=bob from 198.51.100.7",
        )
    )
    assert "hostname:ws-fin-014" in entities
    assert "ip:203.0.113.42" in entities
    assert "user:alice" in entities
    assert "user:bob" in entities
    assert "corr:inc-9" in entities


def test_alerts_sharing_host_inside_window_are_one_incident() -> None:
    alerts = [
        _alert("ALT-3", 6, hostname="WS-1", severity=Severity.HIGH),
        _alert("ALT-1", 0, hostname="WS-1", severity=Severity.LOW),
        _alert("ALT-2", 3, hostname="WS-1", severity=Severity.CRITICAL),
        _alert("ALT-4", 30, hostname="WS-1"),
    ]
    incidents = bundle_alerts(alerts, window_seconds=600)

    assert len(incidents) == 2
    assert incidents[0].alert_ids == ("ALT-1", "ALT-2", "ALT-3")
    assert incidents[0].severity is Severity.CRITICAL
    assert "hostname:ws-1" in incidents[0].entities
    assert incidents[1].alert_ids == ("ALT-4",)
    assert "3 alerts" in incidents[0].summary


def test_window_limits_total_incident_span() -> None:
    alerts = [
        _alert("ALT-1", 0, hostname="WS-1"),
        _alert("ALT-2", 5, hostname="WS-1"),
        _alert("ALT-3", 9, hostname="WS-1"),
    ]
    incidents = bundle_alerts(alerts, window_seconds=360)
    assert [incident.alert_ids for incident in incidents] == [
        ("ALT-1", "ALT-2"),
        ("ALT-3",),
    ]


def test_username_and_correlation_key_grouping() -> None:
    alerts = [
        _alert("ALT-1", 0, tags=("user:alice",)),
        _alert("ALT-2", 2, raw_payload="user=alice opened a session"),
        _alert("ALT-3", 4, tags=("corr:INC-42",)),
        _alert("ALT-4", 5, tags=("event:INC-42",)),
    ]
    incidents = bundle_alerts(alerts, window_seconds=600)
    assert [incident.alert_ids for incident in incidents] == [
        ("ALT-1", "ALT-2"),
        ("ALT-3", "ALT-4"),
    ]


def test_unrelated_alerts_stay_separate() -> None:
    alerts = [
        _alert("ALT-1", 0, hostname="WS-1"),
        _alert("ALT-2", 1, hostname="WS-2", source_ip="203.0.113.42"),
    ]
    incidents = bundle_alerts(alerts, window_seconds=600)
    assert len(incidents) == 2


def test_bundling_is_order_independent() -> None:
    alerts = [
        _alert("ALT-1", 0, hostname="WS-1"),
        _alert("ALT-2", 2, hostname="WS-1"),
        _alert("ALT-3", 4, hostname="WS-1"),
    ]
    forward = bundle_alerts(alerts, window_seconds=600)
    backward = bundle_alerts(list(reversed(alerts)), window_seconds=600)
    assert forward == backward
    assert forward[0].incident_id.startswith("INC-")


def test_summary_does_not_expose_secrets() -> None:
    alert = _alert(
        "ALT-1",
        0,
        hostname="WS-1",
        raw_payload="user=alice password=hunter2 AKIAIOSFODNN7EXAMPLE",
    )
    incident = bundle_alerts([alert], window_seconds=600)[0]
    assert "hunter2" not in incident.summary
    assert "AKIAIOSFODNN7EXAMPLE" not in str(incident.to_dict())


def test_invalid_window_is_rejected() -> None:
    with pytest.raises(ValueError, match="window_seconds"):
        bundle_alerts([], window_seconds=0)
