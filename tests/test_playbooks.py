"""Tests for containment playbooks and HITL reviewer context."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agent.graph import build_graph, resume_triage, start_triage  # noqa: E402
from src.agent.playbooks import (  # noqa: E402
    PLAYBOOKS,
    get_playbook,
    playbook_for,
    render_playbook_brief,
)
from src.cli import main  # noqa: E402
from src.export import build_export  # noqa: E402
from src.schemas import ContainmentAction, SecurityAlert, Severity  # noqa: E402
from src.tools.siem import init_soc_db  # noqa: E402


def _alert() -> SecurityAlert:
    return SecurityAlert(
        alert_id="ALT-1001",
        severity=Severity.CRITICAL,
        title="C2 beacon",
        raw_payload="powershell from 203.0.113.42 to WS-FIN-014",
        source_ip="203.0.113.42",
        hostname="WS-FIN-014",
    )


def test_every_containment_action_has_a_playbook() -> None:
    assert set(PLAYBOOKS) == set(ContainmentAction)
    for playbook in PLAYBOOKS.values():
        assert playbook.requires_hitl is True
        assert playbook.target_type
        assert playbook.risk_notes
        assert playbook.rollback_steps


def test_lookup_and_brief() -> None:
    assert get_playbook(ContainmentAction.BLOCK_IP).title == "Block IP address"
    assert playbook_for("isolate_host") is not None
    assert playbook_for("not_an_action") is None

    brief = render_playbook_brief(ContainmentAction.BLOCK_IP, "203.0.113.42")
    assert "203.0.113.42" in brief
    assert "Risks:" in brief
    assert "Rollback:" in brief
    assert "Human approval is required" in brief


def test_hitl_gate_attaches_playbook_context(tmp_path: Path) -> None:
    db = init_soc_db(tmp_path / "soc.duckdb")
    graph = build_graph(db_path=str(db), audit_db_path=str(tmp_path / "audit.db"))
    start_triage(graph, _alert(), "playbook-1")

    resumed = resume_triage(graph, "playbook-1", "approved", decided_by="analyst")

    assert resumed["hitl_context"]
    for context in resumed["hitl_context"]:
        assert context["requires_hitl"] is True
        assert context["risk_notes"]
        assert context["rollback_steps"]
        assert "Human approval" in context["brief"]


def test_export_includes_playbook_context(tmp_path: Path) -> None:
    db = init_soc_db(tmp_path / "soc.duckdb")
    graph = build_graph(db_path=str(db), audit_db_path=str(tmp_path / "audit.db"))
    start_triage(graph, _alert(), "playbook-2")
    resumed = resume_triage(graph, "playbook-2", "rejected", decided_by="analyst")

    bundle = build_export(resumed)
    assert bundle.hitl.context
    assert bundle.hitl.context[0]["title"] == "Block IP address"


def test_cli_prints_playbook_context_before_decision(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "triage",
            "--json",
            json.dumps(_alert().model_dump(mode="json")),
            "--hitl",
            "reject",
            "--db-path",
            str(tmp_path / "soc.duckdb"),
            "--audit-db",
            str(tmp_path / "audit.db"),
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Target type: IPv4 address" in output
    assert "Risk: Shared or proxy infrastructure" in output
    assert "Rollback: Remove the address from the block list." in output
    assert output.index("Risk:") < output.index("HITL decision:")
