"""Containment playbooks shown to reviewers at the HITL gate.

A playbook explains what an action does, what can go wrong, and how to undo it.
It never executes anything and it never removes the human approval requirement.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, Field

from src.schemas import ContainmentAction

__all__ = [
    "PLAYBOOKS",
    "Playbook",
    "get_playbook",
    "playbook_for",
    "render_playbook_brief",
]


class Playbook(BaseModel):
    """Reviewer guidance for one containment action."""

    action: ContainmentAction
    title: str
    target_type: str
    risk_notes: tuple[str, ...] = Field(default_factory=tuple)
    rollback_steps: tuple[str, ...] = Field(default_factory=tuple)
    requires_hitl: Literal[True] = True


PLAYBOOKS: Mapping[ContainmentAction, Playbook] = {
    ContainmentAction.ISOLATE_HOST: Playbook(
        action=ContainmentAction.ISOLATE_HOST,
        title="Isolate host",
        target_type="hostname",
        risk_notes=(
            "Cuts network access for the host, including legitimate work.",
            "Confirm the hostname belongs to the intended asset before approving.",
        ),
        rollback_steps=(
            "Restore the host to its previous network segment.",
            "Verify with the asset owner that services have returned.",
        ),
    ),
    ContainmentAction.BLOCK_IP: Playbook(
        action=ContainmentAction.BLOCK_IP,
        title="Block IP address",
        target_type="IPv4 address",
        risk_notes=(
            "Shared or proxy infrastructure can be caught by a broad block.",
            "Check whether the address is in an approved scanning range.",
        ),
        rollback_steps=(
            "Remove the address from the block list.",
            "Confirm outbound traffic to the address is allowed again.",
        ),
    ),
    ContainmentAction.DISABLE_ACCOUNT: Playbook(
        action=ContainmentAction.DISABLE_ACCOUNT,
        title="Disable account",
        target_type="username",
        risk_notes=(
            "The account may be a service identity used by automation.",
            "Check active sessions and scheduled jobs before disabling.",
        ),
        rollback_steps=(
            "Re-enable the account after ownership is confirmed.",
            "Rotate credentials if the account was genuinely compromised.",
        ),
    ),
    ContainmentAction.REVOKE_TOKEN: Playbook(
        action=ContainmentAction.REVOKE_TOKEN,
        title="Revoke token",
        target_type="token identifier",
        risk_notes=(
            "Every session using the token will end immediately.",
            "Identify the token owner so their workflow can be restored.",
        ),
        rollback_steps=(
            "Issue a replacement token to the verified owner.",
            "Confirm dependent integrations are working again.",
        ),
    ),
}


def get_playbook(action: ContainmentAction) -> Playbook:
    """Return the playbook for an action."""
    return PLAYBOOKS[action]


def playbook_for(action: ContainmentAction | str) -> Playbook | None:
    """Tolerant lookup for values that may come from text or stored state."""
    if isinstance(action, ContainmentAction):
        return PLAYBOOKS.get(action)
    try:
        return PLAYBOOKS[ContainmentAction(action)]
    except ValueError:
        return None


def render_playbook_brief(action: ContainmentAction, target: str) -> str:
    """Short, plain-language brief for a reviewer."""
    playbook = get_playbook(action)
    risks = "; ".join(playbook.risk_notes)
    rollback = "; ".join(playbook.rollback_steps)
    return (
        f"{playbook.title} on {target} ({playbook.target_type}). "
        f"Risks: {risks}. Rollback: {rollback}. "
        "Human approval is required."
    )
