"""Local MITRE ATT&CK catalogue and technique verification.

The catalogue is a small, offline subset of common SOC techniques. It is not a
replacement for the full ATT&CK dataset. Its job here is narrower: give the
agent something concrete to check a predicted technique ID and tactic against,
and flag anything it cannot verify without raising an exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from src.schemas import MitreMapping

__all__ = [
    "KNOWN_TECHNIQUES",
    "MitreCheck",
    "MitreTechnique",
    "check_mitre_mapping",
    "check_mitre_mappings",
    "get_technique",
    "verified_mappings",
]


@dataclass(frozen=True)
class MitreTechnique:
    """One known technique and the tactics it belongs to."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]


def _tech(technique_id: str, name: str, *tactics: str) -> MitreTechnique:
    return MitreTechnique(technique_id=technique_id, name=name, tactics=tactics)


KNOWN_TECHNIQUES: Mapping[str, MitreTechnique] = {
    # Execution
    "T1059": _tech("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1059.001": _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1204.002": _tech("T1204.002", "User Execution: Malicious File", "Execution"),
    "T1047": _tech("T1047", "Windows Management Instrumentation", "Execution"),
    # Persistence
    "T1053.005": _tech("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence", "Privilege Escalation"),
    "T1098": _tech("T1098", "Account Manipulation", "Persistence", "Privilege Escalation"),
    "T1098.001": _tech("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence", "Privilege Escalation"),
    "T1547.001": _tech("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence", "Privilege Escalation"),
    # Privilege escalation
    "T1078": _tech("T1078", "Valid Accounts", "Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
    # Credential access
    "T1003.001": _tech("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1110": _tech("T1110", "Brute Force", "Credential Access"),
    "T1110.003": _tech("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    "T1558.003": _tech("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"),
    # Defense evasion
    "T1055": _tech("T1055", "Process Injection", "Defense Evasion", "Privilege Escalation"),
    "T1562.001": _tech("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    # Discovery
    "T1049": _tech("T1049", "System Network Connections Discovery", "Discovery"),
    "T1087": _tech("T1087", "Account Discovery", "Discovery"),
    "T1203": _tech("T1203", "Exploitation for Client Execution", "Execution"),
    # Command and control
    "T1071.001": _tech("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1071.004": _tech("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
    "T1090.003": _tech("T1090.003", "Proxy: Multi-hop Proxy", "Command and Control"),
    "T1568.002": _tech("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    # Exfiltration
    "T1041": _tech("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": _tech("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1537": _tech("T1537", "Transfer Data to Cloud Account", "Exfiltration"),
    # Initial access, used by the adversarial fixtures
    "T1566.002": _tech("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    "T1190": _tech("T1190", "Exploit Public-Facing Application", "Initial Access"),
}


@dataclass(frozen=True)
class MitreCheck:
    """Result of checking one mapping against the local catalogue."""

    technique_id: str
    known: bool
    tactic_match: bool
    verified: bool
    reason: str


def get_technique(technique_id: str) -> MitreTechnique | None:
    """Look up a technique ID, accepting lower case input."""
    return KNOWN_TECHNIQUES.get(technique_id.strip().upper())


def check_mitre_mapping(mapping: MitreMapping) -> MitreCheck:
    """Check one predicted mapping without raising on unknown IDs."""
    technique_id = mapping.technique_id.strip().upper()
    technique = get_technique(technique_id)
    if technique is None:
        return MitreCheck(
            technique_id=technique_id,
            known=False,
            tactic_match=False,
            verified=False,
            reason=f"{technique_id} is not in the local technique catalogue",
        )

    supplied = mapping.tactic.strip().lower()
    accepted = {tactic.lower() for tactic in technique.tactics}
    if supplied in accepted:
        return MitreCheck(
            technique_id=technique_id,
            known=True,
            tactic_match=True,
            verified=True,
            reason=f"{technique_id} verified under {mapping.tactic.strip()}",
        )

    return MitreCheck(
        technique_id=technique_id,
        known=True,
        tactic_match=False,
        verified=False,
        reason=(
            f"{technique_id} is known, but tactic {mapping.tactic!r} is not "
            f"one of {', '.join(technique.tactics)}"
        ),
    )


def check_mitre_mappings(mappings: Iterable[MitreMapping]) -> tuple[MitreCheck, ...]:
    """Check several mappings, preserving their order."""
    return tuple(check_mitre_mapping(mapping) for mapping in mappings)


def verified_mappings(
    mappings: Sequence[MitreMapping],
    checks: Sequence[MitreCheck] | None = None,
) -> tuple[MitreMapping, ...]:
    """Return only mappings whose ID and tactic were both verified."""
    results = tuple(check_mitre_mappings(mappings) if checks is None else checks)
    return tuple(
        mapping for mapping, check in zip(mappings, results) if check.verified
    )
