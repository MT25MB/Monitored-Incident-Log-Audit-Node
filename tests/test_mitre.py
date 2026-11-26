"""Tests for the local MITRE catalogue and verification helpers."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evals.run_eval import (  # noqa: E402
    ExpectedOutcome,
    EvalCase,
    JudgeScore,
    grade_case,
)
from src.agent.graph import TriageState, synthesize  # noqa: E402
from src.guardrails.mitre import (  # noqa: E402
    KNOWN_TECHNIQUES,
    check_mitre_mapping,
    check_mitre_mappings,
    get_technique,
    verified_mappings,
)
from src.schemas import (  # noqa: E402
    Classification,
    MitreMapping,
    SecurityAlert,
    Severity,
    TriageReport,
)


def test_catalogue_covers_expected_tactics() -> None:
    tactics = {tactic for technique in KNOWN_TECHNIQUES.values() for tactic in technique.tactics}
    assert {
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Credential Access",
        "Defense Evasion",
        "Discovery",
        "Command and Control",
        "Exfiltration",
    } <= tactics


def test_lookup_accepts_lower_case_and_returns_none_for_unknown() -> None:
    assert get_technique("t1003.001") is not None
    assert get_technique("T9999") is None


def test_known_mapping_verifies() -> None:
    mapping = MitreMapping(
        technique_id="T1003.001",
        technique_name="LSASS Memory",
        tactic="Credential Access",
    )
    check = check_mitre_mapping(mapping)
    assert check.known is True
    assert check.tactic_match is True
    assert check.verified is True
    assert "verified" in check.reason


def test_unknown_and_mismatched_mappings_are_clean() -> None:
    unknown = check_mitre_mapping(
        MitreMapping(technique_id="T9999", technique_name="Made up", tactic="Execution")
    )
    assert unknown.known is False
    assert unknown.verified is False
    assert "not in the local technique catalogue" in unknown.reason

    mismatch = check_mitre_mapping(
        MitreMapping(
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Execution",
        )
    )
    assert mismatch.known is True
    assert mismatch.tactic_match is False
    assert mismatch.verified is False
    assert "Credential Access" in mismatch.reason


def test_verified_mappings_keeps_order_and_drops_unverified() -> None:
    known = MitreMapping(
        technique_id="T1059.001", technique_name="PowerShell", tactic="Execution"
    )
    unknown = MitreMapping(
        technique_id="T9999", technique_name="Unknown", tactic="Execution"
    )
    checks = check_mitre_mappings([known, unknown])
    assert len(checks) == 2
    assert verified_mappings([known, unknown], checks) == (known,)


def test_synthesis_omits_unverified_techniques(tmp_path: Path) -> None:
    alert = SecurityAlert(
        alert_id="ALT-1",
        severity=Severity.HIGH,
        title="Synthetic event",
        raw_payload="powershell from 203.0.113.42",
        source_ip="203.0.113.42",
        hostname="WS-FIN-014",
    )
    state = TriageState(
        alert=alert,
        step=4,
        tool_results=[
            {
                "tool": "query_siem_logs",
                "args": {"alert_id": "ALT-1"},
                "rows": [
                    {
                        "log_id": "L1",
                        "source": "sysmon",
                        "hostname": "WS-FIN-014",
                        "source_ip": "203.0.113.42",
                        "message": "powershell executed",
                        "mitre_technique": "T9999",
                    }
                ],
                "count": 1,
            }
        ],
    )

    result = synthesize(state, audit_db_path=str(tmp_path / "audit.db"))
    report = result["report"]

    assert report.mitre == []
    assert "Unverified MITRE ID(s)" in report.summary


def test_synthesis_uses_catalogue_tactic(tmp_path: Path) -> None:
    alert = SecurityAlert(
        alert_id="ALT-2",
        severity=Severity.HIGH,
        title="LSASS dump",
        raw_payload="procdump lsass from 203.0.113.42",
        source_ip="203.0.113.42",
        hostname="WS-FIN-014",
    )
    state = TriageState(
        alert=alert,
        step=4,
        tool_results=[
            {
                "tool": "query_siem_logs",
                "rows": [
                    {
                        "log_id": "L2",
                        "source": "sysmon",
                        "hostname": "WS-FIN-014",
                        "message": "lsass dump",
                        "mitre_technique": "T1003.001",
                    }
                ],
            }
        ],
    )

    report = synthesize(state, audit_db_path=str(tmp_path / "audit.db"))["report"]
    assert report.mitre[0].technique_id == "T1003.001"
    assert report.mitre[0].tactic == "Credential Access"


def test_grading_excludes_unverified_technique_ids() -> None:
    case = EvalCase(
        case_id="C1",
        alert=SecurityAlert(
            alert_id="ALT-3",
            severity=Severity.LOW,
            title="Benign",
            raw_payload="signed installer",
        ),
        expected=ExpectedOutcome(
            classification=Classification.BENIGN, mitre=[]
        ),
    )
    report = TriageReport(
        alert_id="ALT-3",
        classification=Classification.BENIGN,
        severity=Severity.LOW,
        confidence=0.4,
        summary="Benign event",
        mitre=[
            MitreMapping(
                technique_id="T9999",
                technique_name="Unknown",
                tactic="Execution",
            )
        ],
    )
    judge = JudgeScore(grounded=True, score_1_to_5=5, reason="ok")

    result = grade_case(
        case,
        report,
        before_state={"tool_calls": 4, "traces": [], "injection_detected": False},
        final_traces=[],
        judge=judge,
    )

    assert result.actual_mitre == ()
    assert result.unverified_mitre_ids == ("T9999",)
    assert result.mitre_pass is True
