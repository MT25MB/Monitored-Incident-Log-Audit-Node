"""Command-line entry point for MILAN.

Examples::

    python -m src.cli init-db
    python -m src.cli triage --json-file alert.json --hitl approve
    python -m src.cli batch evals/datasets/full_benchmark.jsonl --limit 5 --pace

All operations are local. No API key is required; LLM enrichment is opt-in and
uses the free-tier provider chain.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from src.agent.graph import MAX_INVESTIGATION_STEPS, build_graph, resume_triage, start_triage
from src.agent.handoff import build_handoff, render_handoff
from src.agent.playbooks import get_playbook
from src.config import Pacer, PacingConfig
from src.export import write_export
from src.monitoring.metrics import compute_metrics, metrics_to_dict
from src.replay import replay_dataset
from src.schemas import SecurityAlert
from src.tools.db_guard import execute_readonly
from src.tools.siem import init_soc_db

__all__ = ["main"]


_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOC_DB = _ROOT / "data" / "milan_soc.duckdb"
DEFAULT_AUDIT_DB = _ROOT / "data" / "milan_audit.db"
DEFAULT_DATASET = _ROOT / "evals" / "datasets" / "full_benchmark.jsonl"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_alert(raw: str) -> SecurityAlert:
    """Parse one alert, accepting either a bare object or a benchmark case."""
    payload = json.loads(raw)
    if isinstance(payload, dict) and "alert" in payload:
        payload = payload["alert"]
    return SecurityAlert.model_validate(payload)


def _load_alerts(path: Path, limit: int | None) -> tuple[SecurityAlert, ...]:
    """Read alerts from a JSONL file, with optional case wrapper."""
    alerts: list[SecurityAlert] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                alerts.append(_load_alert(line))
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"line {line_number}: invalid alert: {exc}") from exc
            if limit is not None and len(alerts) >= limit:
                break
    if not alerts:
        raise ValueError(f"no alerts found in {path}")
    return tuple(alerts)


def _print_summary(state: dict[str, Any]) -> None:
    """Print the fields an analyst checks first."""
    report = state.get("report")
    traces = list(state.get("traces") or [])
    latency = sum(float(trace.latency_ms) for trace in traces)
    cost = sum(float(trace.estimated_cost_usd) for trace in traces)
    flags = list(state.get("injection_flags") or [])

    alert = state.get("alert")
    print(f"Alert: {alert.alert_id if alert else '-'}")
    if report is None:
        print("Verdict: unavailable")
    else:
        print(f"Verdict: {report.classification.value} (confidence {report.confidence:.0%})")
        print(f"Severity: {report.severity.value}")
        techniques = [item.technique_id for item in report.mitre]
        print(f"MITRE: {', '.join(techniques) if techniques else 'none'}")
    print(
        f"Injection detected: {'yes' if state.get('injection_detected') else 'no'} "
        f"({len(flags)} flag(s))"
    )
    print(f"Latency: {latency:.1f} ms across {len(traces)} steps")
    print(f"Tool calls: {state.get('tool_calls', 0)}")
    print(f"Estimated cost: ${cost:.2f}")
    if state.get("hitl_decision"):
        print(f"HITL decision: {state['hitl_decision']}")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_init_db(args: argparse.Namespace) -> int:
    """Create and seed the local SOC database."""
    path = init_soc_db(args.db_path or DEFAULT_SOC_DB)
    connection = duckdb.connect(str(path), read_only=True)
    try:
        counts = {
            table: execute_readonly(
                connection,
                f"SELECT COUNT(*) FROM {table}",  # noqa: S608 - table is a fixed literal
                allowed_tables=(table,),
            ).fetchone()[0]
            for table in ("siem_logs", "threat_intel", "asset_inventory")
        }
    finally:
        connection.close()
    print(f"SOC database: {path}")
    print(
        f"siem_logs={counts['siem_logs']} "
        f"threat_intel={counts['threat_intel']} "
        f"asset_inventory={counts['asset_inventory']}"
    )
    print("Idempotent: existing rows were left unchanged.")
    return 0


def _maybe_export(state: dict[str, Any], args: argparse.Namespace) -> None:
    """Write a JSON export when the caller asked for one."""
    export_dir = getattr(args, "export_dir", None)
    if not export_dir:
        return
    try:
        path = write_export(state, output_dir=export_dir)
    except (OSError, ValueError) as exc:
        print(f"ERROR: export failed: {exc}", file=sys.stderr)
        return
    print(f"Export written to {path}")


def cmd_triage(args: argparse.Namespace) -> int:
    """Run one alert and handle any containment proposal."""
    if not args.json_file and not args.json:
        print("ERROR: provide --json-file or --json", file=sys.stderr)
        return 2
    try:
        raw = Path(args.json_file).read_text(encoding="utf-8") if args.json_file else args.json
        alert = _load_alert(raw)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: invalid alert: {exc}", file=sys.stderr)
        return 2

    graph = build_graph(
        db_path=args.db_path,
        audit_db_path=args.audit_db,
        enrich_with_llm=args.enrich_with_llm,
    )
    thread_id = args.thread_id or f"cli-{uuid.uuid4().hex[:8]}"
    paused = start_triage(graph, alert, thread_id)
    _print_summary(paused)

    report = paused.get("report")
    actions = list(report.recommended_actions) if report else []
    if not actions:
        print("Containment: none proposed")
        _maybe_export(paused, args)
        return 0

    print("Containment proposed:")
    for action in actions:
        playbook = get_playbook(action.action)
        print(f"  {playbook.title} -> {action.target} ({action.approval_status.value})")
        print(f"    Target type: {playbook.target_type}")
        for note in playbook.risk_notes:
            print(f"    Risk: {note}")
        for step in playbook.rollback_steps:
            print(f"    Rollback: {step}")

    mode = args.hitl or ("prompt" if sys.stdin.isatty() else "instructions")
    if mode == "instructions":
        print(
            "No action executed. Re-run with --hitl approve or --hitl reject "
            "to record a decision, or use the Streamlit HITL tab for interactive review."
        )
        _maybe_export(paused, args)
        return 0

    if mode == "prompt":
        try:
            answer = input("Approve containment? [a/r/N] ").strip().lower()
        except EOFError:
            answer = ""
        mode = "approve" if answer == "a" else "reject"
        print("Defaulting to rejection." if mode == "reject" and answer != "r" else "")

    final = resume_triage(graph, thread_id, mode, decided_by=args.reviewer)
    print(f"HITL decision: {final.get('hitl_decision')}")
    print(
        "Executable actions after review: "
        f"{sum(1 for action in final['report'].recommended_actions if action.is_executable)}"
    )
    _maybe_export(final, args)
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    """Run alerts from a JSONL file and write a compact result summary."""
    if args.limit is not None and args.limit < 1:
        print("ERROR: --limit must be >= 1", file=sys.stderr)
        return 2
    try:
        alerts = _load_alerts(args.dataset, args.limit)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    graph = build_graph(
        db_path=args.db_path,
        audit_db_path=args.audit_db,
        enrich_with_llm=args.enrich_with_llm,
    )
    pacer = Pacer(PacingConfig.gentle() if args.pace else PacingConfig(enabled=False))
    results: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    injection_flags = 0
    errors = 0

    for index, alert in enumerate(alerts, start=1):
        pacer.wait()
        thread_id = f"batch-{uuid.uuid4().hex[:8]}"
        try:
            start_triage(graph, alert, thread_id)
            final = resume_triage(graph, thread_id, "rejected", decided_by="cli-batch")
            report = final["report"]
            verdict = report.classification.value
            counts[verdict] = counts.get(verdict, 0) + 1
            if final.get("injection_detected"):
                injection_flags += 1
            traces = final.get("traces", [])
            row = {
                "alert_id": alert.alert_id,
                "verdict": verdict,
                "severity": report.severity.value,
                "mitre": [item.technique_id for item in report.mitre],
                "injection_detected": bool(final.get("injection_detected")),
                "tool_calls": final.get("tool_calls", 0),
                "latency_ms": round(sum(float(trace.latency_ms) for trace in traces), 3),
                "cost_usd": sum(float(trace.estimated_cost_usd) for trace in traces),
                "hitl_decision": final.get("hitl_decision"),
            }
        except Exception as exc:  # keep the batch running across bad alerts
            errors += 1
            row = {"alert_id": alert.alert_id, "error": f"{type(exc).__name__}: {exc}"}
            print(f"[{index}/{len(alerts)}] {alert.alert_id}: ERROR", file=sys.stderr)
        else:
            print(
                f"[{index}/{len(alerts)}] {alert.alert_id}: "
                f"{row['verdict']} · {row['tool_calls']} tools · "
                f"{row['latency_ms']:.1f} ms"
            )
        results.append(row)

    print(f"Processed {len(alerts)} alert(s).")
    print("Verdicts: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
    print(f"Injection flagged: {injection_flags} · Errors: {errors}")

    if args.output_json:
        destination = Path(args.output_json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                    "dataset": str(args.dataset),
                    "total": len(results),
                    "counts": counts,
                    "injection_flags": injection_flags,
                    "errors": errors,
                    "cases": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Results written to {destination}")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Stream a dataset through the graph with optional filters and delay."""
    if args.limit is not None and args.limit < 1:
        print("ERROR: --limit must be >= 1", file=sys.stderr)
        return 2
    if args.delay_sec < 0:
        print("ERROR: --delay-sec must be >= 0", file=sys.stderr)
        return 2

    def progress(index: int, row: dict[str, Any]) -> None:
        if "error" in row:
            print(f"[{index}] {row['case_id']}: ERROR ({row['error']})", file=sys.stderr)
            return
        print(
            f"[{index}] {row['case_id']} ({row['source']}): "
            f"{row['verdict']} · {row['tool_calls']} tools · "
            f"{'injection flagged' if row['injection_detected'] else 'clean'}"
        )

    try:
        summary = replay_dataset(
            args.dataset,
            delay_sec=args.delay_sec,
            source=args.source,
            adversarial_only=args.adversarial_only,
            limit=args.limit,
            db_path=args.db_path,
            audit_db_path=args.audit_db,
            on_record=progress,
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Replayed {summary.total} alert(s).")
    print(
        "Verdicts: "
        + (
            ", ".join(f"{key}={value}" for key, value in sorted((summary.counts or {}).items()))
            or "none"
        )
    )
    print(f"Adversarial cases: {summary.adversarial_count} · Errors: {summary.errors}")

    if args.output_json:
        destination = Path(args.output_json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                {
                    "dataset": str(args.dataset),
                    "total": summary.total,
                    "counts": summary.counts or {},
                    "adversarial_count": summary.adversarial_count,
                    "errors": summary.errors,
                    "cases": list(summary.records),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Results written to {destination}")
    return 0


def cmd_handoff(args: argparse.Namespace) -> int:
    """Print a shift handoff from the audit store."""
    try:
        summary = build_handoff(db_path=args.audit_db, limit=args.limit or 50)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    report = render_handoff(summary, fmt=args.format)
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
        print(f"Handoff written to {destination}")
    else:
        print(report)
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    """Print aggregate metrics from the SQLite audit store."""
    summary = compute_metrics(db_path=args.audit_db)
    providers = (
        ", ".join(f"{name}={count}" for name, count in summary.provider_usage.items()) or "none"
    )
    print("MILAN monitoring summary")
    print(
        f"Runs: {summary.total_runs} "
        f"(completed {summary.completed_runs}, paused {summary.paused_runs})"
    )
    print(
        f"MTTT: {summary.mttt_ms:.1f} ms · "
        f"p50: {summary.p50_latency_ms:.3f} ms · "
        f"p95: {summary.p95_latency_ms:.3f} ms"
    )
    print(
        f"Tool calls: {summary.tool_calls_total} · "
        f"Avg steps/alert: {summary.avg_steps_per_alert:.2f} · "
        f"Cap <={MAX_INVESTIGATION_STEPS}: {summary.step_cap_compliant} ok, "
        f"{summary.step_cap_violations} violations"
    )
    print(
        f"Providers: {providers} · "
        f"Fallback: {summary.fallback_events} event(s) "
        f"({summary.fallback_rate:.0%}) · "
        f"Cost: ${summary.estimated_cost_usd:.2f}"
    )
    print(
        f"Injection flagged: {summary.injection_flagged_runs} ({summary.injection_flag_rate:.0%})"
    )
    print(
        f"HITL: approved={summary.hitl_approved}, "
        f"rejected={summary.hitl_rejected}, "
        f"not_required={summary.hitl_not_required}"
    )

    if args.output_json:
        destination = Path(args.output_json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(metrics_to_dict(summary), indent=2), encoding="utf-8")
        print(f"Metrics written to {destination}")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description="Local SOC alert triage CLI for MILAN",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    triage = subparsers.add_parser("triage", help="Triage one alert")
    source = triage.add_mutually_exclusive_group(required=True)
    source.add_argument("--json-file", help="Path to a JSON alert file")
    source.add_argument("--json", help="Inline JSON alert string")
    triage.add_argument(
        "--hitl",
        choices=("instructions", "prompt", "approve", "reject"),
        default=None,
        help="How to handle a containment proposal (default: prompt on a TTY)",
    )
    triage.add_argument("--reviewer", default="cli_operator", help="Reviewer identity")
    triage.add_argument("--thread-id", default=None, help="LangGraph thread id")
    triage.add_argument("--db-path", default=None, help="Override the DuckDB path")
    triage.add_argument("--audit-db", default=None, help="Override the SQLite audit path")
    triage.add_argument(
        "--export-dir",
        default=None,
        help="Write a validated JSON export of the run to this directory",
    )
    triage.add_argument(
        "--enrich-with-llm",
        action="store_true",
        help="Refine the report through the free-tier LLM chain",
    )
    triage.set_defaults(func=cmd_triage)

    batch = subparsers.add_parser("batch", help="Triage alerts from a JSONL file")
    batch.add_argument(
        "dataset",
        nargs="?",
        type=Path,
        default=DEFAULT_DATASET,
        help="JSONL alert file (default: full benchmark)",
    )
    batch.add_argument("--limit", type=int, default=None, help="Run only the first N alerts")
    batch.add_argument("--pace", action="store_true", help="Apply gentle pacing between alerts")
    batch.add_argument("--output-json", type=Path, default=None, help="Write a result summary")
    batch.add_argument("--db-path", default=None, help="Override the DuckDB path")
    batch.add_argument("--audit-db", default=None, help="Override the SQLite audit path")
    batch.add_argument(
        "--enrich-with-llm",
        action="store_true",
        help="Refine reports through the free-tier LLM chain",
    )
    batch.set_defaults(func=cmd_batch)

    replay = subparsers.add_parser("replay", help="Stream alerts from a JSONL dataset")
    replay.add_argument(
        "dataset",
        nargs="?",
        type=Path,
        default=DEFAULT_DATASET,
        help="JSONL alert file (default: full benchmark)",
    )
    replay.add_argument(
        "--delay-sec", type=float, default=0.0, help="Delay between alerts in seconds"
    )
    replay.add_argument(
        "--source",
        choices=("sysmon", "cloudtrail", "suricata", "auth"),
        default=None,
        help="Only replay alerts from this source",
    )
    replay.add_argument(
        "--adversarial-only",
        action="store_true",
        help="Only replay cases marked as prompt injections",
    )
    replay.add_argument("--limit", type=int, default=None, help="Run only the first N matches")
    replay.add_argument("--output-json", type=Path, default=None, help="Write a result summary")
    replay.add_argument("--db-path", default=None, help="Override the DuckDB path")
    replay.add_argument("--audit-db", default=None, help="Override the SQLite audit path")
    replay.set_defaults(func=cmd_replay)

    handoff = subparsers.add_parser("handoff", help="Print a shift handoff summary")
    handoff.add_argument("--audit-db", default=None, help="Override the SQLite audit path")
    handoff.add_argument("--limit", type=int, default=None, help="Maximum runs to include")
    handoff.add_argument(
        "--format", choices=("markdown", "text"), default="markdown", help="Output format"
    )
    handoff.add_argument("--output", type=Path, default=None, help="Write to a file")
    handoff.set_defaults(func=cmd_handoff)

    metrics = subparsers.add_parser("metrics", help="Summarize the SQLite audit store")
    metrics.add_argument("--audit-db", default=None, help="Override the SQLite audit path")
    metrics.add_argument("--output-json", type=Path, default=None, help="Write metrics as JSON")
    metrics.set_defaults(func=cmd_metrics)

    init_db = subparsers.add_parser("init-db", help="Create and seed the local SOC database")
    init_db.add_argument("--db-path", default=None, help="Override the DuckDB path")
    init_db.set_defaults(func=cmd_init_db)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
