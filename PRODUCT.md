# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

SOC analysts and security engineers who want to try a guarded triage agent locally, plus developers evaluating the open-source project. *(Inferred from the README and the site's existing quickstart; not confirmed in an interview.)*

## Product Purpose

MILAN triages a security alert through a bounded, read-only investigation, produces a structured report, and pauses for human approval before any containment action. Success means a person can reproduce a run offline, inspect every step, and understand why a verdict was reached. *(Inferred from the README and the confirmed site brief.)*

## Positioning

A triage agent built around constraints rather than capability: raw payloads are treated as untrusted data, tools cannot write, the run is capped at six tool calls, and containment always needs a human. It runs for $0 with local DuckDB data and free-tier model routing. *(Product facts from README; positioning phrasing inferred.)*

## Operating Context

Local Python project. Investigation data lives in DuckDB (`data/milan_soc.duckdb`), audit and step traces in SQLite (`data/milan_audit.db`). Interfaces: `python -m src.cli`, `streamlit run src/ui/app.py`, and a static documentation site published from `docs/`. Evaluation uses JSONL datasets and produces Markdown plus JSON artifacts. *(Repository evidence.)*

## Capabilities and Constraints

- Synthetic or anonymized logs only. No real customer logs, secrets, or production telemetry.
- Read-only investigation tools with bound parameters; 6-call hard cap.
- Mandatory HITL approval for containment; missing or invalid decisions fail closed as rejected.
- Zero paid services. GitHub Pages serves the static site with no build step.
- The site must keep working as plain HTML/CSS with local assets only.

## Brand Commitments

Name: **MILAN: Monitored Incident & Log Audit Node**. Logo asset at `docs/logo.png` with a text fallback. Prose must stay plain and human, without marketing filler. Palette family (paper, ink, brick red, deep green) was explicitly requested as restrained and suited to SOC work. *(Confirmed by the user's brief and prior instructions.)*

## Evidence on Hand

- 45-case benchmark in `evals/datasets/full_benchmark.jsonl`: 20 true positives, 15 false positives, 10 prompt-injection cases.
- Measured run in `evals/results.md`: 100% classification accuracy, 0% false positives, 100% MITRE exact match, 100% injection block rate, 100% budget compliance, p50 0.036 ms / p95 29.758 ms, $0.00 cost, dated 2026-11-26.
- Real synthetic cases used on the site: ALT-2004 (SSH brute force, pending HITL actions), ALT-3002 (benign scanner), ALT-4001 (injected verdict request).
- No customer metrics, testimonials, logos, or case studies exist. None may be invented. *(Repository evidence.)*

## Product Principles

- Show the mechanism, not a promise: the page should demonstrate a triage report and a paused containment gate using real synthetic data.
- Constraints are the product story: untrusted input, read-only tools, step cap, human approval.
- Evidence stays checkable: every number and case ID on the site traces to the benchmark files.
- Zero cost and zero build complexity are commitments, not claims to soften.

## Accessibility & Inclusion

The static site must remain keyboard navigable and readable without JavaScript. Reduced-motion support is required for any motion added. *(Inferred from static-site constraints; no separate product requirement was stated.)*
