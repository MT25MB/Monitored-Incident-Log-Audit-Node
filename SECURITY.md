# Security policy

## What MILAN is for

MILAN is a local tool for learning and research about SOC alert triage. It runs
against synthetic or anonymized logs. Do not feed it real customer logs,
production telemetry, credentials, or personal data.

The bundled DuckDB dataset, the JSONL benchmarks, and the generated scenarios
are invented. IPs come from RFC 5737 documentation ranges, domains use
`example.*`, and hostnames and users are made up. If you add your own cases,
keep them synthetic or properly anonymized.

MILAN is not a production containment system. It prepares actions; a person
decides whether they happen.

## Guardrail boundaries

These boundaries are deliberate. Please treat any way around them as a
security issue.

- Investigation tools only read. The DuckDB queries use bound parameters and
  `read_only=True`, so log content cannot change stored data.
- An alert gets at most six tool calls. The graph stops planning when it
  reaches that limit.
- Raw payloads are handled as data, never instructions. Secrets and PII are
  redacted before an external model call. Injection phrases and delimiter
  breakouts are flagged, and the payload is wrapped in
  `<untrusted_log_payload>` tags.
- Containment always needs a human. `ContainmentProposal.requires_hitl` cannot
  be turned off, and a missing or invalid decision is recorded as rejected. No
  `isolate_host` or `block_ip` action executes on its own.
- Every run and every human decision is written to the local SQLite audit
  store so the steps can be reviewed later.

The guardrails reduce risk; they are not a proof of safety. When API keys are
configured, redacted payload text is sent to the chosen free-tier provider.
Review what you paste into a case file before running it.

## Reporting a security issue

Use GitHub's private vulnerability reporting on this repository: open the
**Security** tab and choose **Report a vulnerability**. If that option is not
available, open a draft security advisory or contact the maintainer privately
through GitHub. Please do not post exploit details in a public issue.

Include:

- which guardrail was bypassed or weakened,
- the steps to reproduce it using synthetic data,
- the observed result and the result you expected,
- affected file or commit, if you know it,
- a suggested fix, if you have one.

Do not include real logs, secrets, tokens, or customer identifiers in a report.
A minimal synthetic reproduction is enough.

We will review the report, keep the discussion private while we work on it,
and coordinate disclosure with you. Please give us a reasonable chance to fix
the issue before publishing details.
