"""Pre-release checks for links and the benchmark dataset.

Run with ``python -m scripts.check_repo`` from the repository root. The module
is also importable so tests can exercise the checks with temporary files.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.schemas import SecurityAlert  # noqa: E402

__all__ = [
    "CheckResult",
    "check_dataset",
    "check_links",
    "main",
    "render_checklist",
    "run_checks",
]


class _LinkParser(HTMLParser):
    """Collect local ``href`` and ``src`` values from HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        for key in ("href", "src"):
            value = values.get(key)
            if value:
                self.targets.append(value)


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one repository check."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class Report:
    """Aggregate of all checks."""

    checks: tuple[CheckResult, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)


def _is_local(target: str) -> bool:
    return not target.startswith(("http://", "https://", "#", "mailto:", "data:"))


def _markdown_links(text: str) -> list[str]:
    result: list[str] = []
    index = 0
    while True:
        start = text.find("](", index)
        if start < 0:
            break
        end = text.find(")", start + 2)
        if end < 0:
            break
        result.append(text[start + 2 : end].strip())
        index = end + 1
    return result


def check_links(root: str | Path = _ROOT) -> CheckResult:
    """Check local links in README files and the Pages HTML/CSS."""
    base = Path(root)
    documents: list[tuple[Path, list[str]]] = []

    for relative in ("README.md", "docs/README.md"):
        path = base / relative
        if not path.exists():
            return CheckResult("document links", False, f"missing {relative}")
        documents.append((path, _markdown_links(path.read_text(encoding="utf-8"))))

    site = base / "docs/index.html"
    if not site.exists():
        return CheckResult("site links", False, "missing docs/index.html")
    parser = _LinkParser()
    parser.feed(site.read_text(encoding="utf-8"))
    documents.append((site, parser.targets))

    missing: list[str] = []
    checked = 0
    for document, targets in documents:
        for target in targets:
            if not _is_local(target):
                continue
            checked += 1
            path_part = target.split("#", 1)[0]
            if path_part and not (document.parent / path_part).exists():
                missing.append(f"{document.relative_to(base)} -> {target}")

    if missing:
        return CheckResult("local links", False, "; ".join(missing))
    return CheckResult("local links", True, f"{checked} local reference(s) resolved")


def check_dataset(path: str | Path) -> CheckResult:
    """Validate every line as JSON with a nested SecurityAlert."""
    dataset = Path(path)
    if not dataset.exists():
        return CheckResult("benchmark dataset", False, f"missing {dataset}")

    try:
        lines = dataset.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return CheckResult("benchmark dataset", False, str(exc))

    count = 0
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            return CheckResult("benchmark dataset", False, f"line {line_number}: {exc.msg}")

        alert_payload = payload.get("alert") if isinstance(payload, dict) else payload
        try:
            SecurityAlert.model_validate(alert_payload)
        except Exception as exc:
            return CheckResult(
                "benchmark dataset", False, f"line {line_number}: invalid SecurityAlert: {exc}"
            )
        count += 1

    if count == 0:
        return CheckResult("benchmark dataset", False, "no cases found")
    return CheckResult("benchmark dataset", True, f"{count} case(s) validated")


def run_checks(
    *, root: str | Path = _ROOT, dataset: str | Path | None = None
) -> Report:
    """Run every check and collect the results."""
    target = Path(dataset) if dataset is not None else Path(root) / "evals/datasets/full_benchmark.jsonl"
    return Report(checks=(check_links(root), check_dataset(target)))


def render_checklist(report: Report) -> str:
    """Render a compact pass/fail checklist."""
    lines = ["Repository check"]
    for check in report.checks:
        mark = "PASS" if check.passed else "FAIL"
        suffix = f" ({check.detail})" if check.detail else ""
        lines.append(f"[{mark}] {check.name}{suffix}")
    verdict = "PASS" if report.passed else "FAIL"
    lines.append(f"Overall: {verdict}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Check repository links and benchmark data")
    parser.add_argument("--root", type=Path, default=_ROOT, help="Repository root")
    parser.add_argument("--dataset", type=Path, default=None, help="Benchmark JSONL path")
    args = parser.parse_args(argv)

    report = run_checks(root=args.root, dataset=args.dataset)
    print(render_checklist(report))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
