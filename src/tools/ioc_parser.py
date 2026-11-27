"""Deterministic extraction and normalization of indicators of compromise.

Parsing runs on the output of the secret/PII redactor, so credential-like strings
never become indicators. The helpers are pure, ordered, and de-duplicated.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from src.guardrails.sanitizer import redact_secrets

__all__ = [
    "IocSet",
    "extract_iocs",
    "extract_iocs_from_rows",
    "primary_indicator",
]


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

_WINDOWS_PROCESSES = (
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "procdump.exe",
    "lsass.exe",
    "schtasks.exe",
    "wmic.exe",
    "svchost.exe",
    "explorer.exe",
    "rundll32.exe",
    "mshta.exe",
    "certutil.exe",
)
_LINUX_PROCESSES = (
    "sshd",
    "bash",
    "sh",
    "curl",
    "wget",
    "python3",
    "python",
    "sudo",
    "cron",
    "systemd",
    "nginx",
)
_KNOWN_PROCESS_NAMES = frozenset(name.lower() for name in _WINDOWS_PROCESSES + _LINUX_PROCESSES)
_NON_DOMAIN_TLDS = frozenset(
    {"exe", "dll", "ps1", "sh", "py", "bin", "log", "json", "yaml", "yml", "csv", "xml"}
)
_PROCESS_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(name) for name in _KNOWN_PROCESS_NAMES) + r")\b",
    re.IGNORECASE,
)

_ROW_FIELDS = (
    "message",
    "raw_payload",
    "source_ip",
    "dest_ip",
    "destination_ip",
    "indicator",
    "ip_address",
    "hostname",
    "user",
    "target",
)


@dataclass(frozen=True)
class IocSet:
    """Normalized indicators, each tuple in first-seen order."""

    ip_addresses: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    sha256_hashes: tuple[str, ...] = ()
    md5_hashes: tuple[str, ...] = ()
    process_names: tuple[str, ...] = ()

    @property
    def hashes(self) -> tuple[str, ...]:
        """SHA-256 values followed by MD5 values."""
        return self.sha256_hashes + self.md5_hashes

    @property
    def all_indicators(self) -> tuple[str, ...]:
        """Hashes, domains, then IPs; excludes process names."""
        return self.hashes + self.domains + self.ip_addresses

    def to_dict(self) -> dict[str, list[str]]:
        """Plain lists for JSON or graph state."""
        return {
            "ip_addresses": list(self.ip_addresses),
            "domains": list(self.domains),
            "sha256_hashes": list(self.sha256_hashes),
            "md5_hashes": list(self.md5_hashes),
            "process_names": list(self.process_names),
        }


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def extract_iocs(text: str) -> IocSet:
    """Extract IOCs from text after removing secret-like spans."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    cleaned = redact_secrets(text)[0]

    ips = _ordered_unique(value for value in _IPV4_RE.findall(cleaned) if _valid_ipv4(value))
    domains = _ordered_unique(
        value.lower().rstrip(".")
        for value in _DOMAIN_RE.findall(cleaned)
        if not _valid_ipv4(value)
        and value.lower().rstrip(".") not in _KNOWN_PROCESS_NAMES
        and value.lower().rstrip(".").rsplit(".", 1)[-1] not in _NON_DOMAIN_TLDS
    )
    return IocSet(
        ip_addresses=ips,
        domains=domains,
        sha256_hashes=_ordered_unique(_SHA256_RE.findall(cleaned)),
        md5_hashes=_ordered_unique(_MD5_RE.findall(cleaned)),
        process_names=_ordered_unique(value.lower() for value in _PROCESS_RE.findall(cleaned)),
    )


def extract_iocs_from_rows(rows: Iterable[Mapping[str, Any]]) -> IocSet:
    """Aggregate IOCs from DuckDB rows without mutating them."""
    texts: list[str] = []
    for row in rows:
        for field_name in _ROW_FIELDS:
            value = row.get(field_name)
            if isinstance(value, str) and value:
                texts.append(value)

    parsed = [extract_iocs(text) for text in texts]
    return IocSet(
        ip_addresses=_ordered_unique(item for result in parsed for item in result.ip_addresses),
        domains=_ordered_unique(item for result in parsed for item in result.domains),
        sha256_hashes=_ordered_unique(item for result in parsed for item in result.sha256_hashes),
        md5_hashes=_ordered_unique(item for result in parsed for item in result.md5_hashes),
        process_names=_ordered_unique(item for result in parsed for item in result.process_names),
    )


def primary_indicator(iocs: IocSet, *, prefer_domain: bool = False) -> str | None:
    """Choose one indicator for an intel lookup.

    Hashes take precedence over domains, which take precedence over IPs. A
    domain can be preferred for DNS-centric investigations.
    """
    if iocs.sha256_hashes:
        return iocs.sha256_hashes[0]
    if iocs.md5_hashes:
        return iocs.md5_hashes[0]
    if prefer_domain and iocs.domains:
        return iocs.domains[0]
    if iocs.domains:
        return iocs.domains[0]
    if iocs.ip_addresses:
        return iocs.ip_addresses[0]
    return None
