"""Guardrails for DuckDB queries used by MILAN tools.

Every investigation query is checked before it reaches DuckDB. Only a single
read-only ``SELECT`` or ``WITH ... SELECT`` against the mock SIEM tables is
accepted. Writes, schema changes, attachment of other databases, and
file-export functions are rejected here as well as by the read-only connection.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

import duckdb

__all__ = [
    "ALLOWED_TABLES",
    "QueryGuardError",
    "QueryValidation",
    "execute_readonly",
    "readonly_connection",
    "validate_parameters",
    "validate_readonly_query",
]


#: Tables an investigation query may read.
ALLOWED_TABLES: frozenset[str] = frozenset(
    {"siem_logs", "threat_intel", "asset_inventory"}
)

_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(?:insert|update|delete|drop|create|alter|truncate|merge|replace|"
    r"grant|revoke|attach|detach|install|load|export|import|copy|vacuum|"
    r"analyze|call|pragma|set|reset|checkpoint)\b",
    re.IGNORECASE,
)

_FORBIDDEN_FUNCTIONS = re.compile(
    r"\b(?:read_[a-z_]+|sqlite_scan|postgres_scan|mysql_scan|parquet_scan|"
    r"export_database|copy_from|httpfs|glob)\s*\(",
    re.IGNORECASE,
)

_TABLE_REF = re.compile(r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_.]*)", re.IGNORECASE)
_CTE_NAME = re.compile(r"(?:\bwith|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s+as\s*\(", re.IGNORECASE)
_CTE_BODY = re.compile(
    r"((?:\bwith|,)\s*[A-Za-z_][A-Za-z0-9_]*\s+as\s*)\([^)]*\)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(r"\?")


class QueryGuardError(ValueError):
    """Raised when a query fails validation."""


@dataclass(frozen=True)
class QueryValidation:
    """Result of a successful query check."""

    sql: str
    tables: tuple[str, ...]
    normalized: str

    @property
    def table(self) -> str | None:
        """The first referenced table, when there is one."""
        return self.tables[0] if self.tables else None


def _clean_identifier(name: str) -> str:
    return name.rsplit(".", 1)[-1].strip('"').lower()


def validate_readonly_query(
    sql: str,
    *,
    allowed_tables: Sequence[str] | frozenset[str] = ALLOWED_TABLES,
) -> QueryValidation:
    """Validate one SQL statement before it reaches DuckDB.

    Args:
        sql: The statement to check.
        allowed_tables: Tables this caller is permitted to read. Defaults to
            the three mock SIEM tables.

    Raises:
        QueryGuardError: If the statement is not a single read-only query or
            references a table outside ``allowed_tables``.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise QueryGuardError("SQL must be a non-empty string")

    if "--" in sql or "/*" in sql or "*/" in sql:
        raise QueryGuardError("SQL comments are not allowed in tool queries")

    normalized = " ".join(sql.split())
    statement = normalized.rstrip("; \t\n")
    if ";" in statement:
        raise QueryGuardError("only one SQL statement is allowed")

    first = statement.split(" ", 1)[0].upper()
    if first not in {"SELECT", "WITH"}:
        raise QueryGuardError(f"only SELECT or WITH queries are allowed, got {first!r}")

    if _FORBIDDEN_KEYWORDS.search(statement):
        raise QueryGuardError("write, schema, or attachment statements are not allowed")
    if _FORBIDDEN_FUNCTIONS.search(statement):
        raise QueryGuardError("file and external-data functions are not allowed")
    if first == "WITH":
        remainder = _CTE_BODY.sub(r"\1(...)", statement)
        if not re.search(r"\bselect\b", remainder, re.IGNORECASE):
            raise QueryGuardError("a WITH query must contain a top-level SELECT")

    permitted = {_clean_identifier(name) for name in allowed_tables}
    cte_names = {_clean_identifier(name) for name in _CTE_NAME.findall(statement)}
    referenced = tuple(
        dict.fromkeys(
            _clean_identifier(name)
            for name in _TABLE_REF.findall(statement)
            if _clean_identifier(name) not in cte_names
        )
    )
    if not referenced:
        raise QueryGuardError("query must read from an allowed SIEM table")
    unknown = [name for name in referenced if name not in permitted]
    if unknown:
        raise QueryGuardError(
            "table(s) outside the allowed set: " + ", ".join(unknown)
        )

    return QueryValidation(sql=sql, tables=referenced, normalized=statement)


def validate_parameters(sql: str, params: Sequence[Any]) -> QueryValidation:
    """Validate SQL and check that bound parameters match placeholders."""
    validation = validate_readonly_query(sql)
    expected = len(_PLACEHOLDER.findall(validation.normalized))
    if expected != len(params):
        raise QueryGuardError(
            f"expected {expected} bound parameter(s), got {len(params)}"
        )
    return validation


@contextmanager
def readonly_connection(db_path: str | Path) -> Iterator[duckdb.DuckDBPyConnection]:
    """Open an existing DuckDB file with writes disabled."""
    connection = duckdb.connect(str(db_path), read_only=True)
    try:
        yield connection
    finally:
        connection.close()


def execute_readonly(
    connection: duckdb.DuckDBPyConnection,
    sql: str,
    params: Sequence[Any] = (),
    *,
    allowed_tables: Sequence[str] | frozenset[str] = ALLOWED_TABLES,
) -> Any:
    """Validate a query, then execute it with bound parameters."""
    validation = validate_parameters(sql, params)
    unexpected = [
        name for name in validation.tables if name not in {
            _clean_identifier(table) for table in allowed_tables
        }
    ]
    if unexpected:
        raise QueryGuardError(
            "table(s) outside this tool's scope: " + ", ".join(unexpected)
        )
    return connection.execute(sql, list(params))
