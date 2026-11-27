"""Tests for the DuckDB query guard and its wiring into investigation tools."""

from __future__ import annotations

import sys
from pathlib import Path

import duckdb
import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.cli import main  # noqa: E402
from src.tools.db_guard import (  # noqa: E402
    ALLOWED_TABLES,
    QueryGuardError,
    execute_readonly,
    readonly_connection,
    validate_parameters,
    validate_readonly_query,
)
from src.tools.siem import check_threat_intel, init_soc_db  # noqa: E402


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM siem_logs",
        "SELECT log_id FROM siem_logs WHERE alert_id = ? ORDER BY event_time DESC LIMIT ?",
        "WITH recent AS (SELECT * FROM siem_logs) SELECT * FROM recent",
    ],
)
def test_valid_read_queries_pass(sql: str) -> None:
    result = validate_readonly_query(sql)
    assert result.normalized
    assert "siem_logs" in result.tables


def test_expected_tables_are_the_mock_siem_set() -> None:
    assert ALLOWED_TABLES == {"siem_logs", "threat_intel", "asset_inventory"}


@pytest.mark.parametrize(
    "sql",
    [
        "DROP TABLE siem_logs",
        "INSERT INTO siem_logs VALUES (?)",
        "UPDATE siem_logs SET severity = ?",
        "DELETE FROM siem_logs",
        "CREATE TABLE evil (id INTEGER)",
        "ALTER TABLE siem_logs ADD COLUMN x INTEGER",
        "TRUNCATE siem_logs",
        "COPY siem_logs TO '/tmp/leak.csv'",
        "ATTACH 'other.duckdb' AS other",
        "INSTALL httpfs",
        "SELECT * FROM read_csv_auto('/etc/passwd')",
        "SELECT * FROM sqlite_scan('x.db', 'users')",
        "SELECT * FROM users",
        "SELECT 1",
        "SELECT * FROM siem_logs; DROP TABLE siem_logs",
        "SELECT * FROM siem_logs -- trailing note",
        "SELECT * FROM /* comment */ siem_logs",
    ],
)
def test_unsafe_queries_are_rejected(sql: str) -> None:
    with pytest.raises(QueryGuardError):
        validate_readonly_query(sql)


def test_with_query_must_contain_top_level_select() -> None:
    with pytest.raises(QueryGuardError):
        validate_readonly_query("WITH x AS (SELECT * FROM siem_logs) UPDATE x SET a = 1")
    with pytest.raises(QueryGuardError, match="top-level SELECT"):
        validate_readonly_query("WITH x AS (SELECT * FROM siem_logs) VALUES (1)")


def test_parameter_count_must_match_placeholders() -> None:
    sql = "SELECT * FROM siem_logs WHERE alert_id = ? LIMIT ?"
    assert validate_parameters(sql, ["ALT-1", 10]).tables == ("siem_logs",)
    with pytest.raises(QueryGuardError, match="bound parameter"):
        validate_parameters(sql, ["ALT-1"])


def test_execute_readonly_requires_table_in_tool_scope(tmp_path: Path) -> None:
    db = tmp_path / "guard.duckdb"
    connection = duckdb.connect(str(db))
    connection.execute("CREATE TABLE siem_logs (log_id VARCHAR)")
    connection.execute("CREATE TABLE threat_intel (indicator VARCHAR)")
    connection.execute("INSERT INTO siem_logs VALUES ('LOG-1')")
    connection.close()

    with readonly_connection(db) as connection:
        rows = execute_readonly(
            connection, "SELECT log_id FROM siem_logs", allowed_tables=("siem_logs",)
        ).fetchall()
        assert rows == [("LOG-1",)]

        with pytest.raises(QueryGuardError, match="tool's scope"):
            execute_readonly(
                connection,
                "SELECT indicator FROM threat_intel",
                allowed_tables=("siem_logs",),
            )

        with pytest.raises(QueryGuardError):
            execute_readonly(
                connection, "DELETE FROM siem_logs", allowed_tables=("siem_logs",)
            )

    with readonly_connection(db) as connection:
        assert execute_readonly(
            connection, "SELECT COUNT(*) FROM siem_logs", allowed_tables=("siem_logs",)
        ).fetchone()[0] == 1


def test_siem_tools_still_work_through_guard(tmp_path: Path) -> None:
    db = init_soc_db(tmp_path / "soc.duckdb")
    result = check_threat_intel("203.0.113.42", db_path=db)
    assert result.count == 1
    assert result.trace.success is True


def test_cli_init_db_uses_guarded_queries(tmp_path: Path, capsys) -> None:
    assert main(["init-db", "--db-path", str(tmp_path / "soc.duckdb")]) == 0
    assert "siem_logs=" in capsys.readouterr().out
