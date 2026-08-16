"""Runs the queries in queries.py against a live connection and returns typed
rows. No security judgment happens here -- that's rules.py. This module's only
job is I/O plus shaping.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from rlsentinel.db import queries


@dataclass(frozen=True)
class TableInfo:
    schema_name: str
    table_name: str
    rls_enabled: bool
    rls_forced: bool


@dataclass(frozen=True)
class GrantInfo:
    schema_name: str
    table_name: str
    grantee: str
    privilege_type: str


@dataclass(frozen=True)
class RoleInfo:
    rolname: str
    rolsuper: bool
    rolbypassrls: bool
    rolcanlogin: bool


@dataclass(frozen=True)
class PolicyInfo:
    schema_name: str
    table_name: str
    policy_name: str
    permissive: str
    roles: list[str]
    cmd: str


@dataclass(frozen=True)
class ColumnInfo:
    schema_name: str
    table_name: str
    column_name: str


@dataclass(frozen=True)
class DbSnapshot:
    """Everything the rule engine needs, gathered in one read-only pass."""

    tables: list[TableInfo]
    grants: list[GrantInfo]
    roles: list[RoleInfo]
    current_role: str
    policies: list[PolicyInfo]
    columns: list[ColumnInfo]


def _rows(conn: psycopg.Connection, sql: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall()


def take_snapshot(conn: psycopg.Connection) -> DbSnapshot:
    tables = [
        TableInfo(schema_name=r[0], table_name=r[1], rls_enabled=r[2], rls_forced=r[3])
        for r in _rows(conn, queries.TABLES_AND_RLS)
    ]
    grants = [
        GrantInfo(schema_name=r[0], table_name=r[1], grantee=r[2], privilege_type=r[3])
        for r in _rows(conn, queries.TABLE_GRANTS)
    ]
    roles = [
        RoleInfo(rolname=r[0], rolsuper=r[1], rolbypassrls=r[2], rolcanlogin=r[3])
        for r in _rows(conn, queries.ROLE_FLAGS)
    ]
    current_role_rows = _rows(conn, queries.CURRENT_ROLE)
    current_role = current_role_rows[0][0] if current_role_rows else ""
    policies = [
        PolicyInfo(
            schema_name=r[0],
            table_name=r[1],
            policy_name=r[2],
            permissive=r[3],
            roles=list(r[4]) if r[4] else [],
            cmd=r[5],
        )
        for r in _rows(conn, queries.POLICIES)
    ]
    columns = [
        ColumnInfo(schema_name=r[0], table_name=r[1], column_name=r[2])
        for r in _rows(conn, queries.COLUMNS)
    ]
    return DbSnapshot(
        tables=tables,
        grants=grants,
        roles=roles,
        current_role=current_role,
        policies=policies,
        columns=columns,
    )
