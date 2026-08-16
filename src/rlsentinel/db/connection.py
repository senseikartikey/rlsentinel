"""Connection handling with a hard safety belt: this tool must never be able
to mutate the target database, even by bug.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg


@contextmanager
def read_only_connection(dsn: str, timeout_seconds: int = 5) -> Iterator[psycopg.Connection]:
    """Yield a psycopg connection inside a READ ONLY transaction with a short
    statement_timeout. The transaction is always rolled back on exit -- there
    is no code path in this tool that commits.
    """
    conn = psycopg.connect(dsn, connect_timeout=timeout_seconds)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = '{int(timeout_seconds) * 1000}'")
            cur.execute("BEGIN")
            cur.execute("SET TRANSACTION READ ONLY")
        yield conn
    finally:
        conn.rollback()
        conn.close()
