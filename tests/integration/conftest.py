from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "sql"


def _docker_available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=False)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="session")
def postgres_dsn():
    if not _docker_available():
        pytest.skip("Docker is not available; skipping integration tests")

    import psycopg
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16") as pg:
        dsn = pg.get_connection_url().replace("postgresql+psycopg2", "postgresql")
        seed_sql = (FIXTURES_DIR / "seed.sql").read_text()
        conn = psycopg.connect(dsn, autocommit=True)
        try:
            with conn.cursor() as cur:
                cur.execute(seed_sql)
        finally:
            conn.close()
        yield dsn
