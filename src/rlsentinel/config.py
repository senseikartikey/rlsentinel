"""Resolves DATABASE_URL from flag or env var. Flag wins if both are given."""

from __future__ import annotations

import os


def resolve_db_url(flag_value: str | None) -> str | None:
    if flag_value:
        return flag_value
    return os.environ.get("DATABASE_URL")
