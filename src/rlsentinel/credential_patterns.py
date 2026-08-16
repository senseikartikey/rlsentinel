"""Name heuristics for 'this table/column probably holds a credential'.

Shared by the db scanner (escalates severity when a table/column name matches)
and could be reused by the repo scanner later. Deliberately a flat list, not a
regex DSL -- easy to read, easy to extend, easy to unit test exhaustively.
"""

from __future__ import annotations

CREDENTIAL_NAME_PATTERNS = [
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "session",
    "oauth",
    "private_key",
    "refresh_token",
    "access_token",
    "service_role",
    "client_secret",
    "bearer",
    "encryption_key",
]


def is_credential_shaped(name: str) -> bool:
    """Case-insensitive substring match against the pattern list."""
    lowered = name.lower()
    return any(pattern in lowered for pattern in CREDENTIAL_NAME_PATTERNS)
