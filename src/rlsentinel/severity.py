"""Severity ordering shared by db and repo findings, and by --fail-on."""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Higher value = more severe. IntEnum so comparisons and sorting just work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


# --fail-on accepts "none" (never fail) in addition to real severities.
FAIL_ON_CHOICES = ["critical", "high", "medium", "low", "none"]


def meets_threshold(severity: Severity, fail_on: str) -> bool:
    """True if `severity` is at or above the --fail-on threshold."""
    if fail_on == "none":
        return False
    threshold = Severity[fail_on.upper()]
    return severity >= threshold
