"""
Product support lifecycle — the release lines ("cycles") of a product, when
their security support ends and which release is the latest of each line.

Source-independent: endoflife.date feeds it today (app.inventory.audit.catalog),
any other source producing SupportCycle objects would do.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Protocol

from packaging.version import Version

from app.cve.version_cmp import parse as parse_version

_LEADING_VERSION = re.compile(r"\d+(?:\.\d+)*")


class CatalogUnavailableError(RuntimeError):
    """The lifecycle source could not be read (network, unknown product…)."""


@dataclass(frozen=True)
class SupportCycle:
    """One release line: "11-23h2-w" for Windows, "14" for macOS, "3.12"…

    ``support_ends_on`` is None when no end is announced; ``ended`` is set
    when the source says support is over without giving a date.
    """

    name: str
    label: str = ""
    support_ends_on: date | None = None
    ended: bool = False
    latest: str | None = None

    def __post_init__(self) -> None:
        if not (self.name or "").strip():
            raise ValueError("a support cycle needs a name")
        object.__setattr__(self, "label", (self.label or "").strip() or self.name)

    def is_unsupported(self, today: date, grace_days: int = 0) -> bool:
        if self.ended:
            return True
        return self.support_ends_on is not None and today > self.support_ends_on + timedelta(days=grace_days)

    def days_left(self, today: date) -> int | None:
        """Days of support left, None when no end is known."""
        if self.ended:
            return 0
        if self.support_ends_on is None:
            return None
        return max((self.support_ends_on - today).days, 0)


class SupportCatalog(Protocol):
    def cycles(self, product: str) -> Sequence[SupportCycle]:
        """Every known cycle of ``product``; raises CatalogUnavailableError."""


def leading_version(text: str | None) -> str | None:
    """"14.4.1 (23E224)" -> "14.4.1", "Ubuntu 22.04.3 LTS" -> "22.04.3"."""
    match = _LEADING_VERSION.search(text or "")
    return match.group(0) if match else None


def comparable(text: str | None) -> Version | None:
    """A version that can be ordered, or None when it cannot be read."""
    return parse_version(text) if text else None


def is_older(installed: str | None, reference: str | None) -> bool:
    """True only when both versions can be read and ``installed`` is older."""
    mine, theirs = comparable(installed), comparable(reference)
    return mine is not None and theirs is not None and mine < theirs


def is_precise_enough(reference: str | None, installed: str | None) -> bool:
    """Whether ``reference`` says as much as ``installed``.

    endoflife.date gives "10.0.22631" as the latest Windows 11 23H2 release
    while devices report "10.0.22631.4317": the monthly update is missing, so
    the reference cannot tell an up-to-date PC from one a year behind.
    """
    mine, theirs = comparable(installed), comparable(reference)
    return mine is not None and theirs is not None and len(theirs.release) >= len(mine.release)
