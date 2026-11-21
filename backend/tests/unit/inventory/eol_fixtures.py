"""
Excerpts of endoflife.date answers (api/<product>.json), as served in
November 2026, and a StaticSupportCatalog built from them.
"""
from __future__ import annotations

from app.inventory.audit.catalog import EndOfLifeCycle
from app.inventory.audit.lifecycle import CatalogUnavailableError, SupportCycle

WINDOWS = [
    {"cycle": "11-25h2-e", "releaseLabel": "11 25H2 (E)", "eol": "2028-10-10", "latest": "10.0.26200"},
    {"cycle": "11-25h2-w", "releaseLabel": "11 25H2 (W)", "eol": "2027-10-12", "latest": "10.0.26200"},
    {"cycle": "11-24h2-iot-lts", "releaseLabel": "11 24H2 IoT", "eol": "2034-10-10", "latest": "10.0.26100"},
    {"cycle": "11-24h2-e-lts", "releaseLabel": "11 24H2 (E)", "eol": "2029-10-09", "latest": "10.0.26100"},
    {"cycle": "11-24h2-e", "releaseLabel": "11 24H2 (E)", "eol": "2027-10-12", "latest": "10.0.26100"},
    {"cycle": "11-24h2-w", "releaseLabel": "11 24H2 (W)", "eol": "2026-10-13", "latest": "10.0.26100"},
    {"cycle": "11-23h2-e", "releaseLabel": "11 23H2 (E)", "eol": "2026-11-10", "latest": "10.0.22631"},
    {"cycle": "11-23h2-w", "releaseLabel": "11 23H2 (W)", "eol": "2025-11-11", "latest": "10.0.22631"},
    {"cycle": "10-22h2", "releaseLabel": "10 22H2", "eol": "2025-10-14", "latest": "10.0.19045"},
    {"cycle": "10-21h2-e-lts", "releaseLabel": "10 21H2 (E)", "eol": "2027-01-12", "latest": "10.0.19044"},
]
MACOS = [
    {"cycle": "26", "codename": "Tahoe", "eol": False, "latest": "26.7.3"},
    {"cycle": "15", "codename": "Sequoia", "eol": False, "latest": "15.8.3"},
    {"cycle": "14", "codename": "Sonoma", "eol": "2026-09-14", "latest": "14.8.9"},
    {"cycle": "10.15", "codename": "Catalina", "eol": "2026-02-02", "latest": "10.15.8"},
]
IOS = [
    {"cycle": "26", "eol": False, "latest": "26.7.3"},
    {"cycle": "18", "eol": False, "latest": "18.7.12"},
    {"cycle": "17", "eol": "2025-05-13", "latest": "17.7.7"},
]
ANDROID = [
    {"cycle": "16", "eol": False},
    {"cycle": "13", "eol": "2026-03-02"},
    {"cycle": "12.1", "eol": "2025-03-03"},
    {"cycle": "12", "eol": "2025-03-03"},
    {"cycle": "4.4", "eol": True},
]
UBUNTU = [
    {"cycle": "24.04", "codename": "Noble Numbat", "lts": True, "eol": "2029-05-31", "latest": "24.04.3"},
    {"cycle": "22.04", "codename": "Jammy Jellyfish", "lts": True, "eol": "2027-06-01", "latest": "22.04.5"},
    {"cycle": "20.04", "codename": "Focal Fossa", "lts": True, "eol": "2025-05-29", "latest": "20.04.6"},
]
CHROME = [
    {"cycle": "158", "releaseDate": "2026-11-17", "eol": "2026-12-01"},
    {"cycle": "157", "releaseDate": "2026-11-03", "eol": "2026-11-17"},
    {"cycle": "156", "releaseDate": "2026-10-20", "eol": "2026-11-03"},
    {"cycle": "154", "releaseDate": "2026-09-22", "eol": "2026-10-06"},
]
FIREFOX = [
    {"cycle": "160", "eol": "2026-11-24", "latest": "160.0.1"},
    {"cycle": "140", "eol": "2027-09-14", "latest": "140.5.0", "lts": True},
]
NOTEPAD_PLUS_PLUS = [
    {"cycle": "8.9", "eol": False, "latest": "8.9.9.1"},
    {"cycle": "8.8", "eol": "2025-12-27", "latest": "8.8.9"},
]
OFFICE = [
    {"cycle": "2024", "eol": "2029-10-09"},
    {"cycle": "2021-ltsc", "releaseLabel": "2021 LTSC", "eol": "2026-10-13"},
    {"cycle": "2021", "eol": "2026-10-13"},
    {"cycle": "2019", "eol": "2025-10-14"},
]

ALL = {
    "windows": WINDOWS, "macos": MACOS, "ios": IOS, "ipados": IOS, "android": ANDROID, "ubuntu": UBUNTU,
    "chrome": CHROME, "firefox": FIREFOX, "notepad-plus-plus": NOTEPAD_PLUS_PLUS, "office": OFFICE,
}


def cycles(entries: list[dict]) -> tuple[SupportCycle, ...]:
    return tuple(EndOfLifeCycle.model_validate(entry).to_cycle() for entry in entries)


class StaticSupportCatalog:
    """Stub SupportCatalog: canned cycles per product; ``unavailable``
    products raise like an unreachable endoflife.date. Records the products
    asked for (spy)."""

    def __init__(self, products: dict[str, list[dict]] | None = None, unavailable: tuple[str, ...] = ()) -> None:
        self._products = {name: cycles(entries) for name, entries in (ALL if products is None else products).items()}
        self._unavailable = set(unavailable)
        self.requested: list[str] = []

    def cycles(self, product: str) -> tuple[SupportCycle, ...]:
        self.requested.append(product)
        if product in self._unavailable:
            raise CatalogUnavailableError(f"endoflife.date unreachable for {product}")
        return self._products.get(product, ())
