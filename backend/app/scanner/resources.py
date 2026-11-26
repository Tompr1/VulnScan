"""
What a scan needs besides the network: the client's credentials and the
shared reference data (CVE catalog, KEV, CMS map, advisories…).

Plugins reach them through ``ctx.resources`` and never open the database
themselves, so the same plugins can run where there is no database at all
(a probe installed on a client's network). Each place that runs scans
provides its own implementation:

- the platform reads them from its database (``app.scanner.sql_resources``);
- tests, and later a probe, provide them from memory.

The credentials a scan receives are already bound to one client: a plugin
cannot ask for another client's credential, whatever id a profile names.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.cve.matcher import CveCatalog, InMemoryCveCatalog

PASSWORD = "password"
SSH_KEY = "ssh_key"


class CredentialError(RuntimeError):
    """The credential exists but its secret cannot be read (e.g. the key that
    encrypted it has changed)."""


@dataclass(frozen=True)
class ScanCredential:
    """A credential with its secret in clear, for the duration of one scan."""

    id: int
    name: str
    username: str
    secret_type: str
    secret: str = field(repr=False)
    passphrase: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class CredentialLabel:
    """Id and name of a credential, without its secret (for error messages)."""

    id: int
    name: str


class CredentialVault(Protocol):
    def get(self, credential_id: int) -> ScanCredential | None:
        """The credential, or None when the client has none with this id.

        Raises :class:`CredentialError` when its secret cannot be read.
        """

    def labels(self) -> list[CredentialLabel]:
        """Every credential of the client, without secrets."""


class ReferenceData(Protocol):
    def datasets(self, kind: str) -> list[list[Any]]:
        """Content of each enabled dataset of ``kind``, newest first (as
        :func:`app.cve.dataset_loader.load_json` reads it)."""

    def cve_catalog(self) -> CveCatalog:
        """The CVE catalog the NVD matchers search."""


@dataclass(frozen=True)
class ScanResources:
    credentials: CredentialVault
    reference: ReferenceData

    @classmethod
    def none(cls) -> ScanResources:
        """No credential and no reference data: plugins that need them skip."""
        return cls(InMemoryCredentialVault(), InMemoryReferenceData())


# The resources of one client's scan, from its workspace id.
ScanResourcesFactory = Callable[[int], ScanResources]


class InMemoryCredentialVault:
    def __init__(self, credentials: Iterable[ScanCredential] = ()) -> None:
        self._credentials = {credential.id: credential for credential in credentials}

    def get(self, credential_id: int) -> ScanCredential | None:
        return self._credentials.get(credential_id)

    def labels(self) -> list[CredentialLabel]:
        return [CredentialLabel(c.id, c.name) for c in self._credentials.values()]


class InMemoryReferenceData:
    def __init__(
        self,
        datasets: Mapping[str, list[list[Any]]] | None = None,
        catalog: CveCatalog | None = None,
    ) -> None:
        self._datasets = dict(datasets or {})
        self._catalog = catalog or InMemoryCveCatalog([])

    def datasets(self, kind: str) -> list[list[Any]]:
        return list(self._datasets.get(kind, []))

    def cve_catalog(self) -> CveCatalog:
        return self._catalog
