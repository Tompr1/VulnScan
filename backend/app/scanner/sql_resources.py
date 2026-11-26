"""
Scan resources read from the platform's database: the client's encrypted
credentials and the shared reference datasets.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from sqlalchemy.orm import Session

from app.core.crypto import decrypt_str
from app.cve.catalogs import cve_catalog
from app.cve.dataset_loader import load_json
from app.cve.matcher import CveCatalog
from app.cve.reference_datasets import enabled_dataset_paths
from app.db import models
from app.scanner.resources import CredentialError, CredentialLabel, ScanCredential

SessionFactory = Callable[[], Session]


class SqlCredentialVault:
    """The credentials of one client; another client's ids are not found."""

    def __init__(
        self,
        session_factory: SessionFactory,
        workspace_id: int,
        decrypt: Callable[[str], str] = decrypt_str,
    ) -> None:
        self._session_factory = session_factory
        self._workspace_id = workspace_id
        self._decrypt = decrypt

    def get(self, credential_id: int) -> ScanCredential | None:
        try:
            credential_id = int(credential_id)
        except (TypeError, ValueError):
            return None
        with self._session_factory() as db:
            row = (
                db.query(models.Credential)
                .filter(models.Credential.id == credential_id, models.Credential.workspace_id == self._workspace_id)
                .first()
            )
            if row is None:
                return None
            name, username, secret_type = row.name, row.username or "", row.secret_type
            secret_enc, passphrase_enc = row.secret_enc or "", row.passphrase_enc
        try:
            secret = self._decrypt(secret_enc)
        except Exception as exc:  # any failure of the cipher means the same thing to the user
            raise CredentialError(
                f"Cannot decrypt credential #{credential_id} - the SECRET_KEY may have changed "
                "since this credential was saved. Delete the credential and re-add it "
                f"in the Credentials page. Detail: {exc}"
            ) from exc
        return ScanCredential(
            id=credential_id,
            name=name,
            username=username,
            secret_type=secret_type,
            secret=secret,
            passphrase=self._passphrase(passphrase_enc),
        )

    def labels(self) -> list[CredentialLabel]:
        with self._session_factory() as db:
            rows = (
                db.query(models.Credential.id, models.Credential.name)
                .filter(models.Credential.workspace_id == self._workspace_id)
                .order_by(models.Credential.id)
            )
            return [CredentialLabel(row.id, row.name) for row in rows]

    def _passphrase(self, passphrase_enc: str | None) -> str | None:
        # An unreadable passphrase is dropped: the key may not need one.
        if not passphrase_enc:
            return None
        try:
            return self._decrypt(passphrase_enc)
        except Exception:
            return None


class SqlReferenceData:
    """The reference datasets shared by every client of the platform."""

    def __init__(
        self,
        session_factory: SessionFactory,
        load_dataset: Callable[[str], Iterable[Any]] = load_json,
    ) -> None:
        self._session_factory = session_factory
        self._load_dataset = load_dataset

    def datasets(self, kind: str) -> list[list[Any]]:
        with self._session_factory() as db:
            paths = enabled_dataset_paths(db, kind)
        return [self._load_dataset(path) for path in paths]

    def cve_catalog(self) -> CveCatalog:
        return cve_catalog(self._session_factory, self._load_dataset)

