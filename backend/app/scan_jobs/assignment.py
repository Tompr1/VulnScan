"""
What travels between the platform and whatever executes a scan.

- :class:`ScanAssignment`: everything needed to run one job (target, type,
  profile, scanner configuration, the credentials its profile names), so the
  executing side needs neither the database nor the platform's secret key;
- :class:`ScanReport`: what the execution produced (raw findings) or why it
  failed; the platform scores, saves and announces them.

Today the platform's own worker executes the assignment. A probe installed
on a client's network will receive the same assignment and send back the
same report: both have a plain ``to_dict``/``from_dict`` form.

An assignment's dictionary holds credentials IN CLEAR: it must only travel
over an encrypted, authenticated channel, and never be logged or stored.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from app.scan_jobs.outcome import JobFailure
from app.scanner.plugins.base import Finding
from app.scanner.profile import ScanProfile
from app.scanner.resources import (
    CredentialError,
    CredentialLabel,
    CredentialVault,
    InMemoryCredentialVault,
    ScanCredential,
)

# Key of the job metadata naming the inventory connection to collect.
INVENTORY_CONNECTION_KEY = "inventory_connection_id"


def referenced_credential_ids(options: Mapping[str, Any]) -> list[int]:
    """Ids of the credentials a profile's options name, as plugins read them:
    ``auth.ssh_credential_id`` (SSH inventory, CIS benchmark, server SCA),
    ``ssh_auth.ssh_credential_id`` (server SCA) and ``web_auth.credential_id``
    (web authentication). A plugin reading another key must be added here,
    or it will not get its credential."""
    ids: set[int] = set()
    for section, key in (("auth", "ssh_credential_id"), ("ssh_auth", "ssh_credential_id"), ("web_auth", "credential_id")):
        block = options.get(section)
        if not isinstance(block, Mapping):
            continue
        try:
            ids.add(int(block.get(key)))
        except (TypeError, ValueError):
            continue
    return sorted(ids)


@dataclass(frozen=True)
class ScanAssignment:
    job_id: int
    workspace_id: int
    target: str
    scan_type: str
    profile: ScanProfile = field(default_factory=ScanProfile)
    meta: dict[str, Any] = field(default_factory=dict)
    credentials: tuple[ScanCredential, ...] = ()
    credential_labels: tuple[CredentialLabel, ...] = ()
    # Credentials the profile names whose secret could not be read, by id.
    credential_errors: dict[int, str] = field(default_factory=dict)
    # The client's scan allowlist, in the ALLOWLIST setting form ("*" allows
    # everything). None when the executor applies its own (platform worker);
    # an executor elsewhere must refuse an assignment without one.
    allowlist: str | None = None

    def scanner_config(self, key: str) -> dict[str, Any]:
        config = self.meta.get(key)
        return config if isinstance(config, dict) else {}

    def credential_vault(self) -> InMemoryCredentialVault:
        return InMemoryCredentialVault(self.credentials, self.credential_labels, self.credential_errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "workspace_id": self.workspace_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "profile": {"plugin_selection": dict(self.profile.plugin_selection), "options": self.profile.options},
            "meta": self.meta,
            "credentials": [asdict(c) for c in self.credentials],
            "credential_labels": [asdict(label) for label in self.credential_labels],
            "credential_errors": {str(k): v for k, v in self.credential_errors.items()},
            "allowlist": self.allowlist,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanAssignment:
        profile = data.get("profile") or {}
        return cls(
            job_id=int(data["job_id"]),
            workspace_id=int(data["workspace_id"]),
            target=str(data["target"]),
            scan_type=str(data["scan_type"]),
            profile=ScanProfile(
                plugin_selection={k: bool(v) for k, v in (profile.get("plugin_selection") or {}).items()},
                options=dict(profile.get("options") or {}),
            ),
            meta=dict(data.get("meta") or {}),
            credentials=tuple(ScanCredential(**c) for c in data.get("credentials") or ()),
            credential_labels=tuple(CredentialLabel(**label) for label in data.get("credential_labels") or ()),
            credential_errors={int(k): str(v) for k, v in (data.get("credential_errors") or {}).items()},
            allowlist=data.get("allowlist"),
        )


def assign(
    job_id: int,
    workspace_id: int,
    target: str,
    scan_type: str,
    profile: ScanProfile,
    meta: Mapping[str, Any],
    vault: CredentialVault,
    allowlist: str | None = None,
) -> ScanAssignment:
    """The assignment of a job, with the client's credentials its profile names."""
    credentials, errors = [], {}
    for credential_id in referenced_credential_ids(profile.options):
        try:
            credential = vault.get(credential_id)
        except CredentialError as exc:
            errors[credential_id] = str(exc)
            continue
        if credential is not None:
            credentials.append(credential)
    return ScanAssignment(
        job_id=job_id,
        workspace_id=workspace_id,
        target=target,
        scan_type=scan_type,
        profile=profile,
        meta=dict(meta),
        credentials=tuple(credentials),
        credential_labels=tuple(vault.labels()),
        credential_errors=errors,
        allowlist=allowlist,
    )


_FINDING_FIELDS = tuple(f.name for f in fields(Finding))


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return asdict(finding)


def finding_from_dict(data: Mapping[str, Any]) -> Finding:
    """Unknown keys are ignored: a newer probe may send fields this platform
    does not know yet."""
    values = {name: data[name] for name in _FINDING_FIELDS if name in data}
    values["references"] = list(values.get("references") or [])
    return Finding(**values)


@dataclass(frozen=True)
class ScanReport:
    job_id: int
    findings: tuple[Finding, ...] = ()
    failure: JobFailure | None = None

    @classmethod
    def succeeded(cls, job_id: int, findings: Iterable[Finding]) -> ScanReport:
        return cls(job_id, tuple(findings))

    @classmethod
    def failed(cls, job_id: int, failure: JobFailure) -> ScanReport:
        return cls(job_id, failure=failure)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "findings": [finding_to_dict(f) for f in self.findings],
            "failure": self.failure.to_dict() if self.failure else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanReport:
        failure = data.get("failure")
        return cls(
            job_id=int(data["job_id"]),
            findings=tuple(finding_from_dict(f) for f in data.get("findings") or ()),
            failure=JobFailure.from_dict(failure) if failure else None,
        )
