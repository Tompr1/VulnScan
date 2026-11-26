"""
JobAssigner — turns a job row into the assignment an executor runs.

Shared by the platform's worker (``ScanJobRunner``) and the probe API, so a
job is prepared the same way wherever it runs: the profile it names (with
the job's web authentication override), the client's credentials that
profile names, and, for an executor away from the platform, the client's
scan allowlist.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from app.scan_jobs.assignment import ScanAssignment, assign
from app.scan_jobs.outcome import JobFailure, unknown_scan_type
from app.scan_jobs.repository import ScanJobSnapshot
from app.scanner.allowlist import AllowlistSource
from app.scanner.profile import ScanProfile
from app.scanner.resources import CredentialVault
from app.scanner.target import ScanType

# The credentials of one client, from its workspace id.
VaultFactory = Callable[[int], CredentialVault]


class ProfileSource(Protocol):
    def load_profile(self, workspace_id: int, profile_id: int | None) -> ScanProfile | None: ...


class JobNotReady(Exception):
    """The job cannot be scanned (unknown type, profile gone)."""

    def __init__(self, failure: JobFailure) -> None:
        super().__init__(failure.error)
        self.failure = failure


def scan_type_of(job: ScanJobSnapshot) -> ScanType:
    try:
        return ScanType.parse(job.scan_type)
    except ValueError:
        raise JobNotReady(unknown_scan_type(job.scan_type)) from None


class JobAssigner:
    def __init__(
        self,
        profiles: ProfileSource,
        credentials: VaultFactory,
        allowlists: AllowlistSource | None = None,
    ) -> None:
        self._profiles = profiles
        self._credentials = credentials
        self._allowlists = allowlists

    def profile_for(self, job: ScanJobSnapshot) -> ScanProfile:
        """Raises :class:`JobNotReady` for an unknown scan type or a profile
        that no longer exists."""
        if not scan_type_of(job).requires_profile:
            return ScanProfile().with_web_auth(job.web_auth)
        profile = self._profiles.load_profile(job.workspace_id, job.profile_id)
        if profile is None:
            raise JobNotReady(JobFailure(
                error="Profile not found",
                error_type="configuration",
                detail=(
                    f"Profile ID {job.profile_id} does not exist in workspace {job.workspace_id}. "
                    "Create a scan profile first under Configuration -> Profiles."
                ),
            ))
        return profile.with_web_auth(job.web_auth)

    def assignment_for(self, job: ScanJobSnapshot, profile: ScanProfile) -> ScanAssignment:
        allowlist = str(self._allowlists.policy_for(job.workspace_id)) if self._allowlists else None
        return assign(
            job.id, job.workspace_id, job.target, job.scan_type, profile, job.meta,
            self._credentials(job.workspace_id), allowlist,
        )
