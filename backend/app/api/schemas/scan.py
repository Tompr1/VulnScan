"""
Request models of the ``/scan`` API.

Requests are *parsed* into these types at the HTTP boundary: once a handler
receives a ``CreateJobRequest`` its fields are known to be valid, and FastAPI
answers 422 with one entry per invalid field instead of stopping at the
first error.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, field_validator, model_validator

from app.scanner.target import InvalidTargetError, ScanTarget

NetworkScanType = Literal["internal", "external"]
WebAuthType = Literal["form", "bearer", "basic", "cookie", "header"]


def _parse_target(raw: str) -> str:
    try:
        return ScanTarget.parse(raw).raw
    except InvalidTargetError as exc:
        raise ValueError(str(exc)) from exc


class WebAuthOverride(BaseModel):
    """Per-job web authentication. The fields beyond ``type`` depend on it
    (login_url, username, token, …) and are passed through to the scanner."""

    model_config = ConfigDict(extra="allow")

    type: WebAuthType
    credential_id: PositiveInt | None = None


class CreateJobRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    profile_id: PositiveInt
    scan_type: NetworkScanType = "internal"
    asset_id: PositiveInt | None = None
    web_auth: WebAuthOverride | None = None
    # Delete the referenced credential once the scan ends (one-off pentests).
    web_auth_credential_ephemeral: bool = False

    @field_validator("target")
    @classmethod
    def _target_has_host(cls, value: str) -> str:
        return _parse_target(value)

    def job_meta(self) -> dict[str, Any] | None:
        """Metadata stored on the job for the worker, or None."""
        if self.web_auth is None:
            return None
        meta: dict[str, Any] = {"web_auth": self.web_auth.model_dump(exclude_none=True)}
        if self.web_auth_credential_ephemeral and self.web_auth.credential_id:
            meta["web_auth_credential_ephemeral"] = True
        return meta


def _as_json_object(value: Any, field_name: str) -> dict[str, Any]:
    """Accept a JSON object or its string form (legacy clients send strings)."""
    if isinstance(value, str):
        try:
            value = json.loads(value or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field_name} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return value


class ProfileFields(BaseModel):
    plugin_selection_json: dict[str, bool] = Field(default_factory=dict)
    options_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("plugin_selection_json", "options_json", mode="before")
    @classmethod
    def _json_object(cls, value: Any, info) -> dict[str, Any]:
        return _as_json_object(value, info.field_name)

    def plugin_selection_text(self) -> str:
        return json.dumps(self.plugin_selection_json)

    def options_text(self) -> str:
        return json.dumps(self.options_json)


class CreateProfileRequest(ProfileFields):
    name: str = Field(default="default", min_length=1, max_length=255)


class UpdateProfileRequest(ProfileFields):
    """Partial update: only the fields present in the request are changed."""

    name: str | None = Field(default=None, min_length=1, max_length=255)


class SuppressFindingRequest(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=64)
    reason: str = ""


class CreateScheduleRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    profile_id: PositiveInt
    name: str | None = Field(default=None, max_length=255)
    scan_type: NetworkScanType = "internal"
    schedule_type: Literal["interval", "custom"] = "interval"
    interval_hours: int = Field(default=24, ge=1)
    custom_datetime: datetime | None = None
    repeat: bool = True
    enabled: bool = True

    @field_validator("target")
    @classmethod
    def _target_has_host(cls, value: str) -> str:
        return _parse_target(value)

    @field_validator("custom_datetime")
    @classmethod
    def _naive_datetime_is_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @model_validator(mode="after")
    def _custom_schedule_needs_a_date(self) -> CreateScheduleRequest:
        if self.schedule_type == "custom" and self.custom_datetime is None:
            raise ValueError("custom_datetime is required for custom schedule type")
        return self

    @property
    def display_name(self) -> str:
        return self.name or f"Schedule: {self.target}"
