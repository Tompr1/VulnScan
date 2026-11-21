"""
Request models of the /inventory API, parsed at the HTTP boundary.
"""
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

SyncFrequency = Literal["manual", "daily", "weekly"]


def _stripped_name(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        raise ValueError("name must not be blank")
    return value


class CreateIntuneConnectionRequest(BaseModel):
    """An Entra ID application with the Graph application permission
    DeviceManagementManagedDevices.Read.All (read-only)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    tenant_id: UUID
    client_id: UUID
    # SecretStr: never printed in logs, reprs or validation errors.
    client_secret: SecretStr = Field(min_length=8, max_length=512)
    sync_frequency: SyncFrequency = "daily"

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str | None) -> str | None:
        return _stripped_name(value)


class UpdateIntuneConnectionRequest(BaseModel):
    """Partial update; an absent client_secret keeps the stored one."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    tenant_id: UUID | None = None
    client_id: UUID | None = None
    client_secret: SecretStr | None = Field(default=None, min_length=8, max_length=512)
    sync_frequency: SyncFrequency | None = None
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str | None) -> str | None:
        return _stripped_name(value)
