"""
Microsoft Graph resources used by the Intune connector, parsed at the
boundary. Only the fields we use are declared; others are ignored, so a new
Graph field never breaks the sync.

- managedDevice: https://learn.microsoft.com/graph/api/resources/intune-devices-manageddevice
- detectedApp:   https://learn.microsoft.com/graph/api/resources/intune-devices-detectedapp
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Graph uses this date for "never" (e.g. a device that never checked in).
_GRAPH_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


class _GraphModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class GraphManagedDevice(_GraphModel):
    id: str = Field(min_length=1)
    device_name: str = Field(alias="deviceName", min_length=1)
    operating_system: str = Field(alias="operatingSystem", default="")
    os_version: str | None = Field(alias="osVersion", default=None)
    model: str | None = None
    manufacturer: str | None = None
    serial_number: str | None = Field(alias="serialNumber", default=None)
    user_principal_name: str | None = Field(alias="userPrincipalName", default=None)
    compliance_state: str | None = Field(alias="complianceState", default=None)
    is_encrypted: bool | None = Field(alias="isEncrypted", default=None)
    last_sync: datetime | None = Field(alias="lastSyncDateTime", default=None)
    owner_type: str | None = Field(alias="managedDeviceOwnerType", default=None)
    android_security_patch_level: str | None = Field(alias="androidSecurityPatchLevel", default=None)

    @field_validator("last_sync")
    @classmethod
    def _never_is_none(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        value = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return None if value <= _GRAPH_EPOCH else value


class GraphDetectedApp(_GraphModel):
    id: str = Field(min_length=1)
    display_name: str = Field(alias="displayName", min_length=1)
    version: str | None = None
    publisher: str | None = None
    platform: str | None = None
    device_count: int = Field(alias="deviceCount", default=0, ge=0)


class GraphDeviceReference(_GraphModel):
    id: str = Field(min_length=1)


DEVICE_FIELDS = ",".join(
    field.alias or name for name, field in GraphManagedDevice.model_fields.items()
)
APP_FIELDS = ",".join(field.alias or name for name, field in GraphDetectedApp.model_fields.items())
