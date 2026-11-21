"""
Intune inventory source: managed devices and the applications on them.

Graph v1.0 exposes installed software as "detected apps" (one entry per
name + version, with the devices that have it). Reading them is behind the
AppInventoryReader protocol so the strategy can change (Intune's report
export API suits very large tenants) without touching the source.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import ValidationError

from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.inventory.intune.graph_client import GraphClient
from app.inventory.intune.schemas import (
    APP_FIELDS,
    DEVICE_FIELDS,
    GraphDetectedApp,
    GraphDeviceReference,
    GraphManagedDevice,
)

logger = logging.getLogger(__name__)

SOURCE_NAME = "intune"
DEVICES_PATH = "/deviceManagement/managedDevices"
DETECTED_APPS_PATH = "/deviceManagement/detectedApps"


@dataclass(frozen=True)
class AppInventory:
    apps_by_device: dict[str, tuple[InstalledApp, ...]]
    skipped: int = 0


class AppInventoryReader(Protocol):
    def read(self) -> AppInventory: ...


class DetectedAppsReader:
    """One request for the app list, then one per app for its devices."""

    def __init__(self, client: GraphClient) -> None:
        self._client = client

    def read(self) -> AppInventory:
        apps_by_device: dict[str, list[InstalledApp]] = defaultdict(list)
        skipped = 0
        for raw in self._client.get_all(DETECTED_APPS_PATH, {"$select": APP_FIELDS}):
            parsed = _parse(GraphDetectedApp, raw)
            if parsed is None:
                skipped += 1
                continue
            if parsed.device_count == 0:
                continue
            app = InstalledApp(parsed.display_name, parsed.version, parsed.publisher)
            for device in self._client.get_all(f"{DETECTED_APPS_PATH}/{parsed.id}/managedDevices", {"$select": "id"}):
                reference = _parse(GraphDeviceReference, device)
                if reference is not None:
                    apps_by_device[reference.id].append(app)
        return AppInventory({device: tuple(apps) for device, apps in apps_by_device.items()}, skipped)


class IntuneSource:
    name = SOURCE_NAME

    def __init__(
        self,
        client: GraphClient,
        apps: AppInventoryReader | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._client = client
        self._apps = apps or DetectedAppsReader(client)
        self._clock = clock

    def check_access(self) -> None:
        """Cheapest call proving the credentials and the permission work."""
        self._client.get(DEVICES_PATH, {"$top": 1, "$select": "id"})

    def collect(self) -> InventorySnapshot:
        collected_at = self._clock()
        devices, skipped_devices = self._devices()
        apps = self._apps.read()
        with_apps = tuple(_with_apps(d, apps.apps_by_device.get(d.external_id, ())) for d in devices)
        logger.info(
            "Intune: %d devices, %d apps (%d devices and %d apps skipped as invalid)",
            len(with_apps), sum(len(d.apps) for d in with_apps), skipped_devices, apps.skipped,
        )
        return InventorySnapshot(SOURCE_NAME, with_apps, collected_at, skipped_devices, apps.skipped)

    def _devices(self) -> tuple[list[Device], int]:
        devices, skipped = [], 0
        for raw in self._client.get_all(DEVICES_PATH, {"$select": DEVICE_FIELDS}):
            parsed = _parse(GraphManagedDevice, raw)
            if parsed is None:
                skipped += 1
                continue
            devices.append(_device(parsed))
        return devices, skipped


def _device(graph: GraphManagedDevice) -> Device:
    return Device(
        external_id=graph.id,
        name=graph.device_name,
        platform=Platform.from_os_name(graph.operating_system),
        os_name=graph.operating_system,
        os_version=graph.os_version or None,
        model=graph.model or None,
        manufacturer=graph.manufacturer or None,
        serial_number=graph.serial_number or None,
        user_principal_name=graph.user_principal_name or None,
        ownership=graph.owner_type or None,
        compliance_state=graph.compliance_state or None,
        is_encrypted=graph.is_encrypted,
        security_patch_level=graph.android_security_patch_level or None,
        last_check_in_at=graph.last_sync,
    )


def _with_apps(device: Device, apps: Iterable[InstalledApp]) -> Device:
    return replace(device, apps=tuple(apps))


def _parse(model: type, raw: Any):
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        logger.warning("Skipping invalid Intune %s: %s", model.__name__, exc.errors()[0].get("msg"))
        return None
