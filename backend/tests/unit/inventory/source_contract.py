"""
Contract every InventorySource must satisfy (Liskov): the same assertions
run against each connector — Intune now, GLPI or Fleet later — so they are
interchangeable for the sync and the audit.
"""
from app.inventory.domain import Device, InventorySnapshot


def assert_satisfies_inventory_source_contract(source) -> InventorySnapshot:
    assert isinstance(source.name, str) and source.name

    source.check_access()
    snapshot = source.collect()

    assert isinstance(snapshot, InventorySnapshot)
    assert snapshot.source == source.name
    assert snapshot.collected_at.tzinfo is not None
    assert snapshot.skipped_devices >= 0 and snapshot.skipped_apps >= 0
    ids = [device.external_id for device in snapshot.devices]
    assert len(ids) == len(set(ids)), "a device appears once per snapshot"
    assert all(isinstance(device, Device) for device in snapshot.devices)
    return snapshot
