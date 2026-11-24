"""
InventoryAudit use case: stored devices -> findings linked to their device,
with an in-memory store and a canned endoflife.date catalog.
"""
from datetime import date, datetime, timezone

from app.inventory.audit.auditor import DeviceAuditor
from app.inventory.audit.rules import default_rules
from app.inventory.audit.base import AuditIssue
from app.inventory.audit.service import AuditedDevice, InventoryAudit, device_finding
from app.inventory.domain import Device, InstalledApp, Platform
from tests.unit.inventory.eol_fixtures import StaticSupportCatalog, reference_data

NOW = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)


class InMemoryAuditStore:
    """Fake AuditStore; records the audit runs (spy)."""

    def __init__(self, *devices: AuditedDevice) -> None:
        self.devices = list(devices)
        self.runs = []

    def devices_to_audit(self, connection_id):
        return self.devices

    def record_audit(self, run):
        self.runs.append(run)


def pc(device_id: int, build: str, *apps: InstalledApp, name: str = "PC-COMPTA-04") -> AuditedDevice:
    return AuditedDevice(device_id, Device(
        f"intune-{device_id}", name, Platform.WINDOWS, os_name="Windows", os_version=build,
        user_principal_name="j.martin@corp.example", serial_number="5CG1234XYZ",
        last_check_in_at=datetime(2026, 11, 20, 8, 30, tzinfo=timezone.utc), apps=apps,
    ))


def audit(store, catalog=None, **reference) -> InventoryAudit:
    auditor = DeviceAuditor(default_rules(), today=lambda: date(2026, 11, 21))
    return InventoryAudit(store, auditor, lambda: reference_data(catalog, **reference), clock=lambda: NOW)


def test_chaque_probleme_devient_un_constat_rattache_a_son_appareil():
    store = InMemoryAuditStore(pc(7, "10.0.22631.4317"), pc(8, "10.0.26200.7171", name="PC-RH-01"))

    [finding] = audit(store).run(connection_id=3, workspace_id=1, job_id=42)

    assert finding.plugin_id == "inventory.os_unsupported"
    assert finding.title == "Windows 11 23H2 (W) is no longer supported — PC-COMPTA-04"
    assert (finding.device_id, finding.affected, finding.severity) == (7, "PC-COMPTA-04", "high")
    assert finding.references == ["https://endoflife.date/windows"]


def test_la_preuve_donne_l_identite_de_l_appareil_et_le_detail_du_probleme():
    [finding] = audit(InMemoryAuditStore(pc(7, "10.0.22631.4317"))).run(3, 1, 42)

    assert finding.evidence.splitlines() == [
        "Device: PC-COMPTA-04",
        "User: j.martin@corp.example",
        "Serial number: 5CG1234XYZ",
        "Last check-in: 2026-11-20T08:30+00:00",
        "OS: Windows 10.0.22631.4317",
        "Release: Windows 11 23H2 (W)",
        "End of support: 2025-11-11",
    ]


def test_l_empreinte_reste_la_meme_d_une_version_obsolete_a_l_autre():
    fleet = [pc(n, "10.0.26200.7171", InstalledApp("7-Zip 24.08 (x64)", "24.08"), name=f"PC-{n}") for n in (2, 3)]
    before = audit(InMemoryAuditStore(pc(1, "10.0.26200.7171", InstalledApp("7-Zip 23.01 (x64)", "23.01")), *fleet)).run(3, 1, 42)
    after = audit(InMemoryAuditStore(pc(1, "10.0.26200.7171", InstalledApp("7-Zip 24.07 (x64)", "24.07")), *fleet)).run(3, 1, 43)

    assert [f.title for f in before] != [f.title for f in after]
    assert [f.fingerprint for f in before] == [f.fingerprint for f in after]


def test_deux_appareils_avec_le_meme_probleme_ont_des_empreintes_distinctes():
    findings = audit(InMemoryAuditStore(pc(7, "10.0.22631.4317"), pc(8, "10.0.22631.4317", name="PC-RH-01"))).run(3, 1, 42)

    assert len({f.fingerprint for f in findings}) == 2


def test_l_audit_est_enregistre_avec_ses_compteurs():
    store = InMemoryAuditStore(pc(7, "10.0.22631.4317"), pc(8, "10.0.26200.7171"))

    audit(store).run(3, 1, 42)

    [run] = store.runs
    assert (run.connection_id, run.job_id, run.audited_at, run.devices, run.issues, run.warnings) == (3, 42, NOW, 2, 1, ())


def test_un_audit_incomplet_le_signale_par_un_constat_informatif():
    store = InMemoryAuditStore(pc(7, "10.0.22631.4317"))

    findings = audit(store, StaticSupportCatalog(unavailable=("windows",))).run(3, 1, 42)

    [notice] = [f for f in findings if f.plugin_id == "inventory.audit_incomplete"]
    assert (notice.severity, notice.device_id) == ("info", None)
    assert "windows" in notice.description and "endoflife.date" in notice.remediation
    assert store.runs[0].warnings == (
        "Support lifecycle unavailable (endoflife.date) for: windows. End-of-support checks were skipped "
        "for them; versions were compared with the fleet only.",
    )


def test_un_parc_vide_est_audite_sans_constat():
    store = InMemoryAuditStore()

    assert audit(store).run(3, 1, 42) == []
    assert store.runs[0].devices == 0


def test_un_constat_de_cve_porte_la_cve_la_plus_urgente_son_score_et_le_kev():
    issue = AuditIssue("os_vulnerable", "microsoft:windows_11_23h2:kev", "Windows 11 23H2 has 2 known vulnerabilities",
                       "critical", "…", "…", cve="CVE-2025-1001", cvss=9.8, is_kev=True, confidence=0.9)

    finding = device_finding(issue, pc(7, "10.0.22631.4317"))

    assert (finding.cve, finding.cvss, finding.is_kev, finding.confidence) == ("CVE-2025-1001", 9.8, True, 0.9)
