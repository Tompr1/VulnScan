"""
Known vulnerabilities of a device: CPE identification of what Intune
reports, CVE matching on NVD version ranges, CISA KEV, and the issue the
rule reports. CVEs are NVD API 2.0 entries (trimmed), parsed by the real
parser.
"""
from datetime import date

import pytest

from app.cve.kev import InMemoryKevCatalog, KevEntry
from app.cve.matcher import InMemoryCveCatalog
from app.cve.nvd import parse_vulnerability
from app.inventory.audit.base import AuditContext, LifecycleLookup
from app.inventory.audit.cves import VulnerabilityIndex, identify_software, installed_software
from app.inventory.audit.fleet import FleetBaseline
from app.inventory.audit.rules import VulnerableSoftwareRule
from app.inventory.domain import Device, InstalledApp, Platform
from tests.unit.cve.nvd_fixtures import nvd_entry
from tests.unit.inventory.eol_fixtures import StaticSupportCatalog

TODAY = date(2026, 11, 21)


def match(cpe: str, version: str = "*", target_hw: str = "*", **bounds) -> dict:
    part, vendor, product = cpe.split(":")
    return {"vulnerable": True, "criteria": f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:{target_hw}:*", **bounds}


def cve(cve_id: str, *matches: dict, cvss: float | None = 7.5, description: str = "A vulnerability."):
    return parse_vulnerability(nvd_entry(cve_id, matches=matches, cvss=cvss, description=description)).record


WIN_23H2 = "o:microsoft:windows_11_23h2"
CHROME = "a:google:chrome"

CATALOG = [
    # Windows: one CVE lists x64 and arm64, ranged by full build.
    cve("CVE-2025-1001", match(WIN_23H2, target_hw="x64", versionEndExcluding="10.0.22631.6060"),
        match(WIN_23H2, target_hw="arm64", versionEndExcluding="10.0.22631.6060"), cvss=7.8),
    cve("CVE-2025-1002", match(WIN_23H2, versionEndExcluding="10.0.22631.5000"), cvss=9.8),
    cve("CVE-2024-0900", match(WIN_23H2, versionEndExcluding="10.0.22631.4000"), cvss=5.5),  # already fixed at .4317
    cve("CVE-2025-2001", match(CHROME, versionEndExcluding="131.0.6778.108"), cvss=8.8),
    cve("CVE-2025-2002", match(CHROME, versionEndExcluding="131.0.6778.200"), cvss=None),  # not scored yet
    # Versionless entries cannot tell a patched device from a vulnerable one.
    cve("CVE-2025-3001", match("a:microsoft:365_apps", version="-"), cvss=9.8),
    cve("CVE-2025-3002", match(CHROME), cvss=9.8),
    cve("CVE-2025-4001", match("a:7-zip:7-zip", versionEndExcluding="24.07"), cvss=7.0),
    cve("CVE-2025-5001", match("o:apple:macos", versionStartIncluding="14.0", versionEndExcluding="14.7.1"),
        match("o:apple:macos", versionStartIncluding="15.0", versionEndExcluding="15.1"), cvss=6.5),
    cve("CVE-2025-5002", match("o:apple:ipados", versionEndExcluding="18.1"), cvss=6.0),
    cve("CVE-2025-6001", match("a:mozilla:firefox", versionEndExcluding="139.0.4"), cvss=8.1),
]
KEV = [KevEntry("CVE-2025-1001", date_added=date(2025, 9, 1), due_date=date(2025, 9, 22), ransomware=True)]


def pc(build: str = "10.0.22631.4317", *apps: InstalledApp, platform=Platform.WINDOWS, os_name="Windows") -> Device:
    return Device("id-1", "PC-COMPTA-04", platform, os_name=os_name, os_version=build, apps=apps)


class CountingCatalog(InMemoryCveCatalog):
    """Spy: records the product keys asked for."""

    def __init__(self, records):
        super().__init__(records)
        self.queries = []

    def records_for(self, products):
        self.queries.append(set(products))
        return super().records_for(products)


def index(*devices: Device, kev=KEV) -> VulnerabilityIndex:
    return VulnerabilityIndex.build(devices, InMemoryCveCatalog(CATALOG), InMemoryKevCatalog(kev))


def cves_of(device: Device, **options) -> dict[str, list[str]]:
    return {
        found.software.identity.key: [v.cve_id for v in found.vulnerabilities]
        for found in index(device, **options).for_device(device)
    }


# ── Identification ────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("Google Chrome", "google:chrome"),
        ("Microsoft Edge", "microsoft:edge_chromium"),
        ("Mozilla Firefox (x64 fr)", "mozilla:firefox"),
        ("Firefox", "mozilla:firefox"),  # macOS spelling
        ("Mozilla Firefox ESR (x64 en-US)", "mozilla:firefox_esr"),
        ("7-Zip 24.08 (x64)", "7-zip:7-zip"),
        ("Notepad++ (64-bit x64)", r"notepad-plus-plus:notepad\+\+"),
        ("Adobe Acrobat Reader DC", "adobe:acrobat_reader_dc"),
        ("Adobe Acrobat (64-bit)", "adobe:acrobat_dc"),
        ("Zoom Workplace (64-bit)", "zoom:workplace_desktop"),
        ("zoom.us", "zoom:workplace_desktop"),
        ("Cisco Secure Client - AnyConnect VPN", "cisco:secure_client"),
    ],
)
def test_une_application_courante_est_identifiee_par_son_cpe_nvd(name, key):
    assert identify_software(name).key == key


@pytest.mark.parametrize(
    "name",
    [
        "Microsoft 365 Apps for enterprise - fr-fr",  # NVD gives no version range
        "Microsoft Edge WebView2 Runtime",
        "Zoom Rooms",
        "Zoom Outlook Plugin",
        "FileZilla Server",
        "Google Chrome Beta",
        "Java 8 Update 431 (64-bit)",
    ],
)
def test_une_application_sans_correspondance_fiable_n_est_pas_identifiee(name):
    assert identify_software(name) is None


@pytest.mark.parametrize(
    ("platform", "os_name", "os_version", "title", "cpe"),
    [
        (Platform.WINDOWS, "Windows", "10.0.22631.4317", "Windows 11 23H2", ("o", "microsoft", "windows_11_23h2")),
        (Platform.WINDOWS, "Windows", "10.0.19045.5011", "Windows 10 22H2", ("o", "microsoft", "windows_10_22h2")),
        (Platform.MACOS, "macOS", "14.4.1 (23E224)", "macOS", ("o", "apple", "macos")),
        (Platform.IOS, "iOS", "18.0", "iOS", ("o", "apple", "iphone_os")),
        (Platform.IOS, "iPadOS", "18.0", "iPadOS", ("o", "apple", "ipados")),
    ],
)
def test_le_systeme_est_identifie_par_son_cpe_nvd(platform, os_name, os_version, title, cpe):
    [system] = installed_software(Device("x", "D", platform, os_name=os_name, os_version=os_version))

    assert (system.is_os, system.identity.title, system.identity.cpes[0]) == (True, title, cpe)
    assert system.version == os_version.split(" ")[0]


@pytest.mark.parametrize(
    ("platform", "os_version"),
    [
        (Platform.ANDROID, "14"),  # fixed by security patch level, not by version
        (Platform.WINDOWS, "10.0.99999.1"),  # unknown build
        (Platform.LINUX, "22.04"),
        (Platform.WINDOWS, None),
    ],
)
def test_un_systeme_sans_correspondance_fiable_n_est_pas_identifie(platform, os_version):
    assert installed_software(Device("x", "D", platform, os_version=os_version)) == []


def test_chaque_copie_installee_compte_mais_une_seule_fois_par_version():
    device = pc("10.0.99999.1", InstalledApp("7-Zip 19.00 (x86)", "19.00"), InstalledApp("7-Zip 24.08 (x64)", "24.08"),
                InstalledApp("7-Zip 24.08 (x64)", "24.08"), InstalledApp("Google Chrome", None))

    assert [(s.identity.key, s.version) for s in installed_software(device)] == [("7-zip:7-zip", "19.00"), ("7-zip:7-zip", "24.08")]


# ── Matching ──────────────────────────────────────────────────────────────────

def test_un_windows_est_rapproche_des_cve_corrigees_dans_un_build_ulterieur():
    # .4317 is past the CVE-2024-0900 fix; CVE-2025-1001 lists x64 and arm64 but counts once.
    assert cves_of(pc("10.0.22631.4317")) == {"microsoft:windows_11_23h2": ["CVE-2025-1001", "CVE-2025-1002"]}


def test_un_windows_a_jour_n_a_aucune_cve():
    assert cves_of(pc("10.0.22631.6060")) == {}


def test_les_cve_exploitees_passent_en_premier_puis_par_cvss():
    [found] = index(pc()).for_device(pc())

    assert [v.cve_id for v in found.vulnerabilities] == ["CVE-2025-1001", "CVE-2025-1002"]  # KEV 7.8 before 9.8
    assert [v.cve_id for v in found.exploited] == ["CVE-2025-1001"]
    assert found.highest_cvss == 9.8


def test_les_entrees_nvd_sans_version_sont_ignorees():
    device = pc("10.0.99999.1", InstalledApp("Google Chrome", "131.0.6778.86"))

    assert cves_of(device) == {"google:chrome": ["CVE-2025-2001", "CVE-2025-2002"]}  # not CVE-2025-3002


def test_un_macos_n_est_compare_qu_a_la_plage_de_sa_version():
    assert cves_of(pc("14.6", platform=Platform.MACOS, os_name="macOS")) == {"apple:macos": ["CVE-2025-5001"]}
    assert cves_of(pc("15.1", platform=Platform.MACOS, os_name="macOS")) == {}


def test_un_firefox_esr_n_herite_pas_des_plages_de_firefox():
    device = pc("10.0.99999.1", InstalledApp("Mozilla Firefox ESR (x64 fr)", "128.11.0"))

    assert cves_of(device) == {}


def test_une_ancienne_copie_reste_vulnerable_a_cote_de_la_nouvelle():
    device = pc("10.0.99999.1", InstalledApp("7-Zip 19.00 (x86)", "19.00"), InstalledApp("7-Zip 24.08 (x64)", "24.08"))

    [found] = index(device).for_device(device)

    assert (found.software.version, [v.cve_id for v in found.vulnerabilities]) == ("19.00", ["CVE-2025-4001"])


def test_la_version_corrigeant_toutes_les_cve_est_la_plus_haute_des_bornes():
    [found] = index(pc()).for_device(pc())

    assert found.fixed_in == "10.0.22631.6060"


def test_sans_borne_de_correction_pour_chaque_cve_la_version_corrigee_est_inconnue():
    record = cve("CVE-2025-7001", match(CHROME, versionEndIncluding="131.0.6778.90"))
    device = pc("10.0.99999.1", InstalledApp("Google Chrome", "131.0.6778.86"))

    [found] = VulnerabilityIndex.build([device], InMemoryCveCatalog([record]), InMemoryKevCatalog()).for_device(device)

    assert found.fixed_in is None


def test_le_catalogue_est_interroge_une_seule_fois_pour_tout_le_parc():
    catalog = CountingCatalog(CATALOG)
    fleet = [pc(), pc("10.0.22631.4317", InstalledApp("Google Chrome", "131.0.6778.86"))]

    VulnerabilityIndex.build(fleet, catalog, InMemoryKevCatalog())

    assert catalog.queries == [{("microsoft", "windows_11_23h2"), ("google", "chrome")}]


def test_un_parc_sans_logiciel_identifiable_n_interroge_pas_le_catalogue():
    catalog = CountingCatalog(CATALOG)

    VulnerabilityIndex.build([pc("10.0.99999.1")], catalog, InMemoryKevCatalog())

    assert catalog.queries == []


# ── Rule ──────────────────────────────────────────────────────────────────────

def evaluate(device: Device, kev=KEV):
    context = AuditContext(
        today=TODAY, lifecycle=LifecycleLookup(StaticSupportCatalog()), fleet=FleetBaseline.of([device]),
        vulnerabilities=index(device, kev=kev),
    )
    return VulnerableSoftwareRule().evaluate(device, context)


def test_un_systeme_avec_une_cve_exploitee_est_critique_et_urgent():
    [issue] = evaluate(pc())

    assert (issue.rule, issue.severity, issue.subject) == ("os_vulnerable", "critical", "microsoft:windows_11_23h2:kev")
    assert issue.title == "Windows 11 23H2 10.0.22631.4317 has 2 known vulnerabilities, 1 actively exploited"
    assert (issue.cve, issue.cvss, issue.is_kev, issue.confidence) == ("CVE-2025-1001", 9.8, True, 0.9)
    assert issue.remediation == (
        "1 of these CVEs is exploited by attackers (CISA KEV): patch first; CISA remediation deadline 2025-09-22. "
        "Used in ransomware campaigns.\n\nInstall the latest Windows cumulative update (build 10.0.22631.6060 or later)."
    )
    assert ("Actively exploited (CISA KEV)", "CVE-2025-1001") in issue.evidence
    assert issue.references[0] == "https://nvd.nist.gov/vuln/detail/CVE-2025-1001"


def test_la_description_liste_chaque_cve_avec_son_score():
    [issue] = evaluate(pc())

    assert issue.description.splitlines() == [
        "Windows 11 23H2 10.0.22631.4317 is affected by:",
        "- CVE-2025-1001 (CVSS 7.8, actively exploited (CISA KEV)): A vulnerability.",
        "- CVE-2025-1002 (CVSS 9.8): A vulnerability.",
    ]


def test_sans_cve_exploitee_la_gravite_suit_le_cvss_le_plus_haut():
    [issue] = evaluate(pc(), kev=[])

    assert (issue.severity, issue.subject, issue.is_kev) == ("critical", "microsoft:windows_11_23h2", False)  # CVSS 9.8


def test_une_application_vulnerable_indique_la_version_a_installer():
    [issue] = evaluate(pc("10.0.99999.1", InstalledApp("Google Chrome", "131.0.6778.86")))

    assert (issue.rule, issue.severity, issue.subject) == ("app_vulnerable", "high", "google:chrome")
    assert issue.remediation == "Update Google Chrome to 131.0.6778.200 or later."
    assert "CVE-2025-2002 (not scored yet)" in issue.description


def test_des_cve_toutes_non_notees_restent_visibles_en_gravite_moyenne():
    record = cve("CVE-2025-8001", match(CHROME, versionEndExcluding="132.0"), cvss=None)
    device = pc("10.0.99999.1", InstalledApp("Google Chrome", "131.0"))
    context = AuditContext(
        today=TODAY, lifecycle=LifecycleLookup(StaticSupportCatalog()), fleet=FleetBaseline.of([device]),
        vulnerabilities=VulnerabilityIndex.build([device], InMemoryCveCatalog([record]), InMemoryKevCatalog()),
    )

    [issue] = VulnerableSoftwareRule().evaluate(device, context)

    assert (issue.severity, issue.cvss) == ("medium", None)


def test_la_liste_des_cve_est_tronquee_au_dela_de_quinze():
    records = [cve(f"CVE-2025-{9000 + n}", match(CHROME, versionEndExcluding="132.0")) for n in range(20)]
    device = pc("10.0.99999.1", InstalledApp("Google Chrome", "131.0"))
    context = AuditContext(
        today=TODAY, lifecycle=LifecycleLookup(StaticSupportCatalog()), fleet=FleetBaseline.of([device]),
        vulnerabilities=VulnerabilityIndex.build([device], InMemoryCveCatalog(records), InMemoryKevCatalog()),
    )

    [issue] = VulnerableSoftwareRule().evaluate(device, context)

    lines = issue.description.splitlines()
    assert len(lines) == 1 + 15 + 1 and lines[-1] == "- … and 5 more"
    assert issue.title.endswith("has 20 known vulnerabilities")
    # Threat Intel voit pourtant les 20 (« présente sur mon parc »).
    assert sorted(issue.cves) == sorted(f"CVE-2025-{9000 + n}" for n in range(20))


def test_un_appareil_sans_cve_ne_produit_rien():
    assert evaluate(pc("10.0.22631.6060", InstalledApp("Google Chrome", "131.0.6778.200"))) == []


# ── CISA KEV ──────────────────────────────────────────────────────────────────

def test_une_entree_kev_est_lue_au_format_du_jeu_de_donnees():
    entry = KevEntry.from_row({"cveID": "cve-2025-1001", "dateAdded": "2025-09-01", "dueDate": "2025-09-22",
                               "knownRansomwareCampaignUse": "Known"})

    assert entry == KevEntry("CVE-2025-1001", date(2025, 9, 1), date(2025, 9, 22), ransomware=True)


@pytest.mark.parametrize("row", [{"cve": "pas-une-cve"}, {}, "texte", None])
def test_une_entree_kev_invalide_est_ecartee(row):
    assert KevEntry.from_row(row) is None


def test_le_catalogue_kev_ignore_la_casse_et_les_lignes_invalides():
    catalog = InMemoryKevCatalog.from_rows([{"cve": "CVE-2025-1001", "dueDate": "inconnue"}, {"cve": "x"}])

    assert len(catalog) == 1
    assert catalog.get("cve-2025-1001").due_date is None
    assert catalog.get("CVE-2025-0000") is None


def test_une_seule_cve_sans_version_de_correction_suffit_a_rendre_celle_ci_inconnue():
    records = [cve("CVE-2025-7001", match(CHROME, versionEndExcluding="132.0")),
               cve("CVE-2025-7002", match(CHROME, versionEndIncluding="131.5"))]
    device = pc("10.0.99999.1", InstalledApp("Google Chrome", "131.0"))

    [found] = VulnerabilityIndex.build([device], InMemoryCveCatalog(records), InMemoryKevCatalog()).for_device(device)

    assert found.fixed_in is None


def test_une_cve_exploitee_rend_le_constat_critique_meme_avec_un_cvss_eleve_seulement():
    record = cve("CVE-2025-1001", match(WIN_23H2, versionEndExcluding="10.0.22631.6060"), cvss=7.8)
    device = pc()
    context = AuditContext(
        today=TODAY, lifecycle=LifecycleLookup(StaticSupportCatalog()), fleet=FleetBaseline.of([device]),
        vulnerabilities=VulnerabilityIndex.build([device], InMemoryCveCatalog([record]), InMemoryKevCatalog(KEV)),
    )

    [issue] = VulnerableSoftwareRule().evaluate(device, context)

    assert (issue.severity, issue.cvss) == ("critical", 7.8)


@pytest.mark.parametrize(("value", "ransomware"), [("Known", True), ("Unknown", False), ("", False)])
def test_l_usage_par_des_rancongiciels_n_est_retenu_que_s_il_est_connu(value, ransomware):
    entry = KevEntry.from_row({"cve": "CVE-2025-1001", "knownRansomwareCampaignUse": value})

    assert entry.ransomware is ransomware
