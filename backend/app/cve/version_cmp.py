import re
from packaging.version import Version, InvalidVersion

# Upstream version schemes PEP 440 cannot read, rewritten as post-releases so
# that their order is preserved:
#   OpenSSH portable  9.6p1  -> 9.6.post1    (9.6 < 9.6p1 < 9.7)
#   OpenSSL letters   1.1.1w -> 1.1.1.post23 (1.1.1v < 1.1.1w; "za" > "z")
_OPENSSH_PORTABLE = re.compile(r"^(\d+(?:\.\d+)*)p(\d+)$", re.IGNORECASE)
_OPENSSL_LETTERS = re.compile(r"^(\d+(?:\.\d+)+)([a-z]{1,2})$", re.IGNORECASE)


def _letters_to_number(letters: str) -> int:
    value = 0
    for letter in letters.lower():
        value = value * 27 + (ord(letter) - ord("a") + 1)
    return value


def normalize(v: str) -> str:
    v = (v or "").strip()
    v = v.split(":",1)[-1]
    v = re.sub(r"[^0-9A-Za-z\.\-\+~]", "", v)
    if m := _OPENSSH_PORTABLE.match(v):
        return f"{m.group(1)}.post{m.group(2)}"
    if m := _OPENSSL_LETTERS.match(v):
        return f"{m.group(1)}.post{_letters_to_number(m.group(2))}"
    return v

def parse(v: str):
    try:
        return Version(normalize(v))
    except InvalidVersion:
        return None

_DISTRO_PATCH_RE = re.compile(
    r"[-+](?:"
    r"(?P<deb>deb\d+u(?P<deb_rev>\d+))"      # Debian: +deb10u5
    r"|(?P<ubuntu>ubuntu[\d.]+)"               # Ubuntu: +ubuntu0.20.04.1
    r"|(?P<rhel>el(?P<rhel_maj>\d+)[._]\d+)"   # RHEL/CentOS: .el8_4
    r")",
    re.I,
)

_DISTRO_OS_MAP = {
    "debian": "deb",
    "ubuntu": "ubuntu",
    "rhel": "rhel",
    "centos": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "redhat": "rhel",
}


def extract_distro_patch(raw_version: str) -> dict | None:
    """Parse distro-specific patch suffixes from a raw package version string.

    Returns dict with distro info if a backport suffix is found, else None.
    Examples:
        "1.14.2-2+deb10u5"       -> {"family": "deb", "revision": 5}
        "1:2.30-0ubuntu0.20.04.1" -> {"family": "ubuntu", "revision": 1}
        "3.6.8-47.el8_6"         -> {"family": "rhel", "revision": 6}
    """
    if not raw_version:
        return None
    m = _DISTRO_PATCH_RE.search(raw_version)
    if not m:
        return None
    if m.group("deb"):
        return {"family": "deb", "revision": int(m.group("deb_rev") or 0)}
    if m.group("ubuntu"):
        # Ubuntu revision is typically the trailing segment count
        parts = m.group("ubuntu").replace("ubuntu", "").split(".")
        rev = int(parts[-1]) if parts and parts[-1].isdigit() else 1
        return {"family": "ubuntu", "revision": rev}
    if m.group("rhel"):
        trail = m.group("rhel").split("_")[-1].split(".")[-1]
        return {"family": "rhel", "revision": int(trail) if trail.isdigit() else 1}
    return None


def is_likely_patched(raw_version: str, os_id: str) -> bool:
    """Check if a package version string suggests a distro-backported security fix.

    Args:
        raw_version: The full, unstripped package version (e.g., "1.14.2-2+deb10u5").
        os_id: OS identifier from inventory (e.g., "debian", "ubuntu", "rhel").

    Returns:
        True if the version suffix indicates a security backport for the detected OS.
    """
    patch = extract_distro_patch(raw_version)
    if not patch or patch["revision"] < 1:
        return False
    os_family = _DISTRO_OS_MAP.get((os_id or "").lower().split()[0], "")
    if not os_family:
        return False
    # The patch family must match the OS family
    if patch["family"] == "ubuntu" and os_family in ("deb", "ubuntu"):
        return True
    if patch["family"] == "deb" and os_family == "deb":
        return True
    if patch["family"] == "rhel" and os_family == "rhel":
        return True
    return False


def match_expr(installed: str, expr: str) -> bool:
    inst = parse(installed)
    if not inst:
        return False
    parts = expr.split()
    ok = True
    i = 0
    while i < len(parts):
        op = parts[i]; v = parts[i+1]; i += 2
        pv = parse(v)
        if not pv:
            return False
        if op == "<": ok = ok and (inst < pv)
        elif op == "<=": ok = ok and (inst <= pv)
        elif op == ">": ok = ok and (inst > pv)
        elif op == ">=": ok = ok and (inst >= pv)
        elif op == "==": ok = ok and (inst == pv)
        else: return False
    return ok

