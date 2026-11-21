import pytest

from app.scanner.target import InvalidTargetError, ScanTarget, ScanType


@pytest.mark.parametrize(
    ("raw", "host", "scheme"),
    [
        ("https://Example.com:8443/login", "example.com", "https"),
        ("http://10.0.0.5", "10.0.0.5", "http"),
        ("10.0.0.5:22", "10.0.0.5", "unknown"),
        ("[::1]:8080", "::1", "unknown"),
        ("intranet.local/admin", "intranet.local", "unknown"),
    ],
)
def test_une_cible_est_decomposee_en_hote_et_schema(raw, host, scheme):
    target = ScanTarget.parse(raw)

    assert (target.host, target.scheme) == (host, scheme)


def test_la_cible_brute_est_conservee_sans_espaces_superflus():
    assert ScanTarget.parse("  scanme.local  ").raw == "scanme.local"


@pytest.mark.parametrize("raw", ["", "   ", "http://", ":8080", "/path/only"])
def test_une_cible_sans_hote_est_refusee(raw):
    with pytest.raises(InvalidTargetError):
        ScanTarget.parse(raw)


@pytest.mark.parametrize(("raw", "expected"), [(None, ScanType.INTERNAL), ("", ScanType.INTERNAL), ("EXTERNAL", ScanType.EXTERNAL), ("iac", ScanType.IAC)])
def test_un_type_de_scan_stocke_est_relu(raw, expected):
    assert ScanType.parse(raw) is expected


def test_un_type_de_scan_inconnu_est_refuse():
    with pytest.raises(ValueError):
        ScanType.parse("quantum")
