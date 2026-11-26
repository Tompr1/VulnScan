import pytest

from app.core.config import Settings


@pytest.mark.parametrize(
    ("public_url", "cors", "expected"),
    [
        ("https://v0cday.example.com/", "http://localhost:5173", "https://v0cday.example.com"),
        ("", "http://10.0.0.20:5173, http://localhost:5173", "http://10.0.0.20:5173"),  # where the UI is served
        ("", "*", None),
        ("  ", "", None),
    ],
)
def test_l_adresse_publique_de_l_interface_sert_aux_liens_des_alertes(public_url, cors, expected):
    assert Settings(PUBLIC_URL=public_url, CORS_ORIGINS=cors).public_url == expected
