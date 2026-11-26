"""En production, la plateforme refuse de démarrer avec un réglage dangereux."""
from dataclasses import dataclass

import pytest

from app.core.production import UnsafeConfigurationError, check_production_settings, production_problems


@dataclass
class Reglages:
    APP_ENV: str = "production"
    SECRET_KEY: str = "a" * 64
    DEFAULT_ADMIN_PASSWORD: str = "9f2c41d07be3a5c8e6d1"
    NEO4J_PASSWORD: str = "4be1c0f9d2a7e3b6"
    DATABASE_URL: str = "postgresql+psycopg2://app:7d3e9a1c5b2f8e4d@db:5432/app"
    CORS_ORIGINS: str = "https://soc.example"
    PROBE_REQUIRE_HTTPS: bool = True
    PUBLIC_URL: str = "https://soc.example"
    PROBE_IMAGE: str = ""

    def cors_origins_list(self):
        return ["*"] if self.CORS_ORIGINS == "*" else [o for o in self.CORS_ORIGINS.split(",") if o]

    @property
    def public_url(self):
        return self.PUBLIC_URL or (self.cors_origins_list() or [None])[0]


def test_des_reglages_sains_demarrent_en_production():
    assert production_problems(Reglages()) == []
    check_production_settings(Reglages())


@pytest.mark.parametrize(("champ", "valeur", "attendu"), [
    ("SECRET_KEY", "dev-secret-CHANGE-ME", "SECRET_KEY"),
    ("SECRET_KEY", "court-mais-pas-defaut", "SECRET_KEY"),
    ("DEFAULT_ADMIN_PASSWORD", "admin123", "DEFAULT_ADMIN_PASSWORD"),
    ("NEO4J_PASSWORD", "password", "NEO4J_PASSWORD"),
    ("DATABASE_URL", "postgresql+psycopg2://app:app@db:5432/app", "DATABASE_URL"),
    ("DATABASE_URL", "postgresql+psycopg2://app@db:5432/app", "DATABASE_URL"),
    ("CORS_ORIGINS", "*", "CORS_ORIGINS"),
    ("PROBE_REQUIRE_HTTPS", False, "PROBE_REQUIRE_HTTPS"),
    ("PUBLIC_URL", "http://192.168.2.11:5173", "PUBLIC_URL"),
    ("PROBE_IMAGE", "ghcr.io/msp/v0cday-probe:latest", "PROBE_IMAGE"),
    ("PROBE_IMAGE", "ghcr.io/msp/v0cday-probe@sha256:abc", "PROBE_IMAGE"),
])
def test_chaque_reglage_dangereux_est_nomme(champ, valeur, attendu):
    reglages = Reglages(**{champ: valeur})

    [probleme] = production_problems(reglages)

    assert probleme.startswith(attendu)


def test_en_production_un_reglage_dangereux_empeche_le_demarrage():
    with pytest.raises(UnsafeConfigurationError, match="SECRET_KEY"):
        check_production_settings(Reglages(SECRET_KEY="dev-secret-CHANGE-ME"))


def test_hors_production_les_problemes_sont_seulement_signales(caplog):
    check_production_settings(Reglages(APP_ENV="development", SECRET_KEY="dev-secret-CHANGE-ME"))

    assert "Not fit for production" in caplog.text


def test_sans_url_publique_la_premiere_origine_cors_en_tient_lieu():
    assert production_problems(Reglages(PUBLIC_URL="", CORS_ORIGINS="http://192.168.2.11:5173"))[0].startswith("PUBLIC_URL")
    assert production_problems(Reglages(PUBLIC_URL="", CORS_ORIGINS="https://soc.example")) == []


def test_une_image_de_sonde_epinglee_par_empreinte_est_acceptee():
    assert production_problems(Reglages(PROBE_IMAGE="ghcr.io/msp/v0cday-probe@sha256:" + "0" * 64)) == []
