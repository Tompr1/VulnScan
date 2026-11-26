"""
Settings a production platform must not run with.

The master holds every client's credentials and drives probes inside their
networks: a default password or an open CORS policy there is not a detail.
With APP_ENV=production the platform refuses to start until each problem
below is fixed; elsewhere they are only logged.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

PRODUCTION = "production"
MIN_SECRET_KEY_LENGTH = 32
_DEFAULT_SECRET_KEYS = {"dev-secret-CHANGE-ME", "change-me-very-long-random-secret-please-use-openssl-rand-hex-32"}
_DEFAULT_PASSWORDS = {"", "admin123", "changeme", "password", "app", "neo4j", "CHANGE_ME"}


class UnsafeConfigurationError(RuntimeError):
    pass


def is_pinned_image(reference: str) -> bool:
    """An image reference that names one exact image: ...@sha256:<64 hex>."""
    return re.fullmatch(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}", reference) is not None


def production_problems(settings: Any) -> list[str]:
    """What makes these settings unfit for production, in plain words."""
    problems = []
    secret = settings.SECRET_KEY or ""
    if secret in _DEFAULT_SECRET_KEYS or len(secret) < MIN_SECRET_KEY_LENGTH:
        problems.append(f"SECRET_KEY is a default or shorter than {MIN_SECRET_KEY_LENGTH} characters "
                        "(generate one: openssl rand -hex 32)")
    if settings.DEFAULT_ADMIN_PASSWORD in _DEFAULT_PASSWORDS:
        problems.append("DEFAULT_ADMIN_PASSWORD is a default password")
    if settings.NEO4J_PASSWORD in _DEFAULT_PASSWORDS:
        problems.append("NEO4J_PASSWORD is a default password")
    database_password = urlsplit(settings.DATABASE_URL).password
    if database_password in _DEFAULT_PASSWORDS or database_password is None:
        problems.append("DATABASE_URL has no password or a default one")
    if "*" in settings.cors_origins_list():
        problems.append("CORS_ORIGINS allows every origin ('*')")
    if not settings.PROBE_REQUIRE_HTTPS:
        problems.append("PROBE_REQUIRE_HTTPS is off: probes would receive credentials over plain HTTP")
    image = (getattr(settings, "PROBE_IMAGE", "") or "").strip()
    if image and not is_pinned_image(image):
        problems.append("PROBE_IMAGE is not pinned by digest (registry/name@sha256:<64 hex>): "
                        "probes would run whatever the tag points to")
    public_url = settings.public_url or ""
    if not public_url.startswith("https://"):
        problems.append("PUBLIC_URL (or the first CORS origin) is not an https:// address")
    return problems


def check_production_settings(settings: Any) -> None:
    """Raises :class:`UnsafeConfigurationError` in production when a setting
    is unsafe; logs the problems otherwise."""
    problems = production_problems(settings)
    if not problems:
        return
    if (settings.APP_ENV or "").lower() == PRODUCTION:
        raise UnsafeConfigurationError(
            "Refusing to start in production: " + "; ".join(problems) + ". Fix them in .env."
        )
    logger.warning("Not fit for production (fine for development): %s", "; ".join(problems))
