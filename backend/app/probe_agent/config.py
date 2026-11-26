"""
Configuration of a probe, written by ``v0cday-probe enroll`` and read by
``v0cday-probe run``.

It holds the probe's credential: the file is created readable by its owner
only, and the credential never appears in ``repr`` or logs.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path(os.environ.get("V0CDAY_PROBE_CONFIG", "/etc/v0cday-probe/probe.json"))
DEFAULT_STATE_DIR = Path(os.environ.get("V0CDAY_PROBE_STATE", "/var/lib/v0cday-probe"))


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ProbeConfig:
    platform_url: str
    credential: str = field(repr=False)
    probe_id: int = 0
    workspace_id: int = 0
    name: str = ""
    # CA bundle to trust the platform with (default: the system's).
    ca_bundle: str | None = None
    # Client certificate and key, once the platform's TLS proxy asks for one.
    client_cert: str | None = None
    client_key: str | None = None
    # Lab only: talk to the platform over plain HTTP.
    allow_http: bool = False
    # The client's own limit on what this probe may scan, on top of the
    # platform's allowlist (same syntax as ALLOWLIST). None: no extra limit.
    local_allowlist: str | None = None
    state_dir: str = str(DEFAULT_STATE_DIR)

    def __post_init__(self) -> None:
        check_platform_url(self.platform_url, self.allow_http)
        if "." not in self.credential:
            raise ConfigError("The probe credential is not of the form <id>.<secret>")

    @property
    def authorization(self) -> str:
        return f"Probe {self.credential}"

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Created 0600 before the secret is written into it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(asdict(self), out, indent=2)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: Path) -> ProbeConfig:
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(f"No probe configuration at {path}: enroll the probe first") from None
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"Unreadable probe configuration {path}: {exc}") from None
        known = {name for name in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def check_platform_url(url: str, allow_http: bool) -> None:
    if url.startswith("https://"):
        return
    if url.startswith("http://") and allow_http:
        return
    raise ConfigError(
        "The platform URL must start with https:// (the probe receives credentials from it). "
        "Plain http:// is only accepted with --allow-http, in a lab."
    )
