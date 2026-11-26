"""
Scripts de l'appliance (deploy/appliance/files), lancés pour de vrai avec
des commandes docker et cosign factices qui notent leurs appels.
"""
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

FILES = Path(__file__).resolve().parents[4] / "deploy" / "appliance" / "files"
DIGEST = "ghcr.io/msp/v0cday-probe@sha256:" + "a" * 64
NEW_DIGEST = "ghcr.io/msp/v0cday-probe@sha256:" + "b" * 64

FAKE_DOCKER = r'''#!/bin/bash
echo "ARGS $*" >> "$STUB_LOG"
if [ -n "${V0CDAY_ENROLL_TOKEN:-}" ]; then echo "ENV_TOKEN $V0CDAY_ENROLL_TOKEN" >> "$STUB_LOG"; fi
case " $* " in
  *" enroll "*)
    if [ "${STUB_ENROLL_RC:-0}" = 0 ]; then echo '{}' > "$V0CDAY_CONFIG_DIR/probe.json"; fi
    exit "${STUB_ENROLL_RC:-0}" ;;
  *" desired-image "*) echo "${STUB_DESIRED:-}" ;;
  *" status "*)
    image=$(sed -n 's/^PROBE_IMAGE=//p' "$V0CDAY_COMPOSE_DIR/.env" 2>/dev/null | tail -n 1)
    if [ "$image" = "${STUB_BROKEN_IMAGE:-none}" ]; then exit 1; fi ;;
  *" ps "*) echo running-container-id ;;
  " pull "*) exit "${STUB_PULL_RC:-0}" ;;
esac
exit 0
'''
FAKE_COSIGN = '''#!/bin/bash
echo "COSIGN $*" >> "$STUB_LOG"
exit "${STUB_COSIGN_RC:-0}"
'''


class Appliance:
    def __init__(self, root: Path):
        self.config = root / "etc"
        self.compose = root / "opt"
        self.bin = root / "bin"
        self.log = root / "calls.log"
        for d in (self.config, self.compose, self.bin):
            d.mkdir()
        for name, body in (("docker", FAKE_DOCKER), ("cosign", FAKE_COSIGN)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        self.log.touch()

    def run(self, script, **stub):
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "V0CDAY_CONFIG_DIR": str(self.config),
            "V0CDAY_COMPOSE_DIR": str(self.compose),
            "V0CDAY_HEALTH_DELAY": "0",
            "V0CDAY_HEALTH_TRIES": "2",
            "STUB_LOG": str(self.log),
            **{k: str(v) for k, v in stub.items()},
        }
        result = subprocess.run(["bash", str(FILES / script)], env=env, cwd=self.compose,
                                capture_output=True, text=True, timeout=30)
        self.output = result.stdout + result.stderr
        return result.returncode

    @property
    def calls(self):
        return self.log.read_text().splitlines()

    def seed(self, text):
        (self.config / "seed.env").write_text(text)

    def enrolled(self):
        (self.config / "probe.json").write_text("{}")

    def image(self):
        env = self.compose / ".env"
        return env.read_text().split("PROBE_IMAGE=")[-1].strip() if env.exists() else ""


@pytest.fixture
def vm(tmp_path):
    return Appliance(tmp_path)


# ── Premier démarrage ─────────────────────────────────────────────────────────

SEED = "V0CDAY_PLATFORM=https://soc.example\nV0CDAY_TOKEN=tok-123\n"


def test_au_premier_demarrage_la_sonde_s_enrole_puis_demarre(vm):
    vm.seed(SEED + "V0CDAY_LOCAL_ALLOWLIST=10.0.0.0/8\n")
    (vm.config / "ca.pem").write_text("-----BEGIN CERTIFICATE-----\n")

    code = vm.run("v0cday-probe-firstboot")

    assert code == 0, vm.output
    enroll = next(c for c in vm.calls if " enroll " in c)
    assert "--platform https://soc.example" in enroll
    assert "--local-allowlist 10.0.0.0/8" in enroll
    assert "--ca-bundle /etc/v0cday-probe/ca.pem" in enroll
    assert "-e V0CDAY_ENROLL_TOKEN" in enroll
    assert "ENV_TOKEN tok-123" in vm.calls
    assert vm.calls[-1].endswith("up -d")


def test_le_jeton_ne_passe_pas_par_la_ligne_de_commande_et_disparait_du_disque(vm):
    vm.seed(SEED)

    vm.run("v0cday-probe-firstboot")

    assert not any("tok-123" in c for c in vm.calls if c.startswith("ARGS"))
    assert not (vm.config / "seed.env").exists()


def test_le_http_n_est_demande_que_si_la_graine_le_dit(vm):
    vm.seed(SEED + "V0CDAY_ALLOW_HTTP=1\n")

    vm.run("v0cday-probe-firstboot")

    assert any(" enroll " in c and "--allow-http" in c for c in vm.calls)


def test_une_sonde_deja_enrolee_est_seulement_demarree(vm):
    vm.enrolled()

    assert vm.run("v0cday-probe-firstboot") == 0
    assert [c for c in vm.calls if c.startswith("ARGS")] == [
        f"ARGS compose --project-directory {vm.compose} -f {vm.compose}/docker-compose.yml up -d"]


@pytest.mark.parametrize("seed", [None, "V0CDAY_PLATFORM=https://soc.example\n", "V0CDAY_TOKEN=tok\n"])
def test_sans_graine_utilisable_le_script_s_arrete_sans_reessayer(vm, seed):
    if seed is not None:
        vm.seed(seed)

    assert vm.run("v0cday-probe-firstboot") == 3
    assert vm.calls == []


def test_un_enrolement_refuse_garde_la_graine_et_ne_demarre_rien(vm):
    vm.seed(SEED)

    code = vm.run("v0cday-probe-firstboot", STUB_ENROLL_RC=2)

    assert code == 1
    assert (vm.config / "seed.env").exists()
    assert not any(c.endswith("up -d") for c in vm.calls)
    assert "renew it in Root" in vm.output


def test_le_contenu_de_la_graine_n_est_jamais_execute(vm):
    pwned = vm.compose / "pwned"
    vm.seed(f"V0CDAY_PLATFORM=https://soc.example/$(touch {pwned})\nV0CDAY_TOKEN=`touch {pwned}`\n")

    vm.run("v0cday-probe-firstboot")

    assert not pwned.exists()


# ── Mise à jour ───────────────────────────────────────────────────────────────

def trusted(vm, **extra):
    lines = {"ALLOWED_IMAGE_PREFIX": "ghcr.io/msp/v0cday-probe@sha256:",
             "COSIGN_PUBLIC_KEY": str(vm.config / "cosign.pub"), **extra}
    (vm.config / "update.conf").write_text("".join(f"{k}={v}\n" for k, v in lines.items()))


def test_l_image_demandee_signee_et_epinglee_est_installee(vm):
    vm.enrolled()
    trusted(vm)

    code = vm.run("v0cday-probe-update", STUB_DESIRED=DIGEST)

    assert code == 0, vm.output
    assert f"COSIGN verify --key {vm.config}/cosign.pub {DIGEST}" in vm.calls
    assert f"ARGS pull {DIGEST}" in vm.calls
    assert vm.image() == DIGEST


def test_sans_image_demandee_ou_deja_en_place_rien_ne_change(vm):
    vm.enrolled()
    trusted(vm)
    (vm.compose / ".env").write_text(f"PROBE_IMAGE={DIGEST}\n")

    assert vm.run("v0cday-probe-update", STUB_DESIRED="") == 0
    assert vm.run("v0cday-probe-update", STUB_DESIRED=DIGEST) == 0
    assert not any("pull" in c for c in vm.calls)


@pytest.mark.parametrize(("desired", "conf", "raison"), [
    ("ghcr.io/msp/v0cday-probe:latest", {}, "not pinned by digest"),
    ("ghcr.io/msp/v0cday-probe@sha256:abc", {}, "not pinned by digest"),
    ("ghcr.io/evil/probe@sha256:" + "c" * 64, {}, "not under"),
    (DIGEST, {"COSIGN_PUBLIC_KEY": ""}, "no COSIGN_PUBLIC_KEY"),
])
def test_une_image_qui_n_inspire_pas_confiance_est_refusee(vm, desired, conf, raison):
    vm.enrolled()
    trusted(vm, **conf)

    code = vm.run("v0cday-probe-update", STUB_DESIRED=desired)

    assert code == 2
    assert raison in vm.output
    assert not any(c.startswith("ARGS pull") for c in vm.calls)
    assert vm.image() == ""


def test_une_signature_invalide_est_refusee(vm):
    vm.enrolled()
    trusted(vm)

    assert vm.run("v0cday-probe-update", STUB_DESIRED=DIGEST, STUB_COSIGN_RC=1) == 2
    assert not any(c.startswith("ARGS pull") for c in vm.calls)


def test_sans_signature_en_labo_si_on_l_assume(vm):
    vm.enrolled()
    trusted(vm, COSIGN_PUBLIC_KEY="", REQUIRE_SIGNATURE="no")

    assert vm.run("v0cday-probe-update", STUB_DESIRED=DIGEST) == 0
    assert vm.image() == DIGEST


def test_une_image_qui_ne_demarre_pas_est_annulee(vm):
    vm.enrolled()
    trusted(vm)
    (vm.compose / ".env").write_text(f"OTHER=1\nPROBE_IMAGE={DIGEST}\n")

    code = vm.run("v0cday-probe-update", STUB_DESIRED=NEW_DIGEST, STUB_BROKEN_IMAGE=NEW_DIGEST)

    assert code == 1
    assert vm.image() == DIGEST
    assert (vm.compose / ".env").read_text().startswith("OTHER=1\n")


def test_une_sonde_non_enrolee_ou_une_mise_a_jour_en_cours_ne_lance_rien(vm):
    assert vm.run("v0cday-probe-update", STUB_DESIRED=DIGEST) == 0
    vm.enrolled()
    trusted(vm)
    (vm.compose / ".update.lock").mkdir()

    assert vm.run("v0cday-probe-update", STUB_DESIRED=DIGEST) == 0
    assert vm.calls == []


# ── De Root au premier démarrage ─────────────────────────────────────────────

FRONTEND_MODEL = Path(__file__).resolve().parents[4] / "frontend" / "src" / "design" / "probesModel.js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node absent")
def test_la_configuration_telechargee_dans_root_enrole_l_appliance(vm):
    # Arrange : le user-data tel que Root le produit (même code que l'interface).
    inputs = {"platformUrl": "https://soc.example", "token": "T" * 43, "probeName": "Paris",
              "localAllowlist": "10.0.0.0/8", "caPem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}
    script = (f"import('{FRONTEND_MODEL.as_uri()}').then(m => "
              f"process.stdout.write(m.cloudInitUserData({json.dumps(inputs)})))")
    user_data = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout

    # Act : cloud-init écrit les fichiers, puis le premier démarrage s'exécute.
    config = yaml.safe_load(user_data)
    for item in config["write_files"]:
        target = vm.config / Path(item["path"]).name
        target.write_text(item["content"])
    code = vm.run("v0cday-probe-firstboot")

    # Assert
    assert code == 0, vm.output
    enroll = next(c for c in vm.calls if " enroll " in c)
    assert "--platform https://soc.example" in enroll
    assert "--local-allowlist 10.0.0.0/8" in enroll
    assert "--ca-bundle /etc/v0cday-probe/ca.pem" in enroll
    assert f"ENV_TOKEN {'T' * 43}" in vm.calls
    assert config["hostname"] == "v0cday-probe-paris"
