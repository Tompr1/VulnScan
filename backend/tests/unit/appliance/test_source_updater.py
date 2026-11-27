"""
L'updater d'une sonde installée depuis les sources
(deploy/probe/updater/v0cday-probe-source-update), lancé pour de vrai sur de
vrais dépôts git, avec une commande docker factice qui note ses appels.
"""
import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[4] / "deploy" / "probe" / "updater" / "v0cday-probe-source-update"

FAKE_DOCKER = r'''#!/bin/bash
echo "ARGS $*" >> "$STUB_LOG"
case " $* " in
  *" update-target "*) echo "${STUB_TARGET:-}"; exit "${STUB_TARGET_RC:-0}" ;;
  *" update-report "*) exit 0 ;;
  *" build "*) echo "BUILD_ENV ${V0CDAY_BUILD:-}" >> "$STUB_LOG"; exit "${STUB_BUILD_RC:-0}" ;;
  *" status "*) exit "${STUB_STATUS_RC:-0}" ;;
  *" ps "*) echo running-container-id ;;
esac
exit 0
'''


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}).stdout.strip()


class ProbeVm:
    """Un dépôt « GitHub » (origin), le clone de la VM de la sonde, docker factice."""

    def __init__(self, root: Path):
        self.origin = root / "origin.git"
        self.work = root / "work"       # où l'éditeur publie
        self.repo = root / "clone"      # la VM
        self.bin = root / "bin"
        self.log = root / "calls.log"
        git(root, "init", "--quiet", "--bare", "-b", "main", str(self.origin))
        git(root, "clone", "--quiet", str(self.origin), str(self.work))
        git(self.work, "checkout", "--quiet", "-b", "main")
        (self.work / "deploy" / "probe").mkdir(parents=True)
        self.v1 = self.publish("v1")
        git(root, "clone", "--quiet", str(self.origin), str(self.repo))
        (self.repo / "deploy" / "probe" / "config").mkdir()
        (self.repo / "deploy" / "probe" / "config" / "probe.json").write_text("{}")
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
        self.log.touch()

    def publish(self, content, branch="main"):
        git(self.work, "checkout", "--quiet", "-B", branch)
        (self.work / "deploy" / "probe" / "VERSION").write_text(content)
        git(self.work, "add", "-A")
        git(self.work, "commit", "--quiet", "-m", content)
        git(self.work, "push", "--quiet", "origin", branch)
        return git(self.work, "rev-parse", "HEAD")

    def run(self, **stub):
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": os.environ.get("HOME", "/tmp"),
            "V0CDAY_REPO_DIR": str(self.repo),
            "V0CDAY_HEALTH_DELAY": "0",
            "V0CDAY_HEALTH_TRIES": "2",
            "STUB_LOG": str(self.log),
            **{k: str(v) for k, v in stub.items()},
        }
        result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
        self.output = result.stdout + result.stderr
        return result.returncode

    @property
    def calls(self):
        return self.log.read_text().splitlines()

    @property
    def head(self):
        return git(self.repo, "rev-parse", "HEAD")

    def reports(self):
        return [c.split("update-report ", 1)[1] for c in self.calls if "update-report" in c]


@pytest.fixture
def vm(tmp_path):
    return ProbeVm(tmp_path)


def test_sans_demande_l_updater_ne_fait_rien(vm):
    assert vm.run(STUB_TARGET="") == 0
    assert [c for c in vm.calls if c.startswith("ARGS")] == ["ARGS compose run --rm -T probe update-target"]


def test_une_sonde_non_enrolee_n_appelle_rien(vm):
    (vm.repo / "deploy" / "probe" / "config" / "probe.json").unlink()

    assert vm.run(STUB_TARGET="x") == 0
    assert vm.calls == []


def test_la_sonde_passe_au_commit_demande_le_construit_et_le_signale(vm):
    v2 = vm.publish("v2")

    code = vm.run(STUB_TARGET=v2)

    assert code == 0, vm.output
    assert vm.head == v2
    assert git(vm.repo, "rev-parse", "--abbrev-ref", "HEAD") == "main", "reste sur sa branche (git pull marche)"
    assert f"BUILD_ENV {v2}" in vm.calls
    assert "ARGS compose up -d probe" in vm.calls
    rapports = vm.reports()
    assert rapports[0].startswith("--status running")
    assert rapports[-1].startswith(f"--status done --detail Now runs {v2[:12]}")


def test_un_commit_hors_de_la_branche_suivie_est_refuse(vm):
    ailleurs = vm.publish("branche piégée", branch="evil")
    git(vm.repo, "fetch", "--quiet", "origin", "evil")  # le commit est connu du clone, mais pas sur main

    code = vm.run(STUB_TARGET=ailleurs)

    assert code == 1
    assert vm.head == vm.v1
    assert not any(" build " in c for c in vm.calls)
    assert "is not on origin/main: refused" in vm.reports()[-1]


def test_un_commit_d_une_autre_branche_non_recuperee_est_refuse(vm):
    ailleurs = vm.publish("branche piégée", branch="evil")

    assert vm.run(STUB_TARGET=ailleurs) == 1
    assert vm.head == vm.v1
    assert not any(" build " in c for c in vm.calls)


def test_un_commit_inconnu_est_refuse(vm):
    assert vm.run(STUB_TARGET="f" * 40) == 1
    assert "is not in the repository" in vm.reports()[-1]
    assert vm.head == vm.v1


def test_une_cible_qui_n_est_pas_un_commit_complet_est_refusee(vm):
    assert vm.run(STUB_TARGET="main; rm -rf /") == 1
    assert "not a full commit id" in vm.reports()[-1]
    assert not any(" build " in c for c in vm.calls)


def test_un_build_qui_echoue_laisse_la_version_precedente(vm):
    v2 = vm.publish("v2")

    code = vm.run(STUB_TARGET=v2, STUB_BUILD_RC=1)

    assert code == 1
    assert vm.head == vm.v1
    assert "ARGS compose up -d probe" not in vm.calls
    assert "did not build" in vm.reports()[-1]


def test_une_version_qui_ne_demarre_pas_est_annulee(vm):
    v2 = vm.publish("v2")

    code = vm.run(STUB_TARGET=v2, STUB_STATUS_RC=1)

    assert code == 1
    assert vm.head == vm.v1
    assert "ARGS image tag v0cday-probe:previous v0cday-probe:latest" in vm.calls
    assert vm.calls.count("ARGS compose up -d probe") == 2
    assert "did not come up" in vm.reports()[-1]


def test_des_modifications_locales_bloquent_la_mise_a_jour(vm):
    v2 = vm.publish("v2")
    (vm.repo / "deploy" / "probe" / "VERSION").write_text("bricolé sur la VM")

    assert vm.run(STUB_TARGET=v2) == 1
    assert "local changes" in vm.reports()[-1]
    assert vm.head == vm.v1


def test_une_plateforme_injoignable_ne_change_rien(vm):
    assert vm.run(STUB_TARGET="", STUB_TARGET_RC=1) == 0
    assert vm.reports() == []
