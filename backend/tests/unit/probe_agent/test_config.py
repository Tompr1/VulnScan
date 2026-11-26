"""Le fichier de configuration d'une sonde : il contient son secret."""
import stat

import pytest

from app.probe_agent.config import ConfigError, ProbeConfig


def config(**kwargs):
    values = {"platform_url": "https://soc.example", "credential": "7.s3cret", "probe_id": 7, "workspace_id": 1}
    values.update(kwargs)
    return ProbeConfig(**values)


def test_la_configuration_se_relit_a_l_identique(tmp_path):
    path = tmp_path / "etc" / "probe.json"

    config(local_allowlist="10.0.0.0/8").save(path)

    assert ProbeConfig.load(path) == config(local_allowlist="10.0.0.0/8")


def test_le_fichier_n_est_lisible_que_par_son_proprietaire(tmp_path):
    path = tmp_path / "probe.json"

    config().save(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_le_secret_n_apparait_pas_dans_la_representation():
    assert "s3cret" not in repr(config())
    assert config().authorization == "Probe 7.s3cret"


@pytest.mark.parametrize("url", ["http://soc.example", "soc.example", "ftp://soc.example"])
def test_une_plateforme_hors_https_est_refusee(url):
    with pytest.raises(ConfigError):
        config(platform_url=url)


def test_le_http_est_admis_pour_un_labo_quand_on_le_demande():
    assert config(platform_url="http://192.168.2.11:8888", allow_http=True).allow_http


def test_une_configuration_absente_dit_d_enroler_la_sonde(tmp_path):
    with pytest.raises(ConfigError, match="enroll"):
        ProbeConfig.load(tmp_path / "absent.json")


def test_une_cle_inconnue_d_une_version_plus_recente_est_ignoree(tmp_path):
    path = tmp_path / "probe.json"
    path.write_text('{"platform_url": "https://soc.example", "credential": "7.s", "future": 1}')

    assert ProbeConfig.load(path).credential == "7.s"
