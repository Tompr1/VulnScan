"""
Outils de fabrication de l'appliance (deploy/appliance/tools), lancés avec
les vrais qemu-img et générateurs d'ISO quand la machine les a.
"""
import hashlib
import json
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[4] / "deploy" / "appliance" / "tools"
OVF = "{http://schemas.dmtf.org/ovf/envelope/1}"

needs_qemu = pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img absent")
needs_iso_tool = pytest.mark.skipif(
    not any(shutil.which(t) for t in ("cloud-localds", "genisoimage", "mkisofs", "xorriso", "hdiutil")),
    reason="aucun outil ISO",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@needs_qemu
def test_l_image_est_livree_en_qcow2_ova_et_vhdx_avec_leurs_empreintes(tmp_path):
    # Arrange : une image qcow2 vide de 64 Mio tient lieu d'appliance.
    qcow2 = tmp_path / "v0cday-probe-1.0.0.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(qcow2), "64M"], check=True)

    # Act
    subprocess.run(["bash", str(TOOLS / "convert.sh"), str(qcow2), "1.0.0"], check=True, capture_output=True)

    # Assert : l'OVA commence par son descripteur, que le manifeste couvre.
    ova = tmp_path / "v0cday-probe-1.0.0.ova"
    with tarfile.open(ova) as archive:
        names = archive.getnames()
        assert names == ["v0cday-probe-1.0.0.ovf", "v0cday-probe-1.0.0.mf", "v0cday-probe-1.0.0-disk1.vmdk"]
        archive.extractall(tmp_path / "ova")
    extracted = tmp_path / "ova"
    envelope = ET.parse(extracted / names[0]).getroot()
    file_ref = envelope.find(f"{OVF}References/{OVF}File")
    disk = envelope.find(f"{OVF}DiskSection/{OVF}Disk")
    vmdk = extracted / names[2]
    assert file_ref.get(f"{OVF}href") == names[2]
    assert int(file_ref.get(f"{OVF}size")) == vmdk.stat().st_size
    assert int(disk.get(f"{OVF}capacity")) == 64 * 1024 * 1024
    assert envelope.find(f".//{OVF}Version").text == "1.0.0"
    manifest = (extracted / names[1]).read_text().splitlines()
    assert manifest == [f"SHA256({names[0]})= {sha256(extracted / names[0])}", f"SHA256({names[2]})= {sha256(vmdk)}"]

    info = json.loads(subprocess.run(["qemu-img", "info", "--output=json", str(vmdk)],
                                     check=True, capture_output=True, text=True).stdout)
    assert (info["format"], info["format-specific"]["data"]["create-type"]) == ("vmdk", "streamOptimized")
    vhdx = tmp_path / "v0cday-probe-1.0.0.vhdx"
    assert json.loads(subprocess.run(["qemu-img", "info", "--output=json", str(vhdx)],
                                     check=True, capture_output=True, text=True).stdout)["format"] == "vhdx"
    sums = (tmp_path / "SHA256SUMS").read_text().splitlines()
    assert sums == [f"{sha256(tmp_path / f)}  {f}" for f in (qcow2.name, ova.name, vhdx.name)]


@needs_iso_tool
def test_la_graine_de_premier_demarrage_est_un_iso_cidata_avec_son_user_data(tmp_path):
    user_data = tmp_path / "paris.user-data"
    user_data.write_text("#cloud-config\nwrite_files: []\n")
    iso = tmp_path / "seed.iso"

    subprocess.run(["bash", str(TOOLS / "make-seed-iso.sh"), str(user_data), str(iso)], check=True, capture_output=True)

    data = iso.read_bytes()
    primary_volume = data[16 * 2048:17 * 2048]
    assert primary_volume[1:6] == b"CD001"
    # Padded with spaces (genisoimage) or NUL bytes (hdiutil): blkid reads both as CIDATA.
    assert primary_volume[40:72].strip(b" \x00").upper() == b"CIDATA"
    assert b"user-data" in data or "user-data".encode("utf-16-be") in data
    assert b"#cloud-config" in data


def test_un_fichier_qui_n_est_pas_un_cloud_config_est_refuse(tmp_path):
    user_data = tmp_path / "x"
    user_data.write_text("rm -rf /\n")

    result = subprocess.run(["bash", str(TOOLS / "make-seed-iso.sh"), str(user_data), str(tmp_path / "s.iso")],
                            capture_output=True, text=True)

    assert result.returncode == 1 and "not a #cloud-config" in result.stderr
