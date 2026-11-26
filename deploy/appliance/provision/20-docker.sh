#!/bin/bash
# Docker Engine and the Compose plugin from Docker's repository (Debian's own
# has no Compose v2), and cosign to check the signature of probe images.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# Docker's release key, checked against its published fingerprint.
DOCKER_KEY_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.asc
gpg --show-keys --with-colons /tmp/docker.asc | grep -q "^fpr:::::::::${DOCKER_KEY_FINGERPRINT}:"
gpg --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
install -m 0644 /tmp/v0cday-files/docker-daemon.json /etc/docker/daemon.json
systemctl enable docker
systemctl restart docker

# cosign, checked against the release's checksums.
COSIGN_VERSION="${COSIGN_VERSION:-2.4.1}"
arch=$(dpkg --print-architecture)
base="https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}"
curl -fsSL -o /tmp/cosign "${base}/cosign-linux-${arch}"
curl -fsSL -o /tmp/cosign_checksums.txt "${base}/cosign_checksums.txt"
expected=$(awk -v f="cosign-linux-${arch}" '$2 == f {print $1}' /tmp/cosign_checksums.txt)
[ -n "$expected" ]
echo "${expected}  /tmp/cosign" | sha256sum -c -
install -m 0755 /tmp/cosign /usr/local/bin/cosign
rm -f /tmp/cosign /tmp/cosign_checksums.txt /tmp/docker.asc
