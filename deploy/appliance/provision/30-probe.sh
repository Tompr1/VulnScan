#!/bin/bash
# The probe: its image, its compose file, first boot and updates.
#
# Environment (from Packer variables):
#   PROBE_IMAGE           registry image pinned by digest, pulled; or empty
#                         and /tmp/v0cday-image/probe-image.tar is loaded
#   ALLOWED_IMAGE_PREFIX  images the updater accepts (…/v0cday-probe@sha256:)
#   REQUIRE_SIGNATURE     yes (default) or no (lab)
#   APPLIANCE_VERSION     written to /etc/v0cday-probe/appliance-version
set -euxo pipefail

# 1. The probe image, tagged as the built-in one.
if [ -n "${PROBE_IMAGE:-}" ]; then
  echo "$PROBE_IMAGE" | grep -Eq '@sha256:[0-9a-f]{64}$'
  docker pull "$PROBE_IMAGE"
  docker tag "$PROBE_IMAGE" v0cday-probe:appliance
else
  docker load -i /tmp/v0cday-image/probe-image.tar
  loaded=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '^v0cday-probe:' )
  [ -n "$loaded" ]
  [ "$loaded" = "v0cday-probe:appliance" ] || docker tag "$loaded" v0cday-probe:appliance
fi

# 2. Files.
install -d -m 0755 /opt/v0cday-probe
install -d -m 0700 /etc/v0cday-probe /var/lib/v0cday-probe
install -m 0644 /tmp/v0cday-files/docker-compose.yml /opt/v0cday-probe/docker-compose.yml
install -m 0755 /tmp/v0cday-files/v0cday-probe-firstboot /usr/local/sbin/v0cday-probe-firstboot
install -m 0755 /tmp/v0cday-files/v0cday-probe-update /usr/local/sbin/v0cday-probe-update
install -m 0644 /tmp/v0cday-files/v0cday-probe-firstboot.service /tmp/v0cday-files/v0cday-probe-update.service \
  /tmp/v0cday-files/v0cday-probe-update.timer /etc/systemd/system/

# 3. What the updater trusts. Signed updates without a key would refuse every
# update: stop the build instead.
if [ "${REQUIRE_SIGNATURE:-yes}" != "no" ] && [ ! -s /tmp/v0cday-files/cosign.pub ]; then
  echo "files/cosign.pub is missing: put the public key the probe images are signed with," >&2
  echo "or build with -var require_signature=no (lab only)." >&2
  exit 1
fi
key_line=""
if [ -s /tmp/v0cday-files/cosign.pub ]; then
  install -m 0644 /tmp/v0cday-files/cosign.pub /etc/v0cday-probe/cosign.pub
  key_line="COSIGN_PUBLIC_KEY=/etc/v0cday-probe/cosign.pub"
fi
{
  echo "ALLOWED_IMAGE_PREFIX=${ALLOWED_IMAGE_PREFIX:?set the allowed_image_prefix Packer variable}"
  [ -n "$key_line" ] && echo "$key_line"
  echo "REQUIRE_SIGNATURE=${REQUIRE_SIGNATURE:-yes}"
} > /etc/v0cday-probe/update.conf
chmod 0600 /etc/v0cday-probe/update.conf
echo "${APPLIANCE_VERSION:-dev}" > /etc/v0cday-probe/appliance-version

systemctl daemon-reload
systemctl enable v0cday-probe-firstboot.service v0cday-probe-update.timer

# 4. The image starts: the agent answers its own help.
docker run --rm v0cday-probe:appliance --help >/dev/null
