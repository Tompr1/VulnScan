#!/bin/bash
# Last step: no SSH, no build account, a clean cloud-init for the client's
# first boot, nothing left from the build.
set -euxo pipefail

# The appliance has no SSH: the client's VM opens no port. Support goes
# through the hypervisor's console. (Packer's own session ends with this
# script.)
systemctl disable ssh.service ssh.socket 2>/dev/null || true
# The build account goes with the next boot's cloud-init clean state.
cat > /etc/cloud/cloud.cfg.d/90-v0cday.cfg <<'CFG'
# v0cday probe appliance: no default user, no SSH keys, no password login.
users: []
disable_root: true
ssh_pwauth: false
ssh_deletekeys: true
CFG

apt-get -y autoremove --purge
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/v0cday-files /tmp/v0cday-image
docker image prune -f
journalctl --rotate && journalctl --vacuum-time=1s || true

# cloud-init runs again at the client's first boot (seed with the token).
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*
# The build account cannot be removed while Packer's session uses it: it is
# locked now (no password, no shell, no sudo) and removed at the first boot.
passwd -l packer
usermod -s /usr/sbin/nologin packer
rm -f /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/packer
