#!/bin/bash
# Installs (or removes) the updater of a probe installed from the source, so
# that Root > Scan probes > Update can update it. Run once, with sudo, from
# the clone:
#
#   sudo deploy/probe/updater/install-updater.sh             # install
#   sudo deploy/probe/updater/install-updater.sh --uninstall # remove
#
# The updater runs every minute as the user who owns the clone (it must be in
# the docker group), and only does something when Root asked for an update.
set -euo pipefail

UNIT=v0cday-probe-source-update
SYSTEMD_DIR="${V0CDAY_SYSTEMD_DIR:-/etc/systemd/system}"

die() { echo "install-updater: $*" >&2; exit 1; }

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now "$UNIT.timer" 2>/dev/null || true
  rm -f "$SYSTEMD_DIR/$UNIT.service" "$SYSTEMD_DIR/$UNIT.timer"
  systemctl daemon-reload
  echo "Updater removed. Probe updates are done by hand again (deploy/probe/README.md)."
  exit 0
fi

[ "$(id -u)" = 0 ] || die "run it with sudo"
owner=$(stat -c %U "$repo")
[ "$owner" != root ] || die "$repo belongs to root: clone the repository as the user who runs the probe"
id -nG "$owner" | tr ' ' '\n' | grep -qx docker || die "$owner is not in the docker group (sudo usermod -aG docker $owner)"
[ -d "$repo/.git" ] || die "$repo is not a git clone"
branch=$(sudo -u "$owner" git -C "$repo" rev-parse --abbrev-ref HEAD)
[ "$branch" != HEAD ] || branch=main
chmod +x "$here/$UNIT"

cat > "$SYSTEMD_DIR/$UNIT.service" <<EOF
[Unit]
Description=v0cday probe: apply the update asked in Root (installs from the source)
Wants=network-online.target
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=oneshot
User=$owner
WorkingDirectory=$repo/deploy/probe
Environment=V0CDAY_UPDATE_BRANCH=$branch
ExecStart=$here/$UNIT
# A rebuild takes 10 to 20 minutes.
TimeoutStartSec=1h
EOF

cat > "$SYSTEMD_DIR/$UNIT.timer" <<EOF
[Unit]
Description=v0cday probe: check every minute whether Root asked for an update

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "$UNIT.timer"
echo "Updater installed: it runs every minute as $owner, following $branch of $(sudo -u "$owner" git -C "$repo" remote get-url origin)."
echo "Logs: journalctl -u $UNIT"
