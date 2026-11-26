#!/bin/bash
# Base system: up to date, security updates by themselves, firewall, sysctl.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y full-upgrade
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg nftables unattended-upgrades apt-listchanges \
  qemu-guest-agent open-vm-tools hyperv-daemons

install -m 0644 /tmp/v0cday-files/50-v0cday-unattended-upgrades /etc/apt/apt.conf.d/50-v0cday-unattended-upgrades
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
  > /etc/apt/apt.conf.d/20auto-upgrades

install -m 0755 /tmp/v0cday-files/nftables.conf /etc/nftables.conf
systemctl enable nftables

install -m 0644 /tmp/v0cday-files/90-v0cday-sysctl.conf /etc/sysctl.d/90-v0cday.conf
