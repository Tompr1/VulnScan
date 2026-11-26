#!/bin/bash
# Makes the first-boot seed ISO of one probe (cloud-init NoCloud, label
# "cidata") from the user-data downloaded in Root > Scan probes. Attach it to
# the appliance's CD drive before its first boot (VMware, Hyper-V,
# VirtualBox; Proxmox can use its own cloud-init drive instead, see README).
#
#   tools/make-seed-iso.sh v0cday-probe-paris.user-data paris-seed.iso [network-config]
#
# network-config (optional): cloud-init network config v2, for a static IP;
# without it the appliance uses DHCP.
#
# The ISO holds a one-time enrollment token: hand it over like a password,
# delete it once the probe shows online.
set -euo pipefail

user_data="${1:?usage: make-seed-iso.sh <user-data> <output.iso> [network-config]}"
output="${2:?usage: make-seed-iso.sh <user-data> <output.iso> [network-config]}"
network_config="${3:-}"

head -n 1 "$user_data" | grep -qx '#cloud-config' || { echo "$user_data is not a #cloud-config file" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$user_data" "$work/user-data"
instance="v0cday-probe-$(date +%s)-$$"
printf 'instance-id: %s\n' "$instance" > "$work/meta-data"
if [ -n "$network_config" ]; then
  cp "$network_config" "$work/network-config"
fi

if command -v cloud-localds >/dev/null; then
  args=("$output" "$work/user-data" "$work/meta-data")
  [ -n "$network_config" ] && args=(--network-config "$work/network-config" "${args[@]}")
  cloud-localds "${args[@]}"
elif command -v genisoimage >/dev/null || command -v mkisofs >/dev/null; then
  tool=$(command -v genisoimage || command -v mkisofs)
  "$tool" -quiet -output "$output" -volid cidata -joliet -rock "$work"
elif command -v xorriso >/dev/null; then
  xorriso -as mkisofs -quiet -output "$output" -volid cidata -joliet -rock "$work"
elif command -v hdiutil >/dev/null; then
  rm -f "$output"
  hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$output" "$work"
else
  echo "Install cloud-image-utils, genisoimage or xorriso (or use macOS)" >&2
  exit 1
fi
echo "Seed written to $output (instance $instance)"
