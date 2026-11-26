#!/bin/bash
# Converts the appliance's qcow2 into what each hypervisor imports, next to it:
#   <name>.qcow2  Proxmox, KVM/libvirt (as built)
#   <name>.ova    VMware ESXi/Workstation, VirtualBox (OVF 1.0 + streamOptimized VMDK)
#   <name>.vhdx   Hyper-V (generation 2, UEFI... see README for generation 1)
#   SHA256SUMS    of the three
#
#   tools/convert.sh output/v0cday-probe-1.0.0/v0cday-probe-1.0.0.qcow2 1.0.0
set -euo pipefail

qcow2="${1:?usage: convert.sh <image.qcow2> <version>}"
version="${2:?usage: convert.sh <image.qcow2> <version>}"
here="$(cd "$(dirname "$0")" && pwd)"
dir="$(cd "$(dirname "$qcow2")" && pwd)"
name="$(basename "$qcow2" .qcow2)"
cpus="${APPLIANCE_CPUS:-2}"
memory_mb="${APPLIANCE_MEMORY_MB:-4096}"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
file_size() { wc -c < "$1" | tr -d ' '; }

cd "$dir"
qemu-img convert -O vmdk -o subformat=streamOptimized "$name.qcow2" "$name-disk1.vmdk"
qemu-img convert -O vhdx -o subformat=dynamic "$name.qcow2" "$name.vhdx"

capacity=$(qemu-img info --output=json "$name.qcow2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
sed -e "s|@NAME@|$name|g" \
    -e "s|@VERSION@|$version|g" \
    -e "s|@DISK_FILE@|$name-disk1.vmdk|g" \
    -e "s|@DISK_SIZE@|$(file_size "$name-disk1.vmdk")|g" \
    -e "s|@CAPACITY@|$capacity|g" \
    -e "s|@CPUS@|$cpus|g" \
    -e "s|@MEMORY_MB@|$memory_mb|g" \
    "$here/probe.ovf.template" > "$name.ovf"
{
  echo "SHA256($name.ovf)= $(sha256 "$name.ovf")"
  echo "SHA256($name-disk1.vmdk)= $(sha256 "$name-disk1.vmdk")"
} > "$name.mf"
# The OVF descriptor must come first in an OVA.
tar --format=ustar -cf "$name.ova" "$name.ovf" "$name.mf" "$name-disk1.vmdk"
rm -f "$name.ovf" "$name.mf" "$name-disk1.vmdk"

{
  for f in "$name.qcow2" "$name.ova" "$name.vhdx"; do echo "$(sha256 "$f")  $f"; done
} > SHA256SUMS
echo "Built in $dir: $name.qcow2 $name.ova $name.vhdx SHA256SUMS"
