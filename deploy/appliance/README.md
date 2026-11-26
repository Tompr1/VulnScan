# v0cday probe appliance

A ready-to-import VM for each client: Debian 12 + Docker + the probe. At its
first boot it enrolls itself with the configuration Root gives for that probe
(cloud-init), then runs the client's scans. It **opens no port**: no SSH, a
firewall that drops everything inbound; it only connects out to the platform
(HTTPS) and to the scan targets.

```
 MSP                                             Client
 ─ release a probe image (signed)                ─ imports the appliance (OVA/VHDX/qcow2)
 ─ build the appliance (Packer)        ────────► ─ gives it the first-boot configuration
 ─ Root › Scan probes: New probe                 ─ powers it on: it enrolls and shows online
   → download its first-boot configuration       ─ later: updates itself (OS and probe image)
```

## What the appliance does by itself

| | |
|---|---|
| First boot | `v0cday-probe-firstboot.service`: reads `/etc/v0cday-probe/seed.env` (written by cloud-init), enrolls, **deletes the token**, starts the probe. No seed: it waits and says so on the console. |
| Probe | `/opt/v0cday-probe/docker-compose.yml`, restarted with the VM; state in `/var/lib/v0cday-probe`. |
| Probe updates | `v0cday-probe-update.timer`, hourly: takes the image the platform asks for (`PROBE_IMAGE`), **only if pinned by digest, from the registry fixed at build time, and signed by the MSP's cosign key**; rolls back if the new image does not come up. A compromised platform cannot make a probe run another image. |
| OS updates | Debian security updates install by themselves; a kernel update reboots at 03:30. |
| Firewall | `nftables`: inbound dropped (answers to the probe's own connections excepted). |
| Access | None over the network: the hypervisor's console. The build account is removed at first boot. |

## 1. Sign and publish a probe image (MSP, once per release)

```sh
cosign generate-key-pair                       # once: cosign.key (keep offline), cosign.pub
cp cosign.pub deploy/appliance/files/cosign.pub
COSIGN_KEY=cosign.key deploy/appliance/tools/release-probe-image.sh ghcr.io/your-msp/v0cday-probe 1.0.0
```

It prints the digest-pinned reference, e.g.
`ghcr.io/your-msp/v0cday-probe@sha256:…`. Setting it as `PROBE_IMAGE` in the
platform's `.env` rolls it out to every appliance within the hour (the
production stack refuses a `PROBE_IMAGE` that is not pinned by digest).

## 2. Build the appliance (MSP)

Needs [Packer](https://developer.hashicorp.com/packer) with QEMU (KVM on a
Linux build machine) and `qemu-img`:

```sh
cd deploy/appliance
packer init probe.pkr.hcl
packer build \
  -var version=1.0.0 \
  -var allowed_image_prefix=ghcr.io/your-msp/v0cday-probe@sha256: \
  -var probe_image=ghcr.io/your-msp/v0cday-probe@sha256:<digest> \
  probe.pkr.hcl
```

Without a registry: `docker save v0cday-probe:latest -o image/probe-image.tar`
and leave `probe_image` empty. A lab without signing: `-var require_signature=no`
(the build refuses to run without `files/cosign.pub` otherwise).

Output in `output/v0cday-probe-1.0.0/`: `.qcow2` (Proxmox, KVM), `.ova`
(VMware, VirtualBox), `.vhdx` (Hyper-V) and `SHA256SUMS`.

## 3. Deliver it to a client

In **Root › Scan probes**: *New probe* for the client, then in the window that
shows the token, *Download first-boot configuration*. Optional fields:

- **client's own scope limit** — the probe refuses any job outside it;
- **platform CA certificate** — when the platform uses Caddy's internal CA
  (`deploy/master/README.md` says how to get it).

The file holds a **one-time token** (24 h by default): hand it over like a
password. Then, depending on the hypervisor:

| Hypervisor | Image | First-boot configuration |
|---|---|---|
| VMware ESXi / Workstation | `.ova` | seed ISO on the CD drive |
| Hyper-V | `.vhdx` (generation 2, Secure Boot template "Microsoft UEFI Certificate Authority"; or generation 1) | seed ISO on the DVD drive |
| Proxmox | `.qcow2` (`qm importdisk`) | cloud-init drive + `qm set <vmid> --cicustom "user=local:snippets/<file>"` |
| VirtualBox | `.ova` | seed ISO |
| AWS, Azure | qcow2 converted to the cloud's format | the instance's *user data* field |

Seed ISO:

```sh
tools/make-seed-iso.sh v0cday-probe-paris.user-data paris-seed.iso [network-config]
```

`network-config` (optional, cloud-init v2) sets a static IP; otherwise DHCP.
Give the VM at least 2 vCPU, 4 GB of memory and outbound access to the
platform (443) and to the networks it scans.

Power it on: within a few minutes the probe is **online** in Root. Delete the
seed (file and ISO) afterwards: the token is spent anyway.

## Troubleshooting (hypervisor console)

```sh
systemctl status v0cday-probe-firstboot     # enrollment
journalctl -u v0cday-probe-firstboot
docker compose -f /opt/v0cday-probe/docker-compose.yml logs -f probe
journalctl -u v0cday-probe-update           # image updates
```

An expired or used token: *New enrollment token* (key icon) in Root, a new
first-boot configuration, and on the console:
`cloud-init clean --reboot` after attaching the new seed.
