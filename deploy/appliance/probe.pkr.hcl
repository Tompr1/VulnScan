# v0cday scan probe appliance: a Debian 12 VM running the probe, delivered
# to each client as qcow2 (Proxmox/KVM), OVA (VMware, VirtualBox) and VHDX
# (Hyper-V). See README.md.
#
#   packer init probe.pkr.hcl
#   packer build -var allowed_image_prefix=ghcr.io/your-msp/v0cday-probe@sha256: \
#                -var probe_image=ghcr.io/your-msp/v0cday-probe@sha256:<digest> \
#                -var version=1.0.0 probe.pkr.hcl
#
# Needs QEMU on the build machine (KVM acceleration on Linux, hvf on macOS
# Intel), and qemu-img for the conversions.

packer {
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "version" {
  type        = string
  default     = "dev"
  description = "Appliance version, in the file names and /etc/v0cday-probe/appliance-version."
}

variable "debian_image_url" {
  type    = string
  default = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
}

variable "debian_image_checksum" {
  type    = string
  default = "file:https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"
}

variable "probe_image" {
  type        = string
  default     = ""
  description = "Probe image pinned by digest (registry/v0cday-probe@sha256:...). Empty: load image/probe-image.tar (docker save)."
}

variable "allowed_image_prefix" {
  type        = string
  description = "Images the appliance's updater accepts, e.g. ghcr.io/your-msp/v0cday-probe@sha256:"
}

variable "require_signature" {
  type        = string
  default     = "yes"
  description = "yes: updates must be signed by files/cosign.pub. no: lab only."
}

variable "disk_size" {
  type    = string
  default = "20G"
}

variable "accelerator" {
  type    = string
  default = "kvm"
}

locals {
  name = "v0cday-probe-${var.version}"
  # Used during this build only, then locked (provision/90-cleanup.sh).
  build_password = uuidv4()
}

source "qemu" "probe" {
  iso_url      = var.debian_image_url
  iso_checksum = var.debian_image_checksum
  disk_image   = true
  disk_size    = var.disk_size
  format       = "qcow2"
  accelerator  = var.accelerator
  headless     = true
  memory       = 2048
  cpus         = 2
  net_device   = "virtio-net"
  disk_interface = "virtio"

  cd_label = "cidata"
  cd_content = {
    "meta-data" = file("${path.root}/build/meta-data")
    "user-data" = templatefile("${path.root}/build/user-data.pkrtpl", { password = local.build_password })
  }

  ssh_username     = "packer"
  ssh_password     = local.build_password
  ssh_timeout      = "20m"
  shutdown_command = "sudo shutdown -P now"

  output_directory = "${path.root}/output/${local.name}"
  vm_name          = "${local.name}.qcow2"
}

build {
  sources = ["source.qemu.probe"]

  provisioner "file" {
    source      = "${path.root}/files/"
    destination = "/tmp/v0cday-files"
  }

  # image/ may hold probe-image.tar (docker save) when probe_image is empty.
  provisioner "file" {
    source      = "${path.root}/image/"
    destination = "/tmp/v0cday-image"
  }

  provisioner "shell" {
    execute_command = "sudo -E bash '{{ .Path }}'"
    environment_vars = [
      "PROBE_IMAGE=${var.probe_image}",
      "ALLOWED_IMAGE_PREFIX=${var.allowed_image_prefix}",
      "REQUIRE_SIGNATURE=${var.require_signature}",
      "APPLIANCE_VERSION=${var.version}",
    ]
    scripts = [
      "${path.root}/provision/10-base.sh",
      "${path.root}/provision/20-docker.sh",
      "${path.root}/provision/30-probe.sh",
      "${path.root}/provision/90-cleanup.sh",
    ]
  }

  post-processor "shell-local" {
    inline = ["${path.root}/tools/convert.sh ${path.root}/output/${local.name}/${local.name}.qcow2 ${var.version}"]
  }
}
