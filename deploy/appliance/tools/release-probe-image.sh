#!/bin/bash
# Publishes a probe image: build, push, sign with the MSP's cosign key, check
# the signature, and print the digest-pinned reference to roll it out.
#
#   COSIGN_KEY=cosign.key tools/release-probe-image.sh ghcr.io/your-msp/v0cday-probe 1.0.0
#
# Then:
#   - platform .env: PROBE_IMAGE=<printed reference>  (every appliance's
#     updater moves to it within the hour, after checking its signature);
#   - new appliances: packer build -var probe_image=<printed reference> ...
#
# Keep cosign.key offline (or use a KMS: COSIGN_KEY=awskms://...); only
# cosign.pub goes into the appliances (deploy/appliance/files/cosign.pub).
set -euo pipefail

repository="${1:?usage: release-probe-image.sh <registry/repository> <version>}"
version="${2:?usage: release-probe-image.sh <registry/repository> <version>}"
key="${COSIGN_KEY:?set COSIGN_KEY (cosign generate-key-pair makes one)}"
backend="$(cd "$(dirname "$0")/../../../backend" && pwd)"

docker build -f "$backend/Dockerfile.probe" -t "$repository:$version" "$backend"
docker push "$repository:$version"
reference=$(docker inspect --format '{{index .RepoDigests 0}}' "$repository:$version")
echo "$reference" | grep -Eq '@sha256:[0-9a-f]{64}$' || { echo "no digest for $repository:$version" >&2; exit 1; }

cosign sign --yes --key "$key" "$reference"
cosign verify --key "${COSIGN_PUBLIC_KEY:-${key%.key}.pub}" "$reference" >/dev/null

echo
echo "Signed and published: $reference"
echo "Roll it out with PROBE_IMAGE=$reference in the platform's .env"
