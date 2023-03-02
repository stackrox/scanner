#!/usr/bin/env bash
# Creates a tgz bundle of all binary artifacts needed for scanner

NVD_DEFINITIONS_DIR="/nvd_definitions"
K8S_DEFINITIONS_DIR="/k8s_definitions"
ISTIO_DEFINITIONS_DIR="/istio_definitions"
REPO_TO_CPE_DIR="/repo2cpe"

set -euo pipefail

die() {
    echo >&2 "$@"
    exit 1
}

INPUT_ROOT="$1"
OUTPUT_DIR="$2"

[[ -n "$INPUT_ROOT" && -n "$OUTPUT_DIR" ]] \
    || die "Usage: $0 <input-root-dir> <output-dir>"
[[ -d "$INPUT_ROOT" ]] \
    || die "Input root directory doesn't exist or is not a directory."
[[ -d "$OUTPUT_DIR" ]] \
    || die "Output directory doesn't exist or is not a directory."

OUTPUT_BUNDLE="${OUTPUT_DIR}/bundle.tar.gz"

# Create tmp directory with stackrox directory structure
bundle_root="$(mktemp -d)"
mkdir -p "${bundle_root}/${NVD_DEFINITIONS_DIR}"
mkdir -p "${bundle_root}/${K8S_DEFINITIONS_DIR}"
mkdir -p "${bundle_root}/${ISTIO_DEFINITIONS_DIR}"
mkdir -p "${bundle_root}/${REPO_TO_CPE_DIR}"
chmod -R 755 "${bundle_root}"

# =============================================================================
# Copy scripts to image build context directory

mkdir -p "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/entrypoint.sh"               "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/nodescanning-entrypoint.sh"  "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/import-additional-cas"       "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/restore-all-dir-contents"    "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/save-dir-contents"           "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/trust-root-ca"               "${OUTPUT_DIR}/scripts"

# =============================================================================
# Add binaries and data files to be included in the Dockerfile here. This
# includes artifacts that would be otherwise downloaded or included via a COPY
# command in the Dockerfile.

cp -p  "${INPUT_ROOT}/bin/scanner"                        "${bundle_root}/"
cp -p  "${INPUT_ROOT}/dump/genesis_manifests.json"        "${bundle_root}/"
cp -p  "${INPUT_ROOT}/dump/nvd/"*.json                    "${bundle_root}/${NVD_DEFINITIONS_DIR}"
cp -p  "${INPUT_ROOT}/dump/k8s/"*.yaml                    "${bundle_root}/${K8S_DEFINITIONS_DIR}"
cp -p  "${INPUT_ROOT}/dump/istio/"*.yaml                  "${bundle_root}/${ISTIO_DEFINITIONS_DIR}"
cp -p  "${INPUT_ROOT}/dump/rhelv2/repository-to-cpe.json" "${bundle_root}/${REPO_TO_CPE_DIR}"
cp -pr "${INPUT_ROOT}/rhel/THIRD_PARTY_NOTICES"           "${bundle_root}/"

# =============================================================================

# Files should have owner/group equal to root:root
if tar --version | grep -q "gnu" ; then
  tar_chown_args=("--owner=root:0" "--group=root:0")
else
  tar_chown_args=("--uid=0" "--uname=root" "--gid=0" "--gname=root")
fi

# Create output bundle of all files in $bundle_root
tar cz "${tar_chown_args[@]}" --file "$OUTPUT_BUNDLE" --directory "${bundle_root}" .

# Create checksum
sha512sum "${OUTPUT_BUNDLE}" > "${OUTPUT_BUNDLE}.sha512"
sha512sum --check "${OUTPUT_BUNDLE}.sha512"

# Clean up after success
rm -r "${bundle_root}"
