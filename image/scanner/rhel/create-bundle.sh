#!/usr/bin/env bash
# Creates a tgz bundle of all binary artifacts needed for scanner-rhel

NVD_DEFINITIONS_DIR="/nvd_definitions"

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
chmod -R 755 "${bundle_root}"

# =============================================================================
# Copy scripts to image build context directory

mkdir -p "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/entrypoint.sh"               "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/import-additional-cas"       "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/restore-all-dir-contents"    "${OUTPUT_DIR}/scripts"
cp "${INPUT_ROOT}/scripts/save-dir-contents"           "${OUTPUT_DIR}/scripts"

# =============================================================================
# Add binaries and data files to be included in the Dockerfile here. This
# includes artifacts that would be otherwise downloaded or included via a COPY
# command in the Dockerfile.

cp -p "${INPUT_ROOT}/bin/scanner" "${bundle_root}/"
cp -p "${INPUT_ROOT}/dump/genesis_manifests.json" "${bundle_root}/"
cp -p "${INPUT_ROOT}/dump/nvd/"*.json "${bundle_root}/${NVD_DEFINITIONS_DIR}"

# =============================================================================

# Files should have owner/group equal to root:root
if tar --version | grep -q "gnu" ; then
  tar_chown_args=("--owner=root:0" "--group=root:0")
else
  tar_chown_args=("--uid=root:0" "--gid=root:0")
fi

# Create output bundle of all files in $bundle_root
tar cz "${tar_chown_args[@]}" --file "$OUTPUT_BUNDLE" --directory "${bundle_root}" .

# Create checksum
sha512sum "${OUTPUT_BUNDLE}" > "${OUTPUT_BUNDLE}.sha512"
sha512sum --check "${OUTPUT_BUNDLE}.sha512"

# Clean up after success
rm -r "${bundle_root}"
