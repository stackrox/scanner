#!/usr/bin/env bash
# Creates a tgz bundle of all binary artifacts needed for scanner-db

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
mkdir -p "${bundle_root}/"{"usr/local/bin","etc","docker-entrypoint-initdb.d"}
chmod -R 755 "${bundle_root}"

# =============================================================================

# Add files to be included in the Dockerfile here. This includes artifacts that
# would be otherwise downloaded or included via a COPY command in the
# Dockerfile.

cp -p "${INPUT_ROOT}/dump/definitions.sql.gz" "${bundle_root}/docker-entrypoint-initdb.d/"
cp -p "${INPUT_ROOT}"/*.conf "${bundle_root}/etc/"

# =============================================================================

# Files should have owner/group equal to root:root
if tar --version | grep -q "gnu" ; then
  tar_chown_args=("--owner=root:0" "--group=root:0")
else
  tar_chown_args=("--uid=0" "--uname=root" "--gid=0" "--gname=root")
fi

# Create output bundle of all files in $bundle_root
tar cz --file "$OUTPUT_BUNDLE" --directory "${bundle_root}" .

# Create checksum
sha512sum "${OUTPUT_BUNDLE}" > "${OUTPUT_BUNDLE}.sha512"
sha512sum --check "${OUTPUT_BUNDLE}.sha512"

# Clean up after success
rm -r "${bundle_root}"
