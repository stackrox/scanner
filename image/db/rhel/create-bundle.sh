#!/usr/bin/env bash
# Creates a tgz bundle of all binary artifacts needed for scanner-db-rhel

set -euo pipefail

die() {
    echo >&2 "$@"
    exit 1
}

INPUT_ROOT="$1"
OUTPUT_BUNDLE="$2"

[[ -n "$INPUT_ROOT" && -n "$OUTPUT_BUNDLE" ]] \
    || die "Usage: $0 <input-root> <output-bundle>"
[[ -d "$INPUT_ROOT" ]] \
    || die "Input root directory doesn't exist or is not a directory."

# Create tmp directory with stackrox directory structure
bundle_root="$(mktemp -d)"
mkdir -p "${bundle_root}/"{"usr/local/bin","etc","docker-entrypoint-initdb.d"}
chmod -R 755 "${bundle_root}"

# =============================================================================

# Add files to be included in the Dockerfile here. This includes artifacts that
# would be otherwise downloaded or included via a COPY command in the
# Dockerfile.

cp -p "${INPUT_ROOT}/dump/definitions.sql.gz" "${bundle_root}/docker-entrypoint-initdb.d/"
cp -p "${INPUT_ROOT}/rhel/docker-entrypoint.sh" "${bundle_root}/usr/local/bin/"
cp -p "${INPUT_ROOT}"/*.conf "${bundle_root}/etc/"

postgres_url="https://download.postgresql.org/pub/repos/yum/12/redhat/rhel-8.1-x86_64"
postgres_major="12"
postgres_minor="12.1-2PGDG.rhel8.x86_64"

curl -s -o "${bundle_root}/postgres.rpm" \
    "${postgres_url}/postgresql${postgres_major}-${postgres_minor}.rpm"
curl -s -o "${bundle_root}/postgres-server.rpm" \
    "${postgres_url}/postgresql${postgres_major}-server-${postgres_minor}.rpm"
curl -s -o "${bundle_root}/postgres-libs.rpm" \
    "${postgres_url}/postgresql${postgres_major}-libs-${postgres_minor}.rpm"

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

