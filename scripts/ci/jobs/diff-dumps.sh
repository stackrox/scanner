#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

create_diff_dumps() {
    info "Creating diff dump for each manifest"

    require_executable "jq"

    mkdir -p /tmp/diff-dumps
    idx=-1
    while IFS=$'\t' read -r dumploc timestamp config; do
        idx=$((idx+1))
        dump_file_name="${dumploc##*/}"
        echo "Pulling genesis dump from ${dumploc}"
        gsutil cp "${dumploc}" .
        timestamp_in_zip="$(unzip -p "${dump_file_name}" manifest.json | jq -r '.until')"
        echo "Got timestamps -- from zip: ${timestamp_in_zip}; from manifest: ${timestamp}"
        [[ "${timestamp_in_zip}" == "${timestamp}" ]] # Assertion on the manifest contents
        # ./bin/updater is from the generate-genesis image in OpenShift CI.
        ./bin/updater diff-dumps --base-dump "${dump_file_name}" --head-dump /tmp/genesis-dump/dump.zip --config "${config}" --out-file "/tmp/diff-dumps/dump${idx}/diff.zip"
    done < <(jq -r '.knownGenesisDumps | .[]| [.dumpLocationInGS, .timestamp, (.config // empty | tostring)] | @tsv' < image/scanner/dump/genesis_manifests.json)
    du -d 2 -kh "/tmp/diff-dumps"
}

diff_dumps() {
    info "Starting diff dumps"

    # This is not needed until later, but no reason to continue if this does not exist.
    require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"

    setup_gcp

    create_diff_dumps

    setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"
}

diff_dumps "$*"