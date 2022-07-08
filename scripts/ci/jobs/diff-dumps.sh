#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

create_diff_dumps() {
    info "Creating diff dump for each manifest"

    require_executable "jq"

    local idx

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

upload_diff_dumps() {
    info "Uploading diff dumps"

    local branch
    local idx

    branch=$(get_base_ref)
    idx=-1
    while IFS=$'\t' read -r diffUUID; do
        idx=$((idx+1))
        expected_zip_file_loc="/tmp/diff-dumps/dump${idx}/diff.zip"
        [[ -f "${expected_zip_file_loc}" ]]
        if [[ -z "${diffUUID}" ]]; then
            continue
        fi
        echo "Found file at ${expected_zip_file_loc}"
        du -skh "${expected_zip_file_loc}"
        cmd=()
        # Note: CIRCLE_TAG is defined via openshift_ci_mods in scripts/ci/lib.sh.
        if [[ "$branch" != "master" && -z "${CIRCLE_TAG}" ]]; then
            cmd+=(echo "Would do")
        fi
        "${cmd[@]}" gsutil cp "${expected_zip_file_loc}" gs://definitions.stackrox.io/"${diffUUID}"/diff.zip
    done < <(jq -r '.knownGenesisDumps | .[]| [.uuid] | @tsv' < image/scanner/dump/genesis_manifests.json)
}

create_offline_dump() {
    info "Creating offline dump"

    local branch

    mkdir -p /tmp/offline-dump

    # Fetch the scanner dump which is marked as the base for offline dumps.
    # For offline dumps, we just use one base (the oldest base which is in a version of scanner still supported)
    # for simplicity.
    offline_dumps="$(jq '.knownGenesisDumps | map(.baseForOfflineDumps == true) | indices(true)' < image/scanner/dump/genesis_manifests.json)"
    echo "Got offline dumps list: ${offline_dumps}"
    [[ "$(echo "${offline_dumps}" | jq 'length')" -eq 1 ]]
    offline_diff_location="/tmp/diff-dumps/dump$(echo "${offline_dumps}" | jq -r '.[0]')/diff.zip"
    cp "${offline_diff_location}" /tmp/offline-dump/scanner-defs.zip

    # Prepare k8s and istio dump
    mkdir -p /tmp/scratch
    gsutil cp -r gs://definitions.stackrox.io/cve/* /tmp/scratch/
    cd /tmp/scratch
    zip -r /tmp/offline-dump/k8s-istio.zip *

    cd /tmp/offline-dump
    zip scanner-vuln-updates.zip scanner-defs.zip k8s-istio.zip
    du -skh scanner-vuln-updates.zip
    cmd=()
    branch=$(get_base_ref)
    # Note: CIRCLE_TAG is defined via openshift_ci_mods in scripts/ci/lib.sh.
    if [[ "$branch" != "master" && -z "${CIRCLE_TAG}" ]]; then
        cmd+=(echo "Would do")
    fi
    "${cmd[@]}" gsutil cp scanner-vuln-updates.zip gs://sr-roxc/scanner/scanner-vuln-updates.zip
}

upload_offline_dump() {
    info "Uploading offline dump"

    local branch

    cd /tmp/offline-dump
    cmd=()
    branch=$(get_base_ref)
    # Note: CIRCLE_TAG is defined via openshift_ci_mods in scripts/ci/lib.sh.
    if [[ "$branch" != "master" && -z "${CIRCLE_TAG}" ]]; then
      cmd+=(echo "Would do")
    fi
    "${cmd[@]}" gsutil cp scanner-vuln-updates.zip gs://scanner-support-public/offline/v1/scanner-vuln-updates.zip
}

diff_dumps() {
    info "Starting diff dumps"

    # These are not needed until later, but no reason to continue if these do not exist.
    require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"
    require_environment "GCP_SERVICE_ACCOUNT_CREDS"

    # Create diff dumps
    setup_gcp
    create_diff_dumps
    # Upload diff dumps
    setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"
    upload_diff_dumps

    # Create offline dump
    create_offline_dump
    # Upload offline dump
    setup_gcp "${GCP_SERVICE_ACCOUNT_CREDS}"
    upload_offline_dump
}

diff_dumps "$*"
