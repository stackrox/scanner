#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/gcp.sh
source "$ROOT/scripts/ci/gcp.sh"
# shellcheck source=../../../scripts/ci/lib.sh
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
        # $ROOT/bin/updater is from the generate-genesis image in OpenShift CI.
        "$ROOT/bin/updater" diff-dumps --base-dump "${dump_file_name}" --head-dump /tmp/genesis-dump/genesis-dump.zip --config "${config}" --out-file "/tmp/diff-dumps/dump${idx}/diff.zip"
    done < <(jq -r '.knownGenesisDumps | .[]| [.dumpLocationInGS, .timestamp, (.config // empty | tostring)] | @tsv' < image/scanner/dump/genesis_manifests.json)
    du -d 2 -kh "/tmp/diff-dumps"
}

create_offline_dump() {
    info "Creating offline dump"

    mkdir -p /tmp/offline-dump

    # Fetch the scanner dump which is marked as the base for offline dumps.
    # For offline dumps, we just use one base (the oldest base which is in a version of scanner still supported)
    # for simplicity.
    offline_dumps="$(jq '.knownGenesisDumps | map(.baseForOfflineDumps == true) | indices(true)' < image/scanner/dump/genesis_manifests.json)"
    echo "Got offline dumps list: ${offline_dumps}"
    [[ "$(echo "${offline_dumps}" | jq 'length')" -eq 1 ]]
    offline_diff_location="/tmp/diff-dumps/dump$(echo "${offline_dumps}" | jq -r '.[0]')/diff.zip"
    cp "${offline_diff_location}" /tmp/offline-dump/scanner-defs.zip

    du -h "scanner-defs.zip" | cut -f1
}

create_v4_dump() {
  curl https://raw.githubusercontent.com/stackrox/stackrox/master/scanner/updater/version/RELEASE_VERSION > out/RELEASE_VERSION.txt
  version_file="out/RELEASE_VERSION.txt"
  awk -F '.' '/^[0-9]+\.[0-9]+/ {print $1"."$2}' "$version_file" | sort -u > unique_versions.txt

  # Read the unique versions into an array
  readarray -t unique_versions < unique_versions.txt

  # Print unique versions
  echo "Unique X.Y versions:"
  for version in "${unique_versions[@]}"; do
      echo "$version"

      #zip scanner-vuln-"$version".zip /tmp/offline-dump/scanner-defs.zip /tmp/offline-dump/k8s-istio.zip
  done
}

diff_dumps() {
    info "Starting diff dumps"

    # These are not needed until later, but no reason to continue if these do not exist.
    require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"
    require_environment "SCANNER_GCP_SERVICE_ACCOUNT_CREDS"

    # Create diff dumps
    setup_gcp
    create_diff_dumps

    # Create offline dump
    create_offline_dump
    create_v4_dump
}

diff_dumps "$*"