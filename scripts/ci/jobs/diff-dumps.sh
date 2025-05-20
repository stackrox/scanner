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

upload_diff_dumps() {
    info "Uploading diff dumps"

    local idx
    local expected_zip_file_loc

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
        if is_in_PR_context; then
            cmd+=(echo "Would do")
        fi
        "${cmd[@]}" gsutil cp "${expected_zip_file_loc}" gs://definitions.stackrox.io/"${diffUUID}"/diff.zip
    done < <(jq -r '.knownGenesisDumps | .[]| [.uuid] | @tsv' < image/scanner/dump/genesis_manifests.json)

    # If we're in a PR context, let's save the diff built on top of the latest genesis dump (as opposed to all the
    # diffs), to make it easier for developers to inspect the artifacts when looking through CI logs
    if is_in_PR_context; then
      if [[ -f "${expected_zip_file_loc}" ]]; then
          # $inspect_dir should correspond to the artifact directory in CI
          local inspect_dir
          inspect_dir="/tmp/diff-dumps-inspect"
          mkdir -p "${inspect_dir}"
          # GitHub Actions zips everything during upload, and it's slightly inconvenient to unzip this twice.
          # If it becomes a problem (e.g., the job is takes too long due to this unzipping and rezipping), we can remove
          # this conditional and just `cp` instead
          if is_GITHUB_ACTIONS; then
            unzip "${expected_zip_file_loc}" -d "${inspect_dir}"
          else
            cp "${expected_zip_file_loc}" "${inspect_dir}"
          fi
      else
        error "Couldn't copy ${expected_zip_file_loc} to ${inspect_dir}: ${expected_zip_file_loc} does not exist"
        return 1
      fi
    fi
}

scanner_v2_create_and_upload_bundle() {
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

    # Prepare k8s and istio dump
    mkdir -p /tmp/scratch
    gsutil cp -r gs://definitions.stackrox.io/cve2/* /tmp/scratch/
    cd /tmp/scratch
    zip -r /tmp/offline-dump/k8s-istio.zip *

    cd /tmp/offline-dump
    zip scanner-vuln-updates.zip scanner-defs.zip k8s-istio.zip
    du -skh scanner-vuln-updates.zip
    cmd=()
    if is_in_PR_context; then
        cmd+=(echo "Would do")
    fi
    "${cmd[@]}" gsutil cp scanner-vuln-updates.zip gs://sr-roxc/scanner/scanner-vuln-updates.zip
}

# scanner_v4_create_and_add_bundles() creates versioned offline bundles for V4
# and add V4 definitions to the latest offline bundle.  It determines the
# version to use for each release based on the contents of the
# VULNERABILITY_VERSION file present in each release tag.
# shellcheck disable=SC2120
scanner_v4_create_and_add_bundles() {
    local latest_bundle="${1:-scanner-vuln-updates.zip}"

    local curl="curl --silent --show-error --max-time 60 --retry 3"
    local release_version_url="https://raw.githubusercontent.com/stackrox/stackrox/master/scanner/updater/version/RELEASE_VERSION"
    local vuln_version_pattern="https://raw.githubusercontent.com/stackrox/stackrox/%s/scanner/VULNERABILITY_VERSION"

    [ -f scanner-defs.zip ] || die "missing required bundle inclusion: scanner-defs.zip"
    [ -f k8s-istio.zip ]    || die "missing required bundle inclusion: k8s-istio.zip"
    [ -f "$latest_bundle" ] || die "missing latest bundle: $latest_bundle"

    info "existing latest bundle:"
    unzip -l "$latest_bundle"

    info "fetching release versions at $release_version_url"

    # Read the supported releases file, filter lines with release versions,
    # parse 4.4.* and 4.5.* to print only the X.Y, otherwise print the whole
    # X.Y.Z, finally merge everything together, and pipe one release per line.

    $curl --fail "$release_version_url" \
        | grep '^[0-9]\+\.[0-9]\+\.[0-9]\+$' \
        | sed 's/^\(4\.4\|4\.5\)\..*/\1/' \
        | sort -V \
        | uniq \
        | while read -r release _; do
              v4_prefix=v4-definitions-
              case "$release" in
                  4.4)
                      # We don't support 4.4 offline bundles.
                      continue
                      ;;
                  4.5)
                      # Backward compatibility, the "schema version" is the release itself.
                      version="$release"
                      v4_prefix="scanner-v4-defs-"
                      ;;
                  *)
                      info "fetching schema version for release $release"
                      tmp=$(mktemp)
                      # shellcheck disable=SC2059
                      vuln_version_url=$(printf "$vuln_version_pattern" "$release")
                      local http_status
                      http_status=$($curl --write-out "%{http_code}" -o "$tmp" "$vuln_version_url")
                      case $http_status in
                          200)
                              version=$(cat "$tmp")
                              ;;
                          404)
                              info "release tag not found, assuming the release was not cut, skipping..."
                              continue
                              ;;
                          *)
                              die "failed to fetch the v4 offline bundle version for $release: status $http_status"
                              ;;
                      esac
                      ;;
              esac

              local v4_bundle="$v4_prefix$version.zip"
              info "building $release using schema version $version: filename: $v4_bundle"

              $curl \
                  --fail \
                  -o "$v4_bundle" \
                  "https://definitions.stackrox.io/v4/offline-bundles/$v4_bundle"
              zip "$latest_bundle" "$v4_bundle"
              zip "scanner-vulns-$release.zip" scanner-defs.zip k8s-istio.zip "$v4_bundle"
          done
}

upload_bundles() {
    info "Uploading offline dump"
    cmd=()
    if is_in_PR_context; then
        cmd+=(echo "Would do")
    fi
    "${cmd[@]}" gsutil cp scanner-vuln-updates.zip gs://scanner-support-public/offline/v1/scanner-vuln-updates.zip
    for f in scanner-vulns-*.zip; do
        version=$(echo "$f" | sed 's/scanner-vulns-\(.*\)\.zip/\1/')
        "${cmd[@]}" gsutil cp "$f" gs://scanner-support-public/offline/v1/${version}/scanner-vulns-${version}.zip
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

    # Upload diff dumps
    setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"
    upload_diff_dumps

    # Create offline dump
    scanner_v2_create_and_upload_bundle
    scanner_v4_create_and_add_bundles

    # Upload offline dump
    setup_gcp "${SCANNER_GCP_SERVICE_ACCOUNT_CREDS}"
    upload_bundles
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    diff_dumps "$*"
fi
