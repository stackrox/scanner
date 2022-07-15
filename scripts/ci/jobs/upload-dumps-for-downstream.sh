#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

upload_dumps_for_downstream() {
#    if is_in_PR_context; then
#        info "In PR context. Skipping..."
#        return 0
#    fi

    info "Starting dumps upload"

    require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"
    setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"

    info "Extracting dumps"
    mkdir -p /tmp/vuln-dump
    zip /genesis-dump/dump.zip 'nvd/*' --copy --out /tmp/vuln-dump/nvd-definitions.zip
    zip /genesis-dump/dump.zip 'k8s/*' --copy --out /tmp/vuln-dump/k8s-definitions.zip
    zip /genesis-dump/dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/vuln-dump/repo2cpe.zip

    local scanner_version

    local base_ref
    base_ref="$(get_base_ref)"
    if [[ "${base_ref}" == "master" ]]; then
        # For the master branch we store artifacts in "unversioned" way to make sure this upload job works and
        # does not break on more rare tagged builds. Note that we should not consume these latest builds
        # downstream, we should use tagged ones instead because otherwise the master branch can introduce format
        # changes that the downstream release can be unprepared to deal with.
        scanner_version="latest"
    elif is_tagged; then
        # Tagged builds are the main ones for which we push artifacts and we use the tag as label. Makefile will
        # return tag in the `x.y.z` format for them.
        scanner_version="$(make --quiet --no-print-directory tag)"
    else
        die "Unsupported"
    fi

    destination="gs://definitions.stackrox.io/scanner-data/${scanner_version}/"

    info "Uploading dumps"
    cmd=(echo "Would do")
    "${cmd[@]}" gsutil cp /tmp/vuln-dump/nvd-definitions.zip "$destination"
    "${cmd[@]}" gsutil cp /tmp/vuln-dump/k8s-definitions.zip "$destination"
    "${cmd[@]}" gsutil cp /tmp/vuln-dump/repo2cpe.zip "$destination"
    "${cmd[@]}" gsutil cp /tmp/postgres/pg-definitions.sql.gz "$destination"
    # Note that we include genesis manifests for the downstream to avoid the situation when dumps taken from
    # GCloud are older than manifests taken from the source code repo.
    "${cmd[@]}" gsutil cp image/scanner/dump/genesis_manifests.json "$destination"
}

upload_dumps_for_downstream "$*"
