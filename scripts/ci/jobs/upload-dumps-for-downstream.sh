#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

upload_dumps_for_downstream() {
    info "Starting dumps upload"

    require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"
    setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"

    info "Extracting dumps"
    mkdir -p /tmp/vuln-dump
    zip /tmp/genesis-dump/dump.zip 'nvd/*' --copy --out /tmp/vuln-dump/nvd-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'k8s/*' --copy --out /tmp/vuln-dump/k8s-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/vuln-dump/repo2cpe.zip

    local scanner_version
    if [[ -n "${CIRCLE_TAG}" || "${CIRCLE_BRANCH}" != "master" ]]; then
        # Tagged builds are the main ones for which we push artifacts and we use the tag as label. Makefile will
        # return tag in the `2.20.0` format for them.

        # Also, for PRs with the expected label, we will use the tag that the makefile returns. However that tag
        # would look like `2.20.0-3-g74ff9abf69` and should not overwrite the production tagged dumps. This is
        # enabled for ability to dry-run this upload job.

        scanner_version="$(make --quiet --no-print-directory tag)"
    else
        # For the master branch we store artifacts in "unversioned" way to make sure this upload job works and
        # does not break on more rare tagged builds. Note that we should not consume these latest builds
        # downstream, we should use tagged ones instead becase otherwise the master branch can introduce format
        # changes that the downstream release can be unprepared to deal with.
        scanner_version="latest"
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
