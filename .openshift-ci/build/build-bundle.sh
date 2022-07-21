#!/usr/bin/env bash

# Execute the build steps required to create the scanner image's bundle.tar.gz.
#
# Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/build/build-main-and-bundle.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

openshift_ci_mods

cleanup_image() {
    if [[ -z "${OPENSHIFT_BUILD_NAME:-}" ]]; then
        info "This is not an OpenShift build, will not reduce the image"
        return
    fi

    info "Reducing the image size"

    set +e
    rm -rf /go/{bin,pkg}
    rm -rf /root/{.cache,.npm}
    rm -rf /usr/local/share/.cache
    rm -rf .git
    rm -rf image/scanner/bin
    rm -rf image/scanner/rhel/THIRD_PARTY_NOTICES
    set -e
}

get_genesis_dump() {
    info "Retrieving Genesis dump"

    ls -lrt /tmp/genesis-dump || info "No local genesis dump"

    if is_in_PR_context && ! pr_has_label "generate-dumps-on-pr"; then
        setup_gcp

        info "Label generate-dumps-on-pr not set. Pulling dumps from GCS bucket"
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/nvd-definitions.zip /tmp/nvd-definitions.zip
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/k8s-definitions.zip /tmp/k8s-definitions.zip
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/repo2cpe.zip /tmp/repo2cpe.zip
    else
        zip /tmp/genesis-dump/dump.zip 'nvd/*' --copy --out /tmp/nvd-definitions.zip
        zip /tmp/genesis-dump/dump.zip 'k8s/*' --copy --out /tmp/k8s-definitions.zip
        zip /tmp/genesis-dump/dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/repo2cpe.zip
    fi

    unzip -d image/scanner/dump /tmp/nvd-definitions.zip
    unzip -d image/scanner/dump /tmp/k8s-definitions.zip
    unzip -d image/scanner/dump /tmp/repo2cpe.zip
}

build_bundle() {
    info "Building Scanner binary"
    make scanner-build-nodeps

    info "Making THIRD_PARTY_NOTICES"
    make ossls-notice

    get_genesis_dump

    info "Creating Scanner bundle"
    "$ROOT/image/scanner/rhel/create-bundle.sh" "$ROOT/image/scanner" "$ROOT/image/scanner/rhel"

    cleanup_image
}

build_bundle
