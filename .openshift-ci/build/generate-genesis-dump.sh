#!/usr/bin/env bash

# Execute all steps required to generate the genesis dump

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

openshift_ci_mods

gate_job generate-genesis-dump

generate_genesis_dump() {
    info "Building updater"
    make build-updater

    info "Generating genesis dump"
    mkdir -p /tmp/genesis-dump
    "$ROOT/bin/updater" generate-dump --out-file /tmp/genesis-dump/genesis-dump.zip
    ls -lrt /tmp/genesis-dump

    info "Printing some stats"
    "$ROOT/bin/updater" print-stats /tmp/genesis-dump/genesis-dump.zip

    info "Extracting dumps"
    mkdir -p /tmp/vuln-dump
    zip /tmp/genesis-dump/dump.zip 'nvd/*' --copy --out /tmp/vuln-dump/nvd-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'k8s/*' --copy --out /tmp/vuln-dump/k8s-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/vuln-dump/repo2cpe.zip
}

generate_genesis_dump
