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
    mkdir /genesis-dump
    "$ROOT/bin/updater" generate-dump --out-file /genesis-dump/dump.zip
    ls -lrt /genesis-dump

    info "Printing some stats"
    "$ROOT/bin/updater" print-stats /genesis-dump/dump.zip
}

generate_genesis_dump
