#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"
source "$ROOT/scripts/ci/store-artifacts.sh"

set -euo pipefail

generate_genesis_dump() {
    info "Starting genesis dump generation tests"

    local updater="${SHARED_DIR}/updater"

    eval updater generate-dump --out-file "${SHARED_DIR}"/dump.zip
    ls -lrt /tmp/genesis-dump

    eval updater print-stats "${SHARED_DIR}"/dump.zip

    store_artifacts "${SHARED_DIR}"/dump.zip genesis-dump.zip
}

generate_genesis_dump "$*"
