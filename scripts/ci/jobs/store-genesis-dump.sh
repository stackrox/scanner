#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-postgres-tests.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"
set -euo pipefail

store_genesis_dump() {
    info "Storing genesis dump"
    store_test_results /tmp/genesis-dump genesis-dump
}

store_genesis_dump "$*"
