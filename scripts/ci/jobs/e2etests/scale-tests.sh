#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

scale_tests() {
    info "Starting scale tests"

    make scale-tests
}

scale_tests "$*"
