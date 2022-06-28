#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

build_updater() {
    info "Building updater"

    make build-updater

    cp ./bin/updater "${SHARED_DIR}"
}

build_updater "$*"
