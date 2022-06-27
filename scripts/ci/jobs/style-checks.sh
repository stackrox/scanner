#!/usr/bin/env bash

set -euo pipefail

style_checks() {
    info "Starting style checks"

    make style-checks
}

style_checks "$*"
