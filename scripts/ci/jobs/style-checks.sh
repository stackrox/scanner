#!/usr/bin/env bash

set -euo pipefail

style_checks() {
    info "Starting style checks"

    make style
}

style_checks "$*"
