#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-unit-tests.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

unit_tests() {
    info "Starting unit tests"

    make unit-tests || touch FAIL

    if is_OPENSHIFT_CI; then
        info "Saving junit XML report"
        make generate-junit-reports || touch FAIL
        store_test_results junit-reports junit-reports
    fi

    [[ ! -f FAIL ]] || die "Unit tests failed"
}

unit_tests "$*"
