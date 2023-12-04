#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../../.. && pwd)"
# shellcheck source=../../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

e2e_tests() {
    info "Starting e2e tests"

    make e2e-tests || touch FAIL

    info "Saving junit XML report"
    make generate-junit-reports || touch FAIL
    store_test_results junit-reports junit-reports

    [[ ! -f FAIL ]] || die "E2E tests failed"
}

e2e_tests "$*"
