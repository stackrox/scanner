#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

FAIL_FLAG="/tmp/fail"

info 'Check .containerignore file is in sync with .dockerignore (If this fails, follow instructions in .containerignore to update it.)'
function check-containerignore-is-in-sync() {
    diff \
        --unified \
        --ignore-blank-lines \
        <(grep -v -e '^#' .containerignore) \
        <(grep -vF -e '/.git/' -e '/image/' -e '/qa-tests-backend/' .dockerignore) \
    > diff.txt
}
check-containerignore-is-in-sync || {
    info ".containerignore file is not in sync with .dockerignore"
    info "$(cat diff.txt)"
    git reset --hard HEAD
    echo check-containerignore-is-in-sync >> "$FAIL_FLAG"
}

if [[ -e "$FAIL_FLAG" ]]; then
    echo "ERROR: Some generated file checks failed:"
    cat "$FAIL_FLAG"
    exit 1
fi
