#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

shopt -s nullglob
for cred in /tmp/secret/**/[A-Z]*; do
    export "$(basename "$cred")"="$(cat "$cred")"
done

openshift_ci_mods

function hold() {
    while [[ -e /tmp/hold ]]; do
        info "Holding this job for debug"
        sleep 60
    done
}
trap hold EXIT

if [[ "$#" -lt 1 ]]; then
    die "usage: dispatch <ci-job> [<...other parameters...>]"
fi

ci_job="$1"
shift
ci_export CI_JOB_NAME "$ci_job"

gate_job "$ci_job"

case "$ci_job" in
    e2e-tests)
        "$ROOT/.openshift-ci/e2e_tests.py"
        ;;
    scale-tests)
        "$ROOT/.openshift-ci/scale_tests.py"
        ;;
    slim-e2e-tests)
        "$ROOT/.openshift-ci/slim_e2e_tests.py"
        ;;
    style-checks)
        make style
        ;;
    unit-tests)
        make unit-tests
        ;;
    *)
        # For ease of initial integration this function does not fail when the
        # job is unknown.
        info "nothing to see here: ${ci_job}"
        exit 0
esac
