#!/usr/bin/env bash

# The entrypoint for CI defined in https://github.com/openshift/release/tree/master/ci-operator/config/stackrox/scanner
# Imports secrets to env vars, gates the job based on context, changed files and PR labels and ultimately
# hands off to the test/build script in *scripts/ci/jobs*.
#
# Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/dispatch.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

if [[ "$#" -lt 1 ]]; then
    die "usage: dispatch <ci-job> [<...other parameters...>]"
fi

ci_job="$1"
shift
ci_export CI_JOB_NAME "$ci_job"

case "$ci_job" in
    db-integration-tests)
        ;;
    *)
        openshift_ci_mods
        openshift_ci_import_creds
        ;;
esac

create_exit_trap

gate_job "$ci_job"

case "$ci_job" in
    e2e-tests)
        openshift_ci_e2e_mods
        ;;
esac

export PYTHONPATH="${PYTHONPATH:-}:.openshift-ci"

if ! [[ "$ci_job" =~ [a-z-]+ ]]; then
    # don't exec possibly untrusted scripts
    die "untrusted job: $ci_job"
fi

if [[ -f "$ROOT/scripts/ci/jobs/${ci_job}.sh" ]]; then
    job_script="$ROOT/scripts/ci/jobs/${ci_job}.sh"
elif [[ -f "$ROOT/scripts/ci/jobs/${ci_job//-/_}.py" ]]; then
    job_script="$ROOT/scripts/ci/jobs/${ci_job//-/_}.py"
else
    # For ease of initial integration this function does not fail when the
    # job is unknown.
    info "nothing to see here: ${ci_job}"
    exit 0
fi

"${job_script}" "$@" &
job_pid="$!"

forward_sigint() {
    echo "Dispatch is forwarding SIGINT to job"
    kill -SIGINT "${job_pid}"
}
trap forward_sigint SIGINT

wait "${job_pid}"
