#!/usr/bin/env bash

set -euo pipefail

# Check StackRox service logs.
# Adapted from https://github.com/stackrox/stackrox/blob/master/tests/e2e/lib.sh

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
# shellcheck source=../../lib.sh
source "$SCRIPTS_ROOT/lib.sh"

check_stackrox_logs() {
    if [[ "$#" -ne 1 ]]; then
        die "missing args. usage: check_stackrox_logs <dir>"
    fi

    local dir="$1"

    if [[ ! -d "$dir/stackrox" ]]; then
        die "StackRox logs were not collected. (Use ./scripts/ci/collect-service-logs.sh stackrox)"
    fi

    check_for_stackrox_restarts "$dir"
    check_for_errors_in_stackrox_logs "$dir"
}

check_for_stackrox_restarts() {
    if [[ "$#" -ne 1 ]]; then
        die "missing args. usage: check_for_stackrox_restarts <dir>"
    fi

    local dir="$1"

    if [[ ! -d "$dir/stackrox" ]]; then
        die "StackRox logs were not collected. (Use ./scripts/ci/collect-service-logs.sh stackrox)"
    fi

    local previous_logs
    previous_logs=$(ls "$dir"/stackrox/*-previous.log || true)
    if [[ -n "$previous_logs" ]]; then
        echo >&2 "Previous logs found"
        # shellcheck disable=SC2086
        if ! "$SCRIPTS_ROOT/ci/logcheck/check-restart-logs.sh" "${CI_JOB_NAME}" $previous_logs; then
            exit 1
        fi
    fi
}

check_for_errors_in_stackrox_logs() {
    if [[ "$#" -ne 1 ]]; then
        die "missing args. usage: check_for_errors_in_stackrox_logs <dir>"
    fi

    local dir="$1"

    if [[ ! -d "$dir/stackrox" ]]; then
        die "StackRox logs were not collected. (Use ./scripts/ci/collect-service-logs.sh stackrox)"
    fi

    local logs
    logs=$(ls "$dir"/stackrox/*.log)
    local filtered
    # shellcheck disable=SC2010,SC2086
    filtered=$(ls $logs | grep -v "previous.log" || true)
    if [[ -n "$filtered" ]]; then
        # shellcheck disable=SC2086
        if ! "$SCRIPTS_ROOT/ci/logcheck/check.sh" $filtered; then
            die "Found at least one suspicious log file entry."
        fi
    fi
}

collect_and_check_stackrox_logs() {
    if [[ "$#" -ne 2 ]]; then
        die "missing args. usage: collect_and_check_stackrox_logs <output-dir> <test_stage>"
    fi

    local dir="$1/$2"

    info "Will collect stackrox logs to $dir and check them"

    "$SCRIPTS_ROOT/ci/collect-service-logs.sh" stackrox "$dir"

    check_stackrox_logs "$dir"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        usage
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
