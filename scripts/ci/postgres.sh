#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-postgres-tests.sh

set -euo pipefail

start_postgres() {
    info "Starting Postgres"

    initdb "${HOME}/data"
    pg_ctl -D "${HOME}/data" -l logfile -o "-k /tmp" start
    export PGHOST=/tmp
    createuser -s postgres
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
