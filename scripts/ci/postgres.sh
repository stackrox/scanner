#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-postgres-tests.sh

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
# shellcheck source=../../scripts/lib.sh
source "$SCRIPTS_ROOT/scripts/lib.sh"

set -euo pipefail

_start_postgres() {
    initdb "${HOME}/data"
    pg_ctl -D "${HOME}/data" -l logfile -o "-k /tmp" start
    export PGHOST=/tmp
    createuser -s postgres
}

start_postgres() {
    info "Starting Postgres"

    if [[ $(id -u) == 0 ]]; then
        info "This function should not be run as root."
        if is_CI; then
            info "Running in CI. Creating a non-root user."
            groupadd -g 1001 pg
            adduser pg -u 1001 -g 1001 -d /var/lib/postgresql -s /bin/sh

            # The PATH is not completely preserved, so set the PATH here to ensure postgres-related commands can be found.
            runuser -l pg -c "PATH=$PATH $SCRIPTS_ROOT/scripts/ci/postgres.sh _start_postgres" # TODO(DO NOT MERGE): this is a mess
        else
            die "Please re-run as a non-root user."
        fi
    else
      _start_postgres
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
