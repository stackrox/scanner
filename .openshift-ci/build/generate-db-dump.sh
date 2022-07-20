#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"
source "$ROOT/scripts/ci/postgres.sh"

set -euo pipefail

ci_exit_trap() {
    local exit_code="$?"
    info "Executing a general purpose exit trap for CI"
    echo "Exit code is: ${exit_code}"

    (send_slack_notice_for_failures_on_merge "${exit_code}") || { echo "ERROR: Could not slack a test failure message"; }

    while [[ -e /tmp/hold ]]; do
        info "Holding this job for debug"
        sleep 60
    done
}

create_exit_trap() {
    trap ci_exit_trap EXIT
}

openshift_ci_mods
create_exit_trap

gate_job generate-db-dump

generate_db_dump() {
    touch /tmp/hold

    info "Generating DB dump"

#    start_postgres
#
#    "$ROOT/bin/updater" load-dump --postgres-host 127.0.0.1 --postgres-port 5432 --dump-file /tmp/genesis-dump/genesis-dump.zip
#
#    mkdir /tmp/postgres
#    pg_dump -U postgres postgres://127.0.0.1:5432 > /tmp/postgres/pg-definitions.sql
#    gzip --best /tmp/postgres/pg-definitions.sql
}

generate_db_dump "$*"
