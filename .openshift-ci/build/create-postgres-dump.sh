#!/usr/bin/env bash

# Execute all steps required to create the postgres dump, given a genesis dump.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

openshift_ci_mods

gate_job create-postgres-dump

# create_postgres_dump creates the PG dump based on the given genesis dump from the base image.
create_postgres_dump() {
    info "Loading genesis dump into PG"
    "$ROOT/bin/updater" load-dump --postgres-host 127.0.0.1 --postgres-port 5432 --dump-file /tmp/genesis-dump/dump.zip

    info "Creating PG dump"
    mkdir -p /tmp/postgres
    pg_dump -U postgres postgres://127.0.0.1:5432 > /tmp/postgres/pg-definitions.sql
    gzip --best /tmp/postgres/pg-definitions.sql
}

create_postgres_dump
