#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"
source "$ROOT/scripts/ci/postgres.sh"

set -euo pipefail

generate_db_dump() {
    info "Generating DB dump"

    start_postgres

    "$ROOT/bin/updater" load-dump --postgres-host 127.0.0.1 --postgres-port 5432 --dump-file /tmp/genesis-dump/dump.zip

    mkdir /tmp/postgres
    pg_dump -U postgres postgres://127.0.0.1:5432 > /tmp/postgres/pg-definitions.sql
    gzip --best /tmp/postgres/pg-definitions.sql

    store_artifacts /tmp/postgres postgres
}

generate_db_dump "$*"
