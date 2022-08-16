#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

openshift_ci_mods

gate_job generate-db-dump

generate_db_dump() {
    info "Generating DB dump"

    groupadd -g 1001 pg
    adduser pg -u 1001 -g 1001 -d /var/lib/postgresql -s /bin/sh

    runuser -l pg -c "PATH=$PATH:/usr/pgsql-$PG_MAJOR/bin/ $ROOT/scripts/ci/postgres.sh start_postgres"

    "$ROOT/bin/updater" load-dump --postgres-host 127.0.0.1 --postgres-port 5432 --dump-file /tmp/genesis-dump/genesis-dump.zip

    mkdir /tmp/postgres
    pg_dump -U postgres postgres://127.0.0.1:5432 > /tmp/postgres/pg-definitions.sql
    ls -lrt /tmp/postgres
    gzip --best /tmp/postgres/pg-definitions.sql
    ls -lrt /tmp/postgres
}

generate_db_dump "$*"
