#!/usr/bin/env bash

set -eu

echo "Creating postgres.conf for initialization..."
cat <<EOF > /tmp/postgres.conf
listen_addresses = '*'
EOF

echo "Starting database..."
POSTGRES_PASSWORD=postgres /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/tmp/postgres.conf

echo "Waiting for database to stop..."
pg_ctl -D /var/lib/postgresql/data/pgdata -w stop

rm /tmp/postgres.conf