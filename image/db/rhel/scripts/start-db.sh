#!/usr/bin/env bash

set -eu

echo "Creating postgres.conf for initialization..."
cat <<EOF > /tmp/postgres.conf
listen_addresses = '*'
EOF

echo "Starting database..."
POSTGRES_PASSWORD=postgres /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/tmp/postgres.conf

echo "Waiting for database to stop..."
while [ -f /var/lib/postgresql/data/pgdata/postmaster.pid ]; do
  sleep 1
done

rm /tmp/postgres.conf