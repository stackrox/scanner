#!/usr/bin/env bash

set -eu

echo "Creating postgres.conf for initialization..."
cat <<EOF > /tmp/postgres.conf
listen_addresses = '*'
max_wal_size = 1GB
EOF

echo "Creating temporary PGDATA directory..."
mkdir -p /tmp/data

echo "Starting database..."
PGDATA=/tmp/data POSTGRES_PASSWORD=postgres /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/tmp/postgres.conf

echo "Waiting for database to stop..."
while [ -f /tmp/data/pgdata/postmaster.pid ]; do
  sleep 1
done

rm /tmp/postgres.conf

echo "Compressing database data folder..."
tar -czf /tmp/data.tar.gz -C /tmp/data .

echo "Removing temporary PGDATA directory..."
rm -rf /tmp/data
