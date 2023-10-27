#!/usr/bin/env bash

# The postgres server has been started once during the build process in the Dockerfile.
# Now we need to start it again, but this time with the correct password.
# So we need to issue a command to change the password.

set -e

echo "Creating /var/lib/postgresql/data/pgdata..."
mkdir -p /var/lib/postgresql/data/pgdata

echo "Uncompressing into /var/lib/pgsql/data/pgdata..."
tar -xzf /tmp/data.tar.gz -C /var/lib/postgresql/data/pgdata

echo "Starting database..."
POSTGRES_PASSWORD=postgres /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/etc/postgresql.conf &

echo "Waiting for database to be ready..."
while ! pg_isready -U postgres -h localhost -p 5432; do
  sleep 1
done

echo "Changing password..."
if [ "$POSTGRES_PASSWORD" != "postgres" ]; then
  PGPASSWORD=postgres psql -c "ALTER USER postgres WITH PASSWORD '$POSTGRES_PASSWORD';"
fi

echo "Renaming postgres user if necessary..."
if [ "$POSTGRES_USER" != "postgres" ]; then
  PGPASSWORD="$POSTGRES_PASSWORD" psql -c "ALTER USER postgres RENAME TO $POSTGRES_USER;"
fi

echo "Stopping database..."
pg_ctl -w stop

# Now we can start the database for real. But we will
# forward any arguments to the actual entrypoint script
echo "Starting database for real..."

exec /usr/local/bin/docker-entrypoint.sh "$@"