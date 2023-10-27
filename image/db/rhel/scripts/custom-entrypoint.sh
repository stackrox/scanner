#!/usr/bin/env bash

# The postgres server has been started once during the build process in the Dockerfile.
# Now we need to start it again, but this time with the correct password.
# So we need to issue a command to change the password.

set -e

if [ ! -d "/var/lib/postgresql/data/pgdata" ]; then

  #  ARCHIVAL METHOD
  #  echo "Creating /var/lib/postgresql/data/pgdata..."
  #  mkdir -p /var/lib/postgresql/data/pgdata
  #
  #  echo "Moving archive to target directory..."
  #  mv /tmp/data.tar.gz /var/lib/postgresql/data/pgdata/data.tar.gz
  #
  #  echo "Uncompressing into /var/lib/pgsql/data/pgdata..."
  #  tar -xzf /var/lib/postgresql/data/pgdata/data.tar.gz -C /var/lib/postgresql/data/pgdata
  #
  #  echo "Removing archive..."
  #  rm /var/lib/postgresql/data/pgdata/data.tar.gz
  # END ARCHIVAL METHOD

  # SYMLINK METHOD
  echo "Creating /var/lib/postgresql/data/pgdata..."
  mkdir -p /var/lib/postgresql/data
  echo "Create a symbolic link from /var/lib/postgresql/data/pgdata to /tmp/data"
  ln -s /tmp/data /var/lib/postgresql/data/pgdata
  # END SYMLINK METHOD

  echo "Starting database..."
  POSTGRES_PASSWORD_FILE="" POSTGRES_PASSWORD=postgres /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/etc/postgresql.conf &

  echo "Waiting for database to be ready..."
  while ! pg_isready -U postgres -h localhost -p 5432; do
    sleep 1
  done

  if [ -n "$POSTGRES_PASSWORD" ]; then
    echo "Changing password via POSTGRES_PASSWORD environment variable..."
    PGPASSWORD=postgres psql -c "ALTER USER postgres WITH PASSWORD '$POSTGRES_PASSWORD';"
  elif [ -n "$POSTGRES_PASSWORD_FILE" ]; then
    echo "Changing password via POSTGRES_PASSWORD_FILE environment variable..."
    PGPASSWORD=postgres psql -c "ALTER USER postgres WITH PASSWORD '$(cat "$POSTGRES_PASSWORD_FILE")';"
  else
    echo "No password set. Skipping password change..."
  fi

  echo "Renaming postgres user if necessary..."
  if [ -n "$POSTGRES_USER" ]; then
    if [ "$POSTGRES_USER" != "postgres" ]; then
      if [ -n "$POSTGRES_PASSWORD" ]; then
        PGPASSWORD="$POSTGRES_PASSWORD" psql -c "ALTER USER postgres RENAME TO $POSTGRES_USER;"
      elif [ -n "$POSTGRES_PASSWORD_FILE" ]; then
        PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -c "ALTER USER postgres RENAME TO $POSTGRES_USER;"
      fi
    fi
  fi

  echo "Stopping database..."
  pg_ctl -w stop

else
  echo "Database already initialized. Skipping initialization..."
fi

if [ "${ROX_SCANNER_DB_INIT}" == "true" ]; then
  echo "ROX_SCANNER_DB_INIT is set to true. Exiting..."
  exit 0
else
  echo "Database initialized."
fi

# Now we can start the database for real. But we will
# forward any arguments to the actual entrypoint script
echo "Starting database for real..."
exec /usr/local/bin/docker-entrypoint.sh "$@"
