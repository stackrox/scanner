#!/bin/sh

exec /usr/local/bin/docker-entrypoint.sh postgres -c config_file=/etc/postgresql.conf
