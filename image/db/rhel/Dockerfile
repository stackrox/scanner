FROM registry.redhat.io/rhel8/postgresql-12:latest

COPY ./*.conf /etc/
COPY ./rhel/scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY ./dump/definitions.sql.gz /docker-entrypoint-initdb.d/

ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password PGDATA=/var/lib/postgresql/data

USER root

RUN usermod -u 70 postgres && groupmod -g 70 postgres
RUN mkdir -p "$PGDATA" && chown -R postgres:postgres /var/lib/postgresql /run/postgresql && chmod -R 777 /var/lib/postgresql

USER postgres

ENTRYPOINT ["/docker-entrypoint.sh"]
