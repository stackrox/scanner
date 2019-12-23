FROM postgres:12.0-alpine

# Upgrade libxslt to fix CVE-2019-18197
RUN apk upgrade --no-cache libxslt && apk del apk-tools

COPY ./*.conf /etc/

COPY ./dump/definitions.sql.gz /docker-entrypoint-initdb.d/

ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password
