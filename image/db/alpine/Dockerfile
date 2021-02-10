FROM postgres:11.6-alpine

# Upgrade libxslt to fix CVE-2019-18197 and musl for CVE-2020-28928
RUN apk upgrade --no-cache libxslt \
        && apk add --no-cache --upgrade musl \
        && apk del apk-tools

COPY ./*.conf /etc/

COPY ./dump/definitions.sql.gz /docker-entrypoint-initdb.d/

ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password

USER 70:70
