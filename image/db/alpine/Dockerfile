FROM postgres:12-alpine

RUN apk upgrade

COPY ./*.conf /etc/

COPY ./dump/definitions.sql.gz /docker-entrypoint-initdb.d/

ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password

USER 70:70
