ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
# Be sure to keep the pg_rhel_version in create-bundle.sh up-to-date.
ARG BASE_TAG=8.5

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle
COPY bundle.tar.gz /

WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS base

LABEL name="scanner-db" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner database for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

ENV PG_MAJOR=12
ENV PATH="$PATH:/usr/pgsql-$PG_MAJOR/bin/" \
    PGDATA="/var/lib/postgresql/data" \
    POSTGRES_PASSWORD_FILE="/run/secrets/stackrox.io/secrets/password"

COPY signatures/RPM-GPG-KEY-PGDG-12 /
COPY scripts/docker-entrypoint.sh /usr/local/bin/
COPY --from=extracted_bundle /bundle/postgres.rpm /bundle/postgres-libs.rpm /bundle/postgres-server.rpm /tmp/
COPY --from=extracted_bundle /bundle/etc/postgresql.conf /bundle/etc/pg_hba.conf /etc/

RUN RUN groupadd -g 70 postgres && \
    adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh && \
    rpm --import RPM-GPG-KEY-PGDG-12 && \
    dnf upgrade -y && \
    dnf install -y \
        ca-certificates libicu systemd-sysv /tmp/postgres-libs.rpm \
        /tmp/postgres-server.rpm /tmp/postgres.rpm glibc-locale-source glibc-langpack-en && \
    dnf clean all && \
    rm /tmp/postgres-libs.rpm /tmp/postgres-server.rpm /tmp/postgres.rpm && \
    rm RPM-GPG-KEY-PGDG-12 && \
    # (Optional) Remove line below to keep package management utilities
    rpm -e --nodeps $(rpm -qa curl '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*') && \
    rm -rf /var/cache/dnf && \
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres"]

FROM base AS scanner-db-slim

ENV ROX_SLIM_MODE="true"

USER 70:70

FROM base AS scanner-db

ENV ROX_SLIM_MODE="false"

COPY --from=extracted_bundle /bundle/docker-entrypoint-initdb.d/definitions.sql.gz /docker-entrypoint-initdb.d/

USER 70:70
