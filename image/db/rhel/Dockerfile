ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.6

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle
COPY bundle.tar.gz /

WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

FROM ${BASE_REGISTRY}/${BASE_IMAGE}-minimal:${BASE_TAG} AS base

LABEL name="scanner-db" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner database for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

ENV PG_MAJOR=12
ENV PATH="$PATH:/usr/pgsql-$PG_MAJOR/bin/" \
    PGDATA="/var/lib/postgresql/data/pgdata"

COPY scripts/docker-entrypoint.sh /usr/local/bin/
COPY --from=extracted_bundle /bundle/etc/postgresql.conf /bundle/etc/pg_hba.conf /etc/

ARG POSTGRESQL_ARCH=x86_64

RUN microdnf install -y shadow-utils && \
    groupadd -g 70 postgres && \
    adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh && \
    curl https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-${POSTGRESQL_ARCH}/pgdg-redhat-repo-latest.noarch.rpm -o /tmp/pg_repo.rpm && \
    rpm -i /tmp/pg_repo.rpm && \
    microdnf upgrade -y && \
    microdnf install -y \
        ca-certificates libicu systemd-sysv glibc-locale-source glibc-langpack-en \
        postgresql12-server && \
    microdnf clean all && \
    rpm -e --nodeps $(rpm -qa 'pgdg-redhat-repo*') && \
    # (Optional) Remove line below to keep package management utilities
    rpm -e --nodeps $(rpm -qa shadow-utils curl '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*') && \
    rm -rf /var/cache/dnf /var/cache/yum  /tmp/pg_repo.rpm && \
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    mkdir /docker-entrypoint-initdb.d

# This is equivalent to postgres:postgres.
USER 70:70

COPY --from=extracted_bundle /bundle/docker-entrypoint-initdb.d/definitions.sql.gz /docker-entrypoint-initdb.d/

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres", "-c", "config_file=/etc/postgresql.conf"]
