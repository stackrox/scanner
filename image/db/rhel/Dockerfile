ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.2

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

LABEL name="scanner-db-rhel" \
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
COPY bundle.tar.gz /

RUN groupadd -g 70 postgres && \
    adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh && \
    tar -zxf /bundle.tar.gz ./postgres.rpm && \
    tar -zxf /bundle.tar.gz ./postgres-libs.rpm && \
    tar -zxf /bundle.tar.gz ./postgres-server.rpm && \
    tar -zxf /bundle.tar.gz ./etc/postgresql.conf && \
    tar -zxf /bundle.tar.gz ./etc/pg_hba.conf && \
    tar -zxf /bundle.tar.gz ./docker-entrypoint-initdb.d/definitions.sql.gz && \
    rm -f /bundle.tar.gz && \
    rpm --import RPM-GPG-KEY-PGDG-12 && \
    dnf upgrade -y && \
    dnf install -y \
        ca-certificates libicu systemd-sysv postgres-libs.rpm \
        postgres-server.rpm postgres.rpm glibc-locale-source glibc-langpack-en && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    rpm -e --nodeps curl && \
    # (Optional) Remove line below to keep package managment utilities
    rpm -e --nodeps rpm rpm-build-libs rpm-libs python3-rpm yum $(rpm -qa *dnf*) && \
    rm postgres-libs.rpm postgres-server.rpm postgres.rpm && \
    rm RPM-GPG-KEY-PGDG-12 && \
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres"]

HEALTHCHECK --interval=10s --timeout=5s CMD pg_isready -U postgres

USER 70:70
