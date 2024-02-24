FROM registry.redhat.io/rhel8/postgresql-15:latest AS scanner-db-common

LABEL \
    com.redhat.license_terms="https://www.redhat.com/agreements" \
    description="Scanner Database Image for Red Hat Advanced Cluster Security for Kubernetes" \
    io.k8s.description="Scanner Database Image for Red Hat Advanced Cluster Security for Kubernetes" \
    io.openshift.tags="rhacs,scanner-db,stackrox" \
    maintainer="Red Hat, Inc." \
    source-location="https://github.com/stackrox/scanner" \
    summary="Scanner DB for RHACS" \
    url="https://catalog.redhat.com/software/container-stacks/detail/60eefc88ee05ae7c5b8f041c" \
    # We must set version label to prevent inheriting value set in the base stage.
    # TODO(ROX-20236): configure injection of dynamic version value when it becomes possible.
    version="0.0.1-todo"

USER root

COPY image/db/pg_hba.conf \
     image/db/postgresql.conf \
     /etc/

COPY --chown=postgres:postgres \
     image/db/rhel/scripts/docker-entrypoint.sh \
     /usr/local/bin/

RUN dnf upgrade -y --nobest && \
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    mkdir -p /var/lib/postgresql && \
    groupmod -g 70 postgres && \
    usermod -u 70 postgres -d /var/lib/postgresql && \
    chown -R postgres:postgres /var/lib/postgresql && \
    chown -R postgres:postgres /var/run/postgresql && \
    dnf clean all && \
    rpm --verbose -e --nodeps $(rpm -qa curl '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*') && \
    rm -rf /var/cache/dnf /var/cache/yum && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PG_MAJOR=15 \
    PGDATA="/var/lib/postgresql/data/pgdata"

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres", "-c", "config_file=/etc/postgresql.conf"]

USER 70:70

FROM scanner-db-common AS scanner-db-slim

LABEL \
    com.redhat.component="rhacs-scanner-db-slim-container" \
    io.k8s.display-name="scanner-db-slim" \
    name="rhacs-scanner-db-slim-rhel8"

ENV ROX_SLIM_MODE="true"

FROM scanner-db-common AS scanner-db

LABEL \
    com.redhat.component="rhacs-scanner-db-container" \
    io.k8s.display-name="scanner-db" \
    name="rhacs-scanner-db-rhel8"

COPY --chown=0:0 blob-pg-definitions.sql.gz \
     /docker-entrypoint-initdb.d/definitions.sql.gz
