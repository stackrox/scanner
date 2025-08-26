ARG RPMS_REGISTRY=registry.access.redhat.com
ARG RPMS_BASE_IMAGE=ubi8
ARG RPMS_BASE_TAG=latest

ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8-minimal
ARG BASE_TAG=latest

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle
COPY bundle.tar.gz /

WORKDIR /bundle
RUN microdnf install -y tar gzip && tar -zxf /bundle.tar.gz

FROM ${RPMS_REGISTRY}/${RPMS_BASE_IMAGE}:${RPMS_BASE_TAG} AS postgres_rpms

COPY scripts/download.sh /download.sh
RUN /download.sh

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS base

ARG LABEL_VERSION
ARG LABEL_RELEASE
ARG QUAY_TAG_EXPIRATION

LABEL name="scanner-db" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner database for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform." \
      version="${LABEL_VERSION}" \
      release="${LABEL_RELEASE}" \
      quay.expires-after="${QUAY_TAG_EXPIRATION}"

ENV PG_MAJOR=15
ENV PATH="$PATH:/usr/pgsql-$PG_MAJOR/bin/" \
    PGDATA="/var/lib/postgresql/data/pgdata"

COPY signatures/PGDG-RPM-GPG-KEY-RHEL /
COPY scripts/docker-entrypoint.sh /usr/local/bin/
COPY --from=extracted_bundle /bundle/etc/postgresql.conf /bundle/etc/pg_hba.conf /etc/
COPY --from=postgres_rpms /rpms/postgres.rpm /rpms/postgres-libs.rpm /rpms/postgres-server.rpm /rpms/postgres-contrib.rpm /tmp/

RUN microdnf upgrade -y --nobest && \
    microdnf install -y shadow-utils && \
    groupadd -g 70 postgres && \
    adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh && \
    rpm --import PGDG-RPM-GPG-KEY-RHEL && \
    microdnf install -y \
        ca-certificates \
        glibc-langpack-en \
        glibc-locale-source \
        libicu \
        libxslt \
        lz4 \
        perl-libs \
        python3 \
        systemd-sysv \
        zstd && \
    if [[ $(awk -F'=' '/VERSION_ID/{ gsub(/"/,""); print substr($2,1,1)}' /etc/os-release) -gt 8 ]]; then \
        microdnf install -y uuid; \
    fi && \
    # ---- tiny prechecks: verify /tmp RPMs match OS + don’t require OPENSSL_3.4 ----
    RHEL_MAJOR="$(. /etc/os-release; echo ${VERSION_ID%%.*})" && \
    ARCH="$(arch)" && \
    for p in /tmp/postgres-libs.rpm /tmp/postgres.rpm /tmp/postgres-server.rpm /tmp/postgres-contrib.rpm; do \
      test -e "$p" || { echo "ERROR: Missing $p"; exit 1; }; \
      if ! rpm -qp --qf '%{RELEASE}\n' "$p" | grep -Eq '(\.el'"${RHEL_MAJOR}"'|rhel'"${RHEL_MAJOR}"')'; then \
        echo "ERROR: $p is not an EL${RHEL_MAJOR} build."; exit 1; \
      fi; \
      # must NOT require OPENSSL_3.4 on EL8/EL9
      if [ "${RHEL_MAJOR}" -lt 10 ] && rpm -qpR "$p" | grep -q 'OPENSSL_3\.4'; then \
        echo "ERROR: $p requires OPENSSL_3.4, incompatible with EL${RHEL_MAJOR} (OpenSSL 3.0)."; exit 1; \
      fi; \
    done && \
    # ------------------------------------------------------------------------------- \
    rpm -i /tmp/postgres-libs.rpm /tmp/postgres-server.rpm /tmp/postgres.rpm /tmp/postgres-contrib.rpm && \
    microdnf reinstall -y tzdata && \
    microdnf clean all && \
    rpm -e --nodeps $(rpm -qa shadow-utils curl '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*') && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/postgres-libs.rpm /tmp/postgres-server.rpm /tmp/postgres.rpm /tmp/postgres-contrib.rpm && \
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    mkdir /docker-entrypoint-initdb.d


# This is equivalent to postgres:postgres.
USER 70:70

COPY --from=extracted_bundle /bundle/docker-entrypoint-initdb.d/definitions.sql.gz /docker-entrypoint-initdb.d/

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres", "-c", "config_file=/etc/postgresql.conf"]
