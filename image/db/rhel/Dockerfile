ARG RPMS_REGISTRY=registry.access.redhat.com
ARG RPMS_BASE_IMAGE=ubi9
ARG RPMS_BASE_TAG=latest

ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi9-minimal
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
        zstd \
        && \
    if [[ $(awk -F'=' '/VERSION_ID/{ gsub(/"/,""); print substr($2,1,1)}' /etc/os-release) -gt 8 ]]; then \
        microdnf install -y uuid; \
    fi && \
    rpm -i /tmp/postgres-libs.rpm /tmp/postgres-server.rpm /tmp/postgres.rpm /tmp/postgres-contrib.rpm && \
    # The removal of /usr/share/zoneinfo from UBI minimal images is intentional.
    # After building the image, the image is reduced in size as much as possible,
    # and the /usr/share/zoneinfo directory is purged as it saves space
    # in the final distribution of the image.
    # https://access.redhat.com/solutions/5616681
    microdnf reinstall -y tzdata && \
    microdnf clean all && \
    # (Optional) Remove line below to keep package management utilities
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
