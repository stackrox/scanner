FROM postgres:12-alpine

COPY ./*.conf /etc/
COPY ./scripts/* /
COPY ./dump/definitions.sql.gz /docker-entrypoint-initdb.d/

ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password



ENTRYPOINT ["/docker-entrypoint.sh"]


#
## Create tmp directory with stackrox directory structure
#bundle_root="$(mktemp -d)"
#mkdir -p "${bundle_root}/"{"usr/local/bin","etc","docker-entrypoint-initdb.d"}
#chmod -R 755 "${bundle_root}"
#
## =============================================================================
## Get latest postgres minor version
#
#postgres_repo_url="https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
#postgres_major="12"
#pg_rhel_version="8.3"
#
#build_dir="$(mktemp -d)"
#docker build -q -t postgres-minor-image "${build_dir}" -f - <<EOF
#FROM registry.access.redhat.com/ubi8/ubi:${pg_rhel_version}
#RUN dnf install -y "${postgres_repo_url}"
#ENTRYPOINT dnf list -y postgresql${postgres_major}-server.x86_64 | tail -n 1 | awk '{print \$2}'
#EOF
#postgres_minor="$(docker run --rm postgres-minor-image).x86_64"
#rm -rf "${build_dir}"
#
## =============================================================================
#
## Add files to be included in the Dockerfile here. This includes artifacts that
## would be otherwise downloaded or included via a COPY command in the
## Dockerfile.
#
#cp -p "${INPUT_ROOT}/dump/definitions.sql.gz" "${bundle_root}/docker-entrypoint-initdb.d/"
#cp -p "${INPUT_ROOT}"/*.conf "${bundle_root}/etc/"
#
## Get postgres RPMs directly
#postgres_url="https://download.postgresql.org/pub/repos/yum/12/redhat/rhel-${pg_rhel_version}-x86_64"
#curl -s -o "${bundle_root}/postgres.rpm" \
#    "${postgres_url}/postgresql${postgres_major}-${postgres_minor}.rpm"
#curl -s -o "${bundle_root}/postgres-server.rpm" \
#    "${postgres_url}/postgresql${postgres_major}-server-${postgres_minor}.rpm"
#curl -s -o "${bundle_root}/postgres-libs.rpm" \
#    "${postgres_url}/postgresql${postgres_major}-libs-${postgres_minor}.rpm"


RUN groupadd -g 70 postgres && \
    adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh && \
    rpm --import RPM-GPG-KEY-PGDG-12 && \
    dnf upgrade -y && \
    dnf install -y \
        ca-certificates libicu systemd-sysv /tmp/postgres-libs.rpm \
        /tmp/postgres-server.rpm /tmp/postgres.rpm glibc-locale-source glibc-langpack-en && \
    rpm -e --nodeps curl && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    rm /tmp/postgres-libs.rpm /tmp/postgres-server.rpm /tmp/postgres.rpm && \
    rm RPM-GPG-KEY-PGDG-12 && \
    # (Optional) Remove line below to keep package management utilities
    rpm -e --nodeps rpm rpm-build-libs rpm-libs python3-rpm subscription-manager python3-subscription-manager-rhsm yum $(rpm -qa *hawkey*) $(rpm -qa *dnf*) && \
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

USER 70:70



ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.3

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle
COPY bundle.tar.gz /

WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

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
COPY --from=extracted_bundle /bundle/postgres.rpm /bundle/postgres-libs.rpm /bundle/postgres-server.rpm /tmp/
COPY --from=extracted_bundle /bundle/etc/postgresql.conf /bundle/etc/pg_hba.conf /etc/
COPY --from=extracted_bundle /bundle/docker-entrypoint-initdb.d/definitions.sql.gz /docker-entrypoint-initdb.d/

RUN groupadd -g 70 postgres && \
    adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh && \
    rpm --import RPM-GPG-KEY-PGDG-12 && \
    dnf upgrade -y && \
    dnf install -y \
        ca-certificates libicu systemd-sysv /tmp/postgres-libs.rpm \
        /tmp/postgres-server.rpm /tmp/postgres.rpm glibc-locale-source glibc-langpack-en && \
    rpm -e --nodeps curl && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    rm /tmp/postgres-libs.rpm /tmp/postgres-server.rpm /tmp/postgres.rpm && \
    rm RPM-GPG-KEY-PGDG-12 && \
    # (Optional) Remove line below to keep package management utilities
    rpm -e --nodeps rpm rpm-build-libs rpm-libs python3-rpm subscription-manager python3-subscription-manager-rhsm yum $(rpm -qa *hawkey*) $(rpm -qa *dnf*) && \ 
    localedef -f UTF-8 -i en_US en_US.UTF-8 && \
    chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres"]

HEALTHCHECK --interval=10s --timeout=5s CMD pg_isready -U postgres

USER 70:70
