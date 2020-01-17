# Modified for RHEL from https://github.com/docker-library/postgres/tree/master/12

ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi7/ubi
ARG BASE_TAG=7.7

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

ENV PG_MAJOR 12
ENV PATH $PATH:/usr/pgsql-$PG_MAJOR/bin/
ENV PGDATA /var/lib/postgresql/data
ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password

RUN groupadd -g 70 postgres
RUN adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh

# Install postgres packages from https://yum.postgresql.org/
RUN yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-7-x86_64/pgdg-redhat-repo-latest.noarch.rpm && \
    yum update -y --disableplugin=subscription-manager && \
    yum install -y \
      ca-certificates \
      "postgresql${PG_MAJOR}" \
      "postgresql${PG_MAJOR}-server"

# Remove package manager
RUN rpm -e --nodeps curl rpm rpm-libs rpm-build-libs rpm-python subscription-manager subscription-manager-rhsm yum yum-utils yum-plugin-ovl

RUN localedef -f UTF-8 -i en_US en_US.UTF-8

RUN mkdir /docker-entrypoint-initdb.d
COPY ./rhel/docker-entrypoint.sh /usr/local/bin/
RUN chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && chmod +x /usr/local/bin/docker-entrypoint.sh

COPY ./*.conf /etc/
COPY ./dump/definitions.sql.gz /docker-entrypoint-initdb.d/

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres"]

HEALTHCHECK --interval=10s --timeout=5s CMD pg_isready -U postgres

USER 70:70
