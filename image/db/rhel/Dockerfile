ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.1

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

ENV PG_MAJOR 12
ENV PATH $PATH:/usr/pgsql-$PG_MAJOR/bin/
ENV PGDATA /var/lib/postgresql/data
ENV POSTGRES_PASSWORD_FILE=/run/secrets/stackrox.io/secrets/password

RUN groupadd -g 70 postgres
RUN adduser postgres -u 70 -g 70 -d /var/lib/postgresql -s /bin/sh

ADD bundle.tar.gz /

RUN yum update -y --nogpgcheck --disableplugin=subscription-manager && \
  yum install -y --nogpgcheck --disableplugin=subscription-manager \
    ca-certificates \
    libicu \
    systemd-sysv \
    postgres-libs.rpm \
    postgres-server.rpm \
    postgres.rpm \
    glibc-langpack-en && \
  rm postgres-libs.rpm postgres-server.rpm postgres.rpm \
  ;

RUN rpm -e --nodeps \
  rpm \
  rpm-build-libs \
  rpm-libs \
  python3-rpm \
  subscription-manager \
  python3-subscription-manager-rhsm \
  yum \
  $(rpm -qa *hawkey*) \
  $(rpm -qa *dnf*) \
  ;

RUN localedef -f UTF-8 -i en_US en_US.UTF-8

RUN chown postgres:postgres /usr/local/bin/docker-entrypoint.sh && \
  chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5432
CMD ["postgres"]

HEALTHCHECK --interval=10s --timeout=5s CMD pg_isready -U postgres

USER 70:70
