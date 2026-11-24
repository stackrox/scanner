#!/bin/bash

set -euo pipefail

# If this is updated, be sure to update PG_MAJOR in the Dockerfile and the signature file.
postgres_major=15
pg_rhel_major=9

arch="$(uname -m)"
if [[ "$arch" == "arm64" ]]; then
  arch="aarch64"
fi
output_dir="/rpms"
mkdir $output_dir

if [[ "$arch" == "s390x" ]]; then
  # TODO(ROX-30647): Builds are failing due to UBI9:latest not containing the
  #  necessary version of openssl-libs to build postgresql-contrib.
  pg_build_version="0:16.8-1.module_el9+1209+bd6e4013.s390x"
  dnf module enable -y postgresql:16
  dnf install -y --downloadonly --downloaddir=/tmp "postgresql-${pg_build_version}" "postgresql-private-libs-${pg_build_version}" "postgresql-server-${pg_build_version}" "postgresql-contrib-${pg_build_version}"
  mv /tmp/postgresql-contrib-*.rpm "${output_dir}/postgres-contrib.rpm"
  mv /tmp/postgresql-server-*.rpm "${output_dir}/postgres-server.rpm"
  mv /tmp/postgresql-private-libs-*.rpm "${output_dir}/postgres-libs.rpm"
  mv /tmp/postgresql-*.rpm "${output_dir}/postgres.rpm"
else
  # Resolve RPM locations through PGDG metadata instead of constructing URLs from the
  # RHEL major version: PGDG minor-release repositories can contain package versions
  # absent from the major-release path. Dependencies are not needed here because the
  # runtime stage installs them before installing these RPMs.
  pgdg_repo_url="https://download.postgresql.org/pub/repos/yum/${postgres_major}/redhat/rhel-${pg_rhel_major}-${arch}/"

  for rpm_name in postgres postgres-server postgres-libs postgres-contrib; do
    if [[ "$rpm_name" == "postgres" ]]; then
      package="postgresql${postgres_major}"
    else
      package="postgresql${postgres_major}-${rpm_name#postgres-}"
    fi

    rpm_url="$(dnf -y download --destdir=. --disablerepo='*' "--repofrompath=pgdg,${pgdg_repo_url}" -y "${package}.${arch}" --url --quiet)"
    if [[ -z "$rpm_url" ]]; then
      echo "Unable to resolve a download URL for ${package}.${arch}" >&2
      exit 1
    fi
    echo "Downloading ${rpm_url}"
    curl --retry 3 -sS --fail -o "${output_dir}/${rpm_name}.rpm" "${rpm_url}"
  done
fi
