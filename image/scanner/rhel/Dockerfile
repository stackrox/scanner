ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi7/ubi
ARG BASE_TAG=7.7

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

# Scanner requires the following binaries.
RUN yum update -y --disableplugin=subscription-manager && \
    yum -y install ca-certificates xz

COPY ./bin/scanner /

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
RUN mkdir -p "${NVD_DEFINITIONS_DIR}" && chown -R 4000:4000 "${NVD_DEFINITIONS_DIR}"
COPY ./dump/nvd/*.json "${NVD_DEFINITIONS_DIR}/"

COPY ./dump/genesis_manifests.json /


ENTRYPOINT ["/scanner"]

# Remove package manager
RUN rpm -e subscription-manager yum yum-utils yum-plugin-ovl

RUN chown -R 4000:4000 /tmp

USER 4000:4000


