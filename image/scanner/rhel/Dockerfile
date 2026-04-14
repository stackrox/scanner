ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi9-minimal
ARG BASE_TAG=latest

FROM ${BASE_REGISTRY}/ubi9-micro:${BASE_TAG} AS ubi-micro-base

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle

COPY bundle.tar.gz /
WORKDIR /bundle
RUN microdnf install -y tar gzip && tar -zxf /bundle.tar.gz

FROM ${BASE_REGISTRY}/ubi9:${BASE_TAG} AS package_installer

COPY --from=ubi-micro-base / /out/

RUN dnf install -y \
    --installroot=/out/ \
    --releasever=9 \
    --setopt=install_weak_deps=0 \
    --nodocs \
    bash \
    coreutils \
    findutils \
    util-linux \
    ca-certificates \
    xz \
    gzip \
    less \
    tar && \
    dnf clean all --installroot=/out/ && \
    rm -rf /out/var/cache/dnf /out/var/cache/yum

FROM ubi-micro-base AS base

ARG LABEL_VERSION
ARG LABEL_RELEASE
ARG QUAY_TAG_EXPIRATION

LABEL name="scanner" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform." \
      version="${LABEL_VERSION}" \
      release="${LABEL_RELEASE}" \
      quay.expires-after="${QUAY_TAG_EXPIRATION}"

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

COPY --from=package_installer /out/ /

COPY scripts /

COPY --from=extracted_bundle /bundle/scanner ./

COPY --from=extracted_bundle /bundle/THIRD_PARTY_NOTICES/ /THIRD_PARTY_NOTICES/

RUN chown -R 65534:65534 /tmp && \
    # The contents of paths mounted as emptyDir volumes in Kubernetes are saved
    # by the script `save-dir-contents` during the image build. The directory
    # contents are then restored by the script `restore-all-dir-contents`
    # during the container start.
    chown -R 65534:65534 /etc/pki/ca-trust && /save-dir-contents /etc/pki/ca-trust/source && \
    chmod +rx /scanner

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
ENV K8S_DEFINITIONS_DIR="/k8s_definitions"
ENV ISTIO_DEFINITIONS_DIR="/istio_definitions"
ENV REPO_TO_CPE_DIR="/repo2cpe"

COPY --chown=65534:65534 --from=extracted_bundle "/bundle${NVD_DEFINITIONS_DIR}/" ".${NVD_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 --from=extracted_bundle "/bundle${K8S_DEFINITIONS_DIR}/" ".${K8S_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 --from=extracted_bundle "/bundle${ISTIO_DEFINITIONS_DIR}/" ".${ISTIO_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 --from=extracted_bundle "/bundle${REPO_TO_CPE_DIR}/" ".${REPO_TO_CPE_DIR}/"
COPY --chown=65534:65534 --from=extracted_bundle /bundle/genesis_manifests.json ./

# This is equivalent to nobody:nobody.
USER 65534:65534

ENTRYPOINT ["/entrypoint.sh"]
