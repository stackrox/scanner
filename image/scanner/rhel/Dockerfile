ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.5

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle

COPY bundle.tar.gz /
WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS base

LABEL name="scanner" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

COPY scripts /

COPY ./THIRD_PARTY_NOTICES/ /THIRD_PARTY_NOTICES/

RUN dnf upgrade -y && \
    dnf install -y ca-certificates xz && \
    dnf clean all && \
    # (Optional) Remove line below to keep package management utilities
    # We don't uninstall rpm because scanner uses it to get packages installed in scanned images.
    rpm -e --nodeps $(rpm -qa curl '*dnf*' '*libsolv*' '*hawkey*' 'yum*') && \
    rm -rf /var/cache/dnf && \
    chown -R 65534:65534 /tmp && \
    # The contents of paths mounted as emptyDir volumes in Kubernetes are saved
    # by the script `save-dir-contents` during the image build. The directory
    # contents are then restored by the script `restore-all-dir-contents`
    # during the container start.
    chown -R 65534:65534 /etc/pki /etc/ssl && /save-dir-contents /etc/pki/ca-trust /etc/ssl

ENTRYPOINT ["/entrypoint.sh"]

FROM base AS scanner

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
ENV K8S_DEFINITIONS_DIR="/k8s_definitions"
ENV REPO_TO_CPE_DIR="/repo2cpe"

COPY --from=extracted_bundle /bundle/genesis_manifests.json /bundle/scanner ./
COPY --from=extracted_bundle "/bundle${NVD_DEFINITIONS_DIR}/" ".${NVD_DEFINITIONS_DIR}/"
COPY --from=extracted_bundle "/bundle${K8S_DEFINITIONS_DIR}/" ".${K8S_DEFINITIONS_DIR}/"
COPY --from=extracted_bundle "/bundle${REPO_TO_CPE_DIR}/" ".${REPO_TO_CPE_DIR}/"

RUN chown -R 65534:65534 "${NVD_DEFINITIONS_DIR}" && \
    chown -R 65534:65534 "${K8S_DEFINITIONS_DIR}" && \
    chown -R 65534:65534 "${REPO_TO_CPE_DIR}" && \
    chmod +rx /scanner

USER 65534:65534

FROM base AS scanner-slim

ENV ROX_LITE_MODE="true"

COPY --from=extracted_bundle /bundle/scanner ./

RUN chmod +rx /scanner

USER 65534:65534
