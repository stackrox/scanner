ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.4

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

LABEL name="scanner" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
RUN mkdir -p "${NVD_DEFINITIONS_DIR}"
COPY ./dump/nvd/*.json "${NVD_DEFINITIONS_DIR}/"

ENV K8S_DEFINITIONS_DIR="/k8s_definitions"
RUN mkdir -p "${K8S_DEFINITIONS_DIR}"
COPY ./dump/k8s/*.yaml "${K8S_DEFINITIONS_DIR}/"

ENV REPO_TO_CPE_DIR="/repo2cpe"
RUN mkdir -p "${REPO_TO_CPE_DIR}"
COPY ./dump/rhelv2/repository-to-cpe.json "${REPO_TO_CPE_DIR}/"

COPY ./dump/genesis_manifests.json /
COPY ./scripts/* /
COPY ./bin/scanner /

RUN dnf upgrade -y && \
    dnf install -y ca-certificates xz && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    # (Optional) Remove line below to keep package management utilities
    rpm -e subscription-manager yum $(rpm -qa *hawkey*) $(rpm -qa *dnf*) && \
    chown -R 4000:4000 "${NVD_DEFINITIONS_DIR}" && \
    chown -R 4000:4000 "${K8S_DEFINITIONS_DIR}" && \
    chown -R 4000:4000 "${REPO_TO_CPE_DIR}" && \
    chown -R 4000:4000 /tmp && \
    # The contents of paths mounted as emptyDir volumes in Kubernetes are saved
    # by the script `save-dir-contents` during the image build. The directory
    # contents are then restored by the script `restore-all-dir-contents`
    # during the container start.
    chown -R 4000:4000 /etc/pki /etc/ssl && /save-dir-contents /etc/pki/ca-trust /etc/ssl && \
    chmod +rx /scanner

ENTRYPOINT ["/entrypoint.sh"]

USER 4000:4000
