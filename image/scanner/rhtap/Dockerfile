ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8-minimal
ARG BASE_TAG=latest

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

LABEL name="scanner" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
ENV K8S_DEFINITIONS_DIR="/k8s_definitions"
ENV REPO_TO_CPE_DIR="/repo2cpe"

WORKDIR /src

COPY image/scanner/scripts /
COPY scanner ./
COPY --chown=65534:65534 "${NVD_DEFINITIONS_DIR}/" ".${NVD_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 "${K8S_DEFINITIONS_DIR}/" ".${K8S_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 "${REPO_TO_CPE_DIR}/" ".${REPO_TO_CPE_DIR}/"
COPY --chown=65534:65534 genesis_manifests.json ./

RUN microdnf upgrade --nobest && \
    microdnf install xz && \
    microdnf clean all && \
    # (Optional) Remove line below to keep package management utilities
    # We don't uninstall rpm because scanner uses it to get packages installed in scanned images.
    rpm -e --nodeps $(rpm -qa curl '*dnf*' '*libsolv*' '*hawkey*' 'yum*') && \
    rm -rf /var/cache/dnf /var/cache/yum && \
    chown -R 65534:65534 /tmp && \
    # The contents of paths mounted as emptyDir volumes in Kubernetes are saved
    # by the script `save-dir-contents` during the image build. The directory
    # contents are then restored by the script `restore-all-dir-contents`
    # during the container start.
    chown -R 65534:65534 /etc/pki /etc/ssl && /save-dir-contents /etc/pki/ca-trust /etc/ssl && \
    chmod +rx /scanner

# This is equivalent to nobody:nobody.
USER 65534:65534

ENTRYPOINT ["/entrypoint.sh"]
