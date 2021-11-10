ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.5

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS extracted_bundle

COPY bundle.tar.gz /
WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

LABEL name="scanner-rhel" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
ENV K8S_DEFINITIONS_DIR="/k8s_definitions"
ENV REPO_TO_CPE_DIR="/repo2cpe"

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

COPY scripts /

COPY --from=extracted_bundle /bundle/genesis_manifests.json /bundle/scanner ./
COPY --from=extracted_bundle "/bundle${NVD_DEFINITIONS_DIR}/" ".${NVD_DEFINITIONS_DIR}/"
COPY --from=extracted_bundle "/bundle${K8S_DEFINITIONS_DIR}/" ".${K8S_DEFINITIONS_DIR}/"
COPY --from=extracted_bundle "/bundle${REPO_TO_CPE_DIR}/" ".${REPO_TO_CPE_DIR}/"

COPY ./THIRD_PARTY_NOTICES/ /THIRD_PARTY_NOTICES/

RUN dnf upgrade -y && \
    dnf install -y ca-certificates xz && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    # (Optional) Remove line below to keep package management utilities
    rpm -e subscription-manager yum $(rpm -qa *hawkey*) $(rpm -qa *dnf*) && \
    chown -R 65534:65534 "${NVD_DEFINITIONS_DIR}" && \
    chown -R 65534:65534 "${K8S_DEFINITIONS_DIR}" && \
    chown -R 65534:65534 "${REPO_TO_CPE_DIR}" && \
    chown -R 65534:65534 /tmp && \
    # The contents of paths mounted as emptyDir volumes in Kubernetes are saved
    # by the script `save-dir-contents` during the image build. The directory
    # contents are then restored by the script `restore-all-dir-contents`
    # during the container start.
    chown -R 65534:65534 /etc/pki /etc/ssl && /save-dir-contents /etc/pki/ca-trust /etc/ssl && \
    chmod +rx /scanner

ENTRYPOINT ["/entrypoint.sh"]

USER 65534:65534

HEALTHCHECK CMD curl --insecure --fail https://127.0.0.1:8080/clarify/ping
