ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8-minimal
ARG BASE_TAG=latest

FROM registry-proxy.engineering.redhat.com/rh-osbs/openshift-golang-builder:v1.20.10-202310161945.el8.gdc4b478 AS builder

ENV CGO_ENABLED=1
ENV GOFLAGS=""
ENV CI=1

COPY . /src
WORKDIR /src

RUN dnf install -y jq && \
    make build-updater && \
    ./bin/updater generate-dump && \
    go build -trimpath -ldflags="-X github.com/stackrox/scanner/pkg/version.Version=$(git describe --tags --abbrev=10 --dirty --long)" -o image/scanner/bin/scanner ./cmd/clair && \
    mkdir image/scanner/dump && \
    unzip -o dump.zip -d image/scanner/dump && \
    image/scanner/rhel/create-bundle.sh image/scanner image/scanner/rhel && \
    mkdir /bundle && \
    tar -C /bundle -xzf /src/image/scanner/rhel/bundle.tar.gz

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS base

LABEL name="scanner" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

COPY image/scanner/scripts /

COPY --from=extracted_bundle /bundle/scanner ./

COPY --from=extracted_bundle /bundle/THIRD_PARTY_NOTICES/ /THIRD_PARTY_NOTICES/

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
