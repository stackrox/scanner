ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8-minimal
ARG BASE_TAG=latest

FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_8_1.20 as builder

ENV CGO_ENABLED=1
ENV GOFLAGS=""
ENV CI=1

COPY . /src
WORKDIR /src

RUN scripts/konflux/fail-build-if-git-is-dirty.sh

RUN unzip -j blob-repo2cpe.zip -d image/scanner/dump/repo2cpe && \
    unzip -j blob-k8s-definitions.zip -d image/scanner/dump/k8s_definitions && \
    unzip -j blob-nvd-definitions.zip -d image/scanner/dump/nvd_definitions

RUN echo -n "version: " && scripts/konflux/version.sh && \
    go build -trimpath -ldflags="-X github.com/stackrox/scanner/pkg/version.Version=$(scripts/konflux/version.sh)" -o image/scanner/bin/scanner ./cmd/clair

# Replace genesis manifests file in the source code with the one generated at
# the point when the dump was taken.  This is to avoid discrepancy between other
# files of the dump and the manifest.
COPY ./blob-genesis_manifests.json image/scanner/dump/genesis_manifests.json

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

LABEL \
    com.redhat.component="rhacs-scanner-container" \
    com.redhat.license_terms="https://www.redhat.com/agreements" \
    description="This image supports image scanning for RHACS" \
    io.k8s.description="This image supports image scanning for RHACS" \
    io.k8s.display-name="scanner" \
    io.openshift.tags="rhacs,scanner,stackrox" \
    maintainer="Red Hat, Inc." \
    name="rhacs-scanner-rhel8" \
    source-location="https://github.com/stackrox/scanner" \
    summary="The image scanner for RHACS" \
    url="https://catalog.redhat.com/software/container-stacks/detail/60eefc88ee05ae7c5b8f041c" \
    # We must set version label to prevent inheriting value set in the base stage.
    # TODO(ROX-20236): configure injection of dynamic version value when it becomes possible.
    version="0.0.1-todo"

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
ENV K8S_DEFINITIONS_DIR="/k8s_definitions"
ENV REPO_TO_CPE_DIR="/repo2cpe"

COPY --from=builder /src/image/scanner/scripts /
COPY --from=builder /src/image/scanner/bin/scanner ./
COPY --chown=65534:65534 --from=builder "/src/image/scanner/dump${NVD_DEFINITIONS_DIR}/" ".${NVD_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 --from=builder "/src/image/scanner/dump${K8S_DEFINITIONS_DIR}/" ".${K8S_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 --from=builder "/src/image/scanner/dump${REPO_TO_CPE_DIR}/" ".${REPO_TO_CPE_DIR}/"
COPY --chown=65534:65534 --from=builder /src/image/scanner/dump/genesis_manifests.json ./

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
    chown -R 65534:65534 /etc/pki /etc/ssl && \
    /save-dir-contents /etc/pki/ca-trust /etc/ssl

# This is equivalent to nobody:nobody.
USER 65534:65534

ENTRYPOINT ["/entrypoint.sh"]
