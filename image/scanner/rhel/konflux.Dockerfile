# Compiling scanner binaries and staging repo2cpe and genesis manifests
FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_8_1.24@sha256:beed4519c775d6123c11351048be29e6f93ab0adaea2c7d55977b445966f5b27 AS builder

ARG SCANNER_TAG
RUN if [[ "$SCANNER_TAG" == "" ]]; then >&2 echo "error: required SCANNER_TAG arg is unset"; exit 6; fi
ENV RELEASE_TAG="${SCANNER_TAG}"

# TODO(ROX-27054): Remove the redundant strictfipsruntime option if one is found to be so
ENV GOEXPERIMENT=strictfipsruntime
ENV GOTAGS=strictfipsruntime
ENV GOFLAGS=""
ENV CI=1

COPY . /src
WORKDIR /src

RUN unzip -j .konflux/scanner-data/blob-repo2cpe.zip -d image/scanner/dump/repo2cpe && \
    unzip -j .konflux/scanner-data/blob-k8s-definitions.zip -d image/scanner/dump/k8s_definitions && \
    unzip -j .konflux/scanner-data/blob-nvd-definitions.zip -d image/scanner/dump/nvd_definitions

RUN echo -n "version: " && make --quiet --no-print-directory tag && \
    make CGO_ENABLED=1 scanner-build-nodeps

# Replace genesis manifests file in the source code with the one generated at
# the point when the dump was taken.  This is to avoid discrepancy between other
# files of the dump and the manifest.
COPY .konflux/scanner-data/blob-genesis_manifests.json image/scanner/dump/genesis_manifests.json


# Common base for scanner slim and full
FROM registry.access.redhat.com/ubi8-minimal:latest@sha256:89f2c9794a3357a8463e3acc4dad45075b1a9a63ae05d4a493dd1451625f2222 AS scanner-common

ARG SCANNER_TAG

LABEL \
    com.redhat.license_terms="https://www.redhat.com/agreements" \
    description="This image supports image scanning for Red Hat Advanced Cluster Security for Kubernetes" \
    io.k8s.description="This image supports image scanning for Red Hat Advanced Cluster Security for Kubernetes" \
    io.openshift.tags="rhacs,scanner,stackrox" \
    maintainer="Red Hat, Inc." \
    # Custom Snapshot creation in `operator-bundle-pipeline` depends on source-location label to be set correctly.
    source-location="https://github.com/stackrox/scanner" \
    summary="The image scanner for Red Hat Advanced Cluster Security for Kubernetes" \
    url="https://catalog.redhat.com/software/container-stacks/detail/60eefc88ee05ae7c5b8f041c" \
    # We must set version label to prevent inheriting value set in the base stage.
    version="${SCANNER_TAG}" \
    # Release label is required by EC although has no practical semantics.
    # We also set it to not inherit one from a base stage in case it's RHEL or UBI.
    release="1"

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

ENV REPO_TO_CPE_DIR="/repo2cpe"

COPY --from=builder /src/image/scanner/scripts /
COPY --from=builder /src/image/scanner/bin/scanner ./
COPY --chown=65534:65534 --from=builder "/src/image/scanner/dump${REPO_TO_CPE_DIR}/" ".${REPO_TO_CPE_DIR}/"
COPY --chown=65534:65534 --from=builder /src/image/scanner/dump/genesis_manifests.json ./

COPY LICENSE /licenses/LICENSE

RUN microdnf install xz && \
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
    chown -R 65534:65534 /etc/pki/ca-trust /etc/ssl && \
    /save-dir-contents /etc/pki/ca-trust /etc/ssl

# This is equivalent to nobody:nobody.
USER 65534:65534

ENTRYPOINT ["/entrypoint.sh"]


# Scanner Slim
FROM scanner-common AS scanner-slim

LABEL \
    com.redhat.component="rhacs-scanner-slim-container" \
    io.k8s.display-name="scanner-slim" \
    name="rhacs-scanner-slim-rhel8"

ENV ROX_SLIM_MODE="true"


# Scanner (full)
FROM scanner-common AS scanner

LABEL \
    com.redhat.component="rhacs-scanner-container" \
    io.k8s.display-name="scanner" \
    name="rhacs-scanner-rhel8"

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
ENV K8S_DEFINITIONS_DIR="/k8s_definitions"

COPY --chown=65534:65534 --from=builder "/src/image/scanner/dump${NVD_DEFINITIONS_DIR}/" ".${NVD_DEFINITIONS_DIR}/"
COPY --chown=65534:65534 --from=builder "/src/image/scanner/dump${K8S_DEFINITIONS_DIR}/" ".${K8S_DEFINITIONS_DIR}/"
