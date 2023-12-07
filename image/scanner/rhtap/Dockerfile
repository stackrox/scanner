ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8-minimal
ARG BASE_TAG=latest

FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_8_1.20 as builder

ENV CGO_ENABLED=1
ENV GOFLAGS=""
ENV CI=1

COPY . /src
WORKDIR /src

RUN unzip -j repo2cpe.zip -d image/scanner/dump/repo2cpe && \
    unzip -j k8s-definitions.zip -d image/scanner/dump/k8s_definitions && \
    unzip -j nvd-definitions.zip -d image/scanner/dump/nvd_definitions

RUN go build -trimpath -ldflags="-X github.com/stackrox/scanner/pkg/version.Version=$(git describe --tags --abbrev=10 --dirty --long)" -o image/scanner/bin/scanner ./cmd/clair

# Replace genesis manifests file in the source code with the one generated at
# the point when the dump was taken.  This is to avoid discrepancy between other
# files of the dump and the manifest.
COPY ./genesis_manifests.json image/scanner/dump/genesis_manifests.json

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

LABEL name="scanner" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="Image scanner for the StackRox Kubernetes Security Platform" \
      description="This image supports image scanning in the StackRox Kubernetes Security Platform."

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
    chown -R 65534:65534 /etc/pki /etc/ssl && /save-dir-contents /etc/pki/ca-trust /etc/ssl && \
    chmod +rx /scanner

# This is equivalent to nobody:nobody.
USER 65534:65534

ENTRYPOINT ["/entrypoint.sh"]
