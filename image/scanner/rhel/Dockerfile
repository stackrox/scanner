ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8-minimal
ARG BASE_TAG=latest

FROM quay.io/stackrox-io/apollo-ci:scanner-build-0.3.61-4-g955b639000 as extracted_bundle

COPY . /src
WORKDIR /src
# COPY api ./api
# COPY benchmarks ./benchmarks
# COPY chart ./chart
# COPY cmd ./cmd
# COPY cpe ./cpe
# COPY database ./database
# COPY e2etests ./e2etests
# COPY ext ./ext
# COPY generated ./generated
# COPY genesis-dump ./genesis-dump
# COPY image ./image
# COPY img ./img
# COPY istio ./istio
# COPY k8s ./k8s
# COPY localdev ./localdev
# COPY make ./make
# COPY pkg ./pkg
# COPY proto ./proto
# COPY rendered-chart ./rendered-chart
# COPY scale ./scale
# COPY singletons ./singletons
# COPY testdata ./testdata
# COPY testimages ./testimages
# COPY tools ./tools
# COPY .git ./.git

# COPY BUILD_IMAGE_VERSION CODE_OF_CONDUCT.md deps go.mod go.sum LICENSE Makefile proto-generated-srcs README.md worker.go worker_test.go .

RUN dnf install -y jq
RUN make build-updater
RUN ./bin/updater generate-dump
RUN go build -trimpath -ldflags="-X github.com/stackrox/scanner/pkg/version.Version=$(git describe --tags --abbrev=10 --dirty --long)" -o image/scanner/bin/scanner ./cmd/clair
RUN mkdir image/scanner/rhel/dump
RUN unzip -o dump.zip -d image/scanner/rhel/dump
RUN image/scanner/rhel/create-bundle.sh image/scanner image/scanner/rhel
RUN mkdir /bundle
RUN tar -C /bundle -xzf /src/image/scanner/rhel/bundle.tar.gz

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
