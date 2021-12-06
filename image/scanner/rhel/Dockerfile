ARG BUNDLE_BASE_REGISTRY=registry.access.redhat.com
ARG BUNDLE_BASE_IMAGE=ubi8/ubi
ARG BUNDLE_BASE_TAG=8.5

ARG BASE_REGISTRY
ARG BASE_IMAGE
ARG BASE_TAG

FROM ${BUNDLE_BASE_REGISTRY}/${BUNDLE_BASE_IMAGE}:${BUNDLE_BASE_TAG} AS extracted_bundle

COPY bundle.tar.gz /
WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

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
