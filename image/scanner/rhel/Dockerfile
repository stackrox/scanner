FROM registry.access.redhat.com/ubi8/ubi:8.3

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN dnf install -y ca-certificates xz

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

RUN chown -R 4000:4000 /etc/pki /etc/ssl && /save-dir-contents /etc/pki/ca-trust /etc/ssl

USER 4000:4000

ENTRYPOINT ["/entrypoint.sh"]
