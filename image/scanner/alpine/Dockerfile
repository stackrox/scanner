FROM alpine:3.10

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

# Scanner requires the following binaries.
RUN apk update && \
    apk --no-cache add \
            ca-certificates xz \
        && apk --repository "http://nl.alpinelinux.org/alpine/3.10/community" --no-cache add rpm \
        && apk --purge del apk-tools;

COPY ./bin/scanner /

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
RUN mkdir -p "${NVD_DEFINITIONS_DIR}"
COPY ./dump/nvd/*.json "${NVD_DEFINITIONS_DIR}/"

COPY ./dump/genesis_manifests.json /
COPY ./scripts/* /

RUN chown -R 4000:4000 /etc/ssl && /save-dir-contents /etc/ssl
VOLUME /etc/ssl

USER 4000:4000

ENTRYPOINT ["/scanner"]
