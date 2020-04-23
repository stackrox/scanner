ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.1

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN yum update -y --nogpgcheck --disableplugin=subscription-manager && \
    yum install -y --nogpgcheck --disableplugin=subscription-manager \
      ca-certificates xz && \
      # hawkey and dnf added in UBI8 upgrade so we don't violate our "no package manager" policy
    rpm -e subscription-manager yum $(rpm -qa *hawkey*) $(rpm -qa *dnf*) \
    ;

ADD bundle.tar.gz /

ENV NVD_DEFINITIONS_DIR="/nvd_definitions"
RUN mkdir -p "${NVD_DEFINITIONS_DIR}" && chown -R 4000:4000 "${NVD_DEFINITIONS_DIR}"
RUN chown -R 4000:4000 /tmp

COPY ./scripts/* /

RUN chown -R 4000:4000 /etc/ssl && save-dir-contents /etc/ssl
VOLUME /etc/ssl

RUN chmod +rx "/scanner"
ENTRYPOINT ["/scanner"]

USER 4000:4000

HEALTHCHECK CMD curl --insecure --fail https://127.0.0.1:8080/clarify/ping
