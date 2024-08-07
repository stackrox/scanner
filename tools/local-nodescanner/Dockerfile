ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi9-minimal
ARG BASE_TAG=9.4-1194

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS base

COPY ./bin/local-nodescanner /local-nodescanner

ENTRYPOINT [ "/local-nodescanner" ]
