ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi9
ARG BASE_TAG=9.1

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS base

COPY ./bin/local-nodescanner /local-nodescanner

ENTRYPOINT [ "/local-nodescanner" ]