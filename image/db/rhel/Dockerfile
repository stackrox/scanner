ARG BUNDLE_BASE_REGISTRY=registry.access.redhat.com
ARG BUNDLE_BASE_IMAGE=ubi8/ubi
# Be sure to keep the pg_rhel_version in create-bundle.sh up-to-date.
ARG BUNDLE_BASE_TAG=8.5

ARG BASE_REGISTRY
ARG BASE_IMAGE
ARG BASE_TAG

FROM ${BUNDLE_BASE_REGISTRY}/${BUNDLE_BASE_IMAGE}:${BUNDLE_BASE_TAG} AS extracted_bundle

COPY bundle.tar.gz /
WORKDIR /bundle
RUN tar -xzf /bundle.tar.gz

FROM ${BASE_REPOSITORY}/${BASE_IMAGE}:${BASE_TAG}

COPY --from=extracted_bundle /bundle/docker-entrypoint-initdb.d/definitions.sql.gz /docker-entrypoint-initdb.d/
