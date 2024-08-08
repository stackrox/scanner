FROM registry.access.redhat.com/ubi9-minimal:latest AS scanner-db-slim

RUN microdnf -y install xz


FROM registry.access.redhat.com/ubi9:latest AS scanner-db

RUN dnf -y install xz
