FROM registry.access.redhat.com/ubi9-minimal:latest AS scanner-db-slim

RUN microdnf install xz


FROM registry.access.redhat.com/ubi9:latest AS scanner-db

RUN dnf install xz
