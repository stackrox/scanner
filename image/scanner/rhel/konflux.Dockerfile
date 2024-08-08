FROM registry.access.redhat.com/ubi8-minimal:latest AS scanner-slim

RUN microdnf install xz


FROM registry.access.redhat.com/ubi8:latest AS scanner

RUN dnf install xz
