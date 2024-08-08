FROM registry.access.redhat.com/ubi8-minimal:latest AS scanner-slim

RUN microdnf -y install xz


FROM registry.access.redhat.com/ubi8:latest AS scanner

RUN dnf -y install xz
