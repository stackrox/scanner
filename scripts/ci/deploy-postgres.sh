#!/usr/bin/env bash
# shellcheck disable=SC1091

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/lib.sh"

set -euo pipefail

# Deploys PostgreSQL and port-forwards the TCP endpoint.

deploy_postgres() {
    info "Deploying Postgres"

    make deploy-postgres-osci

    _start_port_forward_for_postgres
}

_start_port_forward_for_postgres() {
    info "Creating port-forward for Postgres"

    # Try preventing kubectl port-forward from hitting the FD limit, see
    # https://github.com/kubernetes/kubernetes/issues/74551#issuecomment-910520361
    # Note: this might fail if we don't have the correct privileges. Unfortunately,
    # we cannot `sudo ulimit` because it is a shell builtin.
    ulimit -n 65535 || true

    # Give it some time to start.
    sleep 5
    kubectl -n stackrox get pod
    POD="$(kubectl -n stackrox get pod -o jsonpath='{.items[?(@.metadata.labels.app=="postgres")].metadata.name}')"
    [[ -n "${POD}" ]]
    kubectl -n stackrox wait "--for=condition=Ready" "pod/${POD}" --timeout=10m
    nohup kubectl port-forward -n stackrox "${POD}" "5432:5432" & # PostgreSQL endpoint.
    sleep 10
}

undeploy_postgres() {
    info "Tearing down Postgres"

    make undeploy-postgres-osci
}
