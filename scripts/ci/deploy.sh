#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
# shellcheck source=../../scripts/lib.sh
source "$ROOT/scripts/lib.sh"

set -euo pipefail

# Deploys Scanner and port-forwards the HTTP and gRPC endpoints.
# Adapted from https://github.com/stackrox/stackrox/blob/master/tests/e2e/lib.sh

_deploy_scanner() {
    if [[ "$#" -ne 1 ]]; then
        die "missing args. usage: deploy_scanner <cmd>"
    fi

    local cmd="$1"

    info "Deploying Scanner"

    make "${cmd}"

    _wait_for_scanner

    _start_port_forwards_for_test
}

_wait_for_scanner() {
    info "Waiting for Scanner to start"

    sleep 5
    kubectl -n stackrox get pod
    POD="$(kubectl -n stackrox get pod -o jsonpath='{.items[?(@.metadata.labels.app=="scanner")].metadata.name}')"
    [[ -n "${POD}" ]]
    kubectl -n stackrox wait "--for=condition=Ready" "pod/${POD}" --timeout=30m
    kubectl -n stackrox get pod
}

_start_port_forwards_for_test() {
    info "Creating port-forwards for test"

    # Try preventing kubectl port-forward from hitting the FD limit, see
    # https://github.com/kubernetes/kubernetes/issues/74551#issuecomment-910520361
    # Note: this might fail if we don't have the correct privileges. Unfortunately,
    # we cannot `sudo ulimit` because it is a shell builtin.
    ulimit -n 65535 || true

    success=0
    for _ in $(seq 1 10); do
        nohup kubectl port-forward -n stackrox "${POD}" "8080:8080" & # Legacy clairify endpoint
        nohup kubectl port-forward -n stackrox "${POD}" "8443:8443" & # gRPC endpoint
        curl --retry 12 --retry-connrefused -4 --retry-delay 5 --retry-max-time 60 -sk 'https://localhost:8080/clairify/ping' || touch FAIL
        echo
        curl --retry 12 --retry-connrefused -4 --retry-delay 5 --retry-max-time 60 -skf 'https://localhost:8443/v1/ping' || touch FAIL
        echo
        if [[ ! -f FAIL ]]; then
            success=1
            break
        fi
        echo "Port-forwarding failed."
        cat nohup.out || true
        rm nohup.out || true
        rm FAIL || true
        pkill kubectl || true
        sleep 5
    done

    [[ "${success}" -gt 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -ne 1 ]]; then
        die "missing args. 'deploy' or 'slim-deploy' required."
    fi
    _deploy_scanner "$1"
fi
