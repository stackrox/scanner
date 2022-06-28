#!/bin/sh
set -eu

# Collect Service Logs script
#
# Extracts service logs from the given Kubernetes cluster and saves them off for
# future examination.
#
# Usage:
#   collect-service-logs.sh NAMESPACE [DIR]
#
# Example:
# $ ./scripts/ci/collect-service-logs.sh stackrox
#
# Assumptions:
# - Logs are saved under /tmp/k8s-service-logs/ or DIR if passed
#
# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/collect-service-logs.sh

usage() {
    echo "./scripts/ci/collect-service-logs.sh <namespace>"
    echo "e.g. ./scripts/ci/collect-service-logs.sh stackrox"
}

main() {
    namespace="$1"
    if [ -z "${namespace}" ]; then
        usage
        exit 1
    fi

    if [ $# -gt 1 ]; then
        log_dir="$2"
    else
        log_dir="/tmp/k8s-service-logs"
    fi
    log_dir="${log_dir}/${namespace}"
    mkdir -p "${log_dir}"

    echo
    echo ">>> Collecting from namespace ${namespace} <<<"
    echo
	  set +e

    for pod in $(kubectl -n "${namespace}" get po | tail -n +2 | awk '{print $1}'); do
        kubectl describe po "${pod}" -n "${namespace}" > "${log_dir}/${pod}_describe.log"
        for ctr in $(kubectl -n "${namespace}" get po "$pod" -o jsonpath='{.status.containerStatuses[*].name}'); do
            kubectl -n "${namespace}" logs "po/${pod}" -c "$ctr" > "${log_dir}/${pod}-${ctr}.log"
            kubectl -n "${namespace}" logs "po/${pod}" -p -c "$ctr" > "${log_dir}/${pod}-${ctr}-previous.log"
        done
        for ctr in $(kubectl -n "${namespace}" get po "$pod" -o jsonpath='{.status.initContainerStatuses[*].name}'); do
            kubectl -n "${namespace}" logs "po/${pod}" -c "$ctr" > "${log_dir}/${pod}-${ctr}.log"
            kubectl -n "${namespace}" logs "po/${pod}" -p -c "$ctr" > "${log_dir}/${pod}-${ctr}-previous.log"
        done
    done
    find "${log_dir}" -type f -size 0 -delete
}

main "$@"
