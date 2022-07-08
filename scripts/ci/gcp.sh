#!/usr/bin/env bash

# A collection of GCP related reusable bash functions for CI
#
# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/gcp.sh

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$SCRIPTS_ROOT/scripts/ci/lib.sh"

set -euo pipefail

setup_gcp() {
    info "Setting up GCP auth and config"

    ensure_CI

    local service_account
    if [ $# -gt 0 ]; then
        service_account="$1"
    else
        require_environment "GOOGLE_SA_CIRCLECI_SCANNER"
        service_account="${GOOGLE_SA_CIRCLECI_SCANNER}"
    fi

    require_executable "gcloud"

    if [[ "$(gcloud config get-value core/project 2>/dev/null)" == "stackrox-ci" ]]; then
        echo "Current project is already set to stackrox-ci. Assuming configuration already applied."
        return
    fi
    gcloud auth activate-service-account --key-file <(echo "$service_account")
    gcloud auth list
    gcloud config set project stackrox-ci
    gcloud config set compute/region us-central1
    gcloud config unset compute/zone
    gcloud config set core/disable_prompts True
}
