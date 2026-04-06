#!/usr/bin/env bash

# A collection of GKE related reusable bash functions for CI
# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/gke.sh

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
# shellcheck source=../../scripts/ci/lib.sh
source "$SCRIPTS_ROOT/scripts/ci/lib.sh"
# shellcheck source=../../scripts/ci/gcp.sh
source "$SCRIPTS_ROOT/scripts/ci/gcp.sh"

set -euo pipefail

provision_gke_cluster() {
    info "Provisioning a GKE cluster"

    setup_gcp
    assign_env_variables "$@"
    create_cluster
}

assign_env_variables() {
    info "Assigning environment variables for later steps"

    if [[ "$#" -ne 1 ]]; then
        die "missing args. usage: assign_env_variables <cluster-id>"
    fi

    local cluster_id="$1"

    ensure_CI

    local build_num
    if is_OPENSHIFT_CI; then
        require_environment "BUILD_ID"
        build_num="${BUILD_ID}"
    else
        die "Support is missing for this CI environment"
    fi

    local cluster_name="rox-ci-${cluster_id}-${build_num}"
    cluster_name="${cluster_name:0:40}" # (for GKE name limit)
    ci_export CLUSTER_NAME "$cluster_name"
    echo "Assigned cluster name is $cluster_name"

    choose_release_channel
    choose_cluster_version
}

choose_release_channel() {
    if ! is_in_PR_context; then
        GKE_RELEASE_CHANNEL="${GKE_RELEASE_CHANNEL:-stable}"
    elif pr_has_label ci-gke-use-rapid-channel; then
        GKE_RELEASE_CHANNEL="rapid"
    elif pr_has_label ci-gke-use-regular-channel; then
        GKE_RELEASE_CHANNEL="regular"
    elif pr_has_label ci-gke-use-stable-channel; then
        GKE_RELEASE_CHANNEL="stable"
    elif pr_has_pragma gke_release_channel; then
        GKE_RELEASE_CHANNEL="$(pr_get_pragma gke_release_channel)"
    fi
}

choose_cluster_version() {
    if is_in_PR_context && pr_has_pragma gke_cluster_version; then
        GKE_CLUSTER_VERSION="$(pr_get_pragma gke_cluster_version)"
    fi
    if [[ "${GKE_CLUSTER_VERSION:-}" == "latest" ]]; then
        GKE_CLUSTER_VERSION="$(gcloud container get-server-config --format json | jq -r ".validMasterVersions[0]")"
    elif [[ "${GKE_CLUSTER_VERSION:-}" == "oldest" ]]; then
        GKE_CLUSTER_VERSION="$(gcloud container get-server-config --format json | jq -r ".validMasterVersions[-1]")"
    fi
    if [[ "${GKE_CLUSTER_VERSION:-}" == "null" ]]; then
        echo "WARNING: Unable to extract version from gcloud config."
        echo "Valid versions are:"
        gcloud container get-server-config --format json | jq .validMasterVersions
        unset GKE_CLUSTER_VERSION
    fi
}

create_cluster() {
    info "Creating a GKE cluster"
    # Store requested timestamp to create log query link with time range.
    date -u +"%Y-%m-%dT%H:%M:%SZ" > /tmp/GKE_CLUSTER_REQUESTED_TIMESTAMP

    ensure_CI

    require_environment "CLUSTER_NAME"

    local tags="stackrox-ci"
    local labels="stackrox-ci=true"
    if is_OPENSHIFT_CI; then
        require_environment "JOB_NAME"
        require_environment "BUILD_ID"
        build_num="${BUILD_ID}"
        job_name="${JOB_NAME}"
    else
        die "Support is missing for this CI environment"
    fi

    # Refresher on bash shell parameter expansion:
    # https://www.gnu.org/software/bash/manual/bash.html#Shell-Parameter-Expansion
    # ${VAR//./-} : Replaces all "." with a "-"
    # ${VAR/%-/}  : Deletes the last "-"
    # ${VAR,,}    : Converts all alphabetic to their lowercase form
    tags="${tags},stackrox-ci-${job_name:0:50}"
    tags="${tags//./-}"
    tags="${tags/%-/}"
    labels="${labels},stackrox-ci-job=${job_name:0:63}"
    labels="${labels//./-}"
    labels="${labels/%-/}"
    labels="${labels},stackrox-ci-build-id=${build_num:0:63}"
    labels="${labels//./-}"
    labels="${labels/%-/}"

    if is_in_PR_context; then
        labels="${labels},pr=$(get_PR_number)"
    fi

    # lowercase
    tags="${tags,,}"
    labels="${labels,,}"

    ### Network Sizing ###
    # The overall subnetwork ("--create-subnetwork") is used for nodes.
    # The "cluster" secondary range is for pods ("--cluster-ipv4-cidr").
    # The "services" secondary range is for ClusterIP services ("--services-ipv4-cidr").
    # See https://cloud.google.com/kubernetes-engine/docs/how-to/alias-ips#cluster_sizing.

    REGION=us-central1
    NUM_NODES="${NUM_NODES:-3}"
    GCP_IMAGE_TYPE="${GCP_IMAGE_TYPE:-UBUNTU_CONTAINERD}"
    POD_SECURITY_POLICIES="${POD_SECURITY_POLICIES:-false}"
    GKE_RELEASE_CHANNEL="${GKE_RELEASE_CHANNEL:-stable}"
    MACHINE_TYPE="${MACHINE_TYPE:-e2-standard-4}"
    DISK_SIZE_GB=${DISK_SIZE_GB:-80}

    echo "Creating ${NUM_NODES} node cluster with image type \"${GCP_IMAGE_TYPE}\" and ${DISK_SIZE_GB}GB disks."

    if [[ -n "${GKE_CLUSTER_VERSION:-}" ]]; then
        ensure_supported_cluster_version
        echo "Using GKE cluster version: ${GKE_CLUSTER_VERSION} (which overrides release channel ${GKE_RELEASE_CHANNEL})"
        VERSION_ARGS=(--cluster-version "${GKE_CLUSTER_VERSION}" --no-enable-autoupgrade)
    else
        echo "Using GKE release channel: $GKE_RELEASE_CHANNEL"
        VERSION_ARGS=(--release-channel "${GKE_RELEASE_CHANNEL}")
    fi

    PSP_ARG=
    if [[ "${POD_SECURITY_POLICIES}" == "true" ]]; then
        PSP_ARG="--enable-pod-security-policy"
    fi
    zones=$(gcloud compute zones list --format="value(name,region.basename(),status)" | awk "/${REGION}\tUP\$/{print \$1}" | shuf)
    success=0
    for zone in $zones; do
        echo "Trying zone $zone"
        ci_export ZONE "$zone"
        gcloud config set compute/zone "${zone}"
        status=0
        # shellcheck disable=SC2153
        timeout 830 gcloud beta container clusters create \
          --machine-type "${MACHINE_TYPE}" \
          --num-nodes "${NUM_NODES}" \
          --disk-type=pd-ssd \
          --disk-size="${DISK_SIZE_GB}GB" \
          --create-subnetwork range=/28 \
          --cluster-ipv4-cidr=/20 \
          --services-ipv4-cidr=/24 \
          --enable-ip-alias \
          --enable-network-policy \
          --no-enable-autorepair \
          "${VERSION_ARGS[@]}" \
          --image-type "${GCP_IMAGE_TYPE}" \
          --tags="${tags}" \
          --labels="${labels}" \
          ${PSP_ARG} \
          "${CLUSTER_NAME}" || status="$?"
        if [[ "${status}" == 0 ]]; then
            success=1
            break
        elif [[ "${status}" == 124 ]]; then
            info "gcloud command timed out. Checking to see if cluster is still creating"
            if ! gcloud container clusters describe "${CLUSTER_NAME}" >/dev/null; then
                info "Create cluster did not create the cluster in Google. Trying a different zone..."
            else
                for i in {1..60}; do
                    if [[ "$(gcloud container clusters describe "${CLUSTER_NAME}" --format json | jq -r .status)" == "RUNNING" ]]; then
                        success=1
                        break
                    fi
                    sleep 20
                    info "Waiting for cluster ${CLUSTER_NAME} in ${zone} to move to running state (wait $i of 60)"
                done
            fi

            if [[ "${success}" == 1 ]]; then
                info "Successfully launched cluster ${CLUSTER_NAME}"
                local kubeconfig="${KUBECONFIG:-${HOME}/.kube/config}"
                ls -l "${kubeconfig}" || true
                gcloud container clusters get-credentials "$CLUSTER_NAME"
                ls -l "${kubeconfig}" || true
                break
            fi
            info "Timed out"
            info "Attempting to delete the cluster before trying another zone"
            gcloud container clusters delete "${CLUSTER_NAME}" || {
                info "An error occurred deleting the cluster: $?"
                true
            }
        fi
    done

    if [[ "${success}" == "0" ]]; then
        info "Cluster creation failed"
        return 1
    fi

    add_a_maintenance_exclusion
}

add_a_maintenance_exclusion() {
    from_now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    plus_five_epoch=$(($(date -u '+%s') + 5*3600))
    plus_five="$(date -u --date=@${plus_five_epoch} +"%Y-%m-%dT%H:%M:%SZ")"

    gcloud container clusters update "${CLUSTER_NAME}" \
      --add-maintenance-exclusion-name leave-these-clusters-alone \
      --add-maintenance-exclusion-start "${from_now}" \
      --add-maintenance-exclusion-end "${plus_five}" \
      --add-maintenance-exclusion-scope no_upgrades
}

wait_for_cluster() {
    info "Waiting for a GKE cluster to stabilize"

    while [[ $(kubectl -n kube-system get pod | tail -n +2 | wc -l) -lt 2 ]]; do
        echo "Still waiting for kubernetes to create initial kube-system pods"
        sleep 1
    done

    local grace_period=30
    while true; do
        kubectl -n kube-system get pod
        local numstarting
        numstarting=$(kubectl -n kube-system get pod -o json | jq '[(.items[].status.containerStatuses // [])[].ready | select(. | not)] | length')
        if ((numstarting == 0)); then
            local last_start_ts
            last_start_ts="$(kubectl -n kube-system get pod -o json | jq '[(.items[].status.containerStatuses // [])[] | (.state.running.startedAt // (now | todate)) | fromdate] | max')"
            local curr_ts
            curr_ts="$(date '+%s')"
            local remaining_grace_period
            remaining_grace_period=$((last_start_ts + grace_period - curr_ts))
            if ((remaining_grace_period <= 0)); then
                break
            fi
            echo "Waiting for another $remaining_grace_period seconds for kube-system pods to stabilize"
            sleep "$remaining_grace_period"
        fi

        echo "Waiting for ${numstarting} kube-system containers to be initialized"
        sleep 10
    done
}

ensure_supported_cluster_version() {
    local match
    match=$(gcloud container get-server-config --format json | jq "[.validMasterVersions | .[] | select(.|test(\"^${GKE_CLUSTER_VERSION}\"))][0]")
    if [[ -z "${match}" || "${match}" == "null" ]]; then
        echo "ERROR: A supported version cannot be found that matches ${GKE_CLUSTER_VERSION}."
        echo "Valid master versions are:"
        gcloud container get-server-config --format json | jq .validMasterVersions
        exit 1
    fi
    GKE_CLUSTER_VERSION=$(sed -e 's/^"//' -e 's/"$//' <<<"${match}")
}

refresh_gke_token() {
    info "Starting a GKE token refresh loop"

    require_environment "ZONE"
    require_environment "CLUSTER_NAME"

    local real_kubeconfig="${KUBECONFIG:-${HOME}/.kube/config}"

    # refresh token every 15m
    local pid
    while true; do
        sleep 900 &
        pid="$!"
        kill_sleep() {
            # shellcheck disable=SC2317
            echo "refresh_gke_token() terminated, killing the background sleep ($pid)"
            # shellcheck disable=SC2317
            kill "$pid"
        }
        trap kill_sleep SIGINT SIGTERM
        wait "$pid"

        info "Refreshing the GKE auth token"
        gcloud config config-helper --force-auth-refresh >/dev/null
        echo >/tmp/kubeconfig-new
        chmod 0600 /tmp/kubeconfig-new
        # shellcheck disable=SC2153
        KUBECONFIG=/tmp/kubeconfig-new gcloud container clusters get-credentials --project stackrox-ci --zone "$ZONE" "$CLUSTER_NAME"
        KUBECONFIG=/tmp/kubeconfig-new kubectl get ns >/dev/null
        mv /tmp/kubeconfig-new "$real_kubeconfig"
    done
}

teardown_gke_cluster() {
    local canceled="${1:-false}"

    info "Tearing down the GKE cluster: ${CLUSTER_NAME:-}, canceled: ${canceled}"

    require_environment "CLUSTER_NAME"
    require_executable "gcloud"

    if [[ "${canceled}" == "false" ]]; then
        # (prefix output to avoid triggering prow log focus)
        "$SCRIPTS_ROOT/scripts/ci/cleanup-deployment.sh" 2>&1 | sed -e 's/^/out: /' || true
    fi

    gcloud config set compute/zone "${ZONE}"

    for i in {1..10}; do
        gcloud container clusters describe "${CLUSTER_NAME}" --format "flattened(status)"
        if [[ ! "$(gcloud container clusters describe "${CLUSTER_NAME}" --format 'get(status)')" =~ PROVISIONING|RECONCILING ]]; then
            break
        fi
        info "Before deleting, waiting for cluster ${CLUSTER_NAME} to leave provisioning state (wait $i of 10)"
        sleep 60
    done
    gcloud container clusters delete "$CLUSTER_NAME" --async

    info "Cluster deleting asynchronously"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
