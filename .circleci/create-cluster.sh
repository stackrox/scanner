#!/usr/bin/env bash

### Network Sizing ###
# The overall subnetwork ("--create-subnetwork") is used for nodes.
# The "cluster" secondary range is for pods ("--cluster-ipv4-cidr").
# The "services" secondary range is for ClusterIP services ("--services-ipv4-cidr").
# See https://cloud.google.com/kubernetes-engine/docs/how-to/alias-ips#cluster_sizing.

create-cluster() {
  [[ -n "${CLUSTER_NAME}" ]] || { echo "No CLUSTER_NAME found!"; return 1; }
  REGION=us-central1
  NUM_NODES="${NUM_NODES:-1}"

  # this function does not work in strict -e mode
  set +euo pipefail

  echo "Creating ${NUM_NODES} node cluster"

  zones=$(gcloud compute zones list --filter="region=$REGION" | grep UP | cut -f1 -d' ')
  success=0
  for zone in $zones; do
      echo "Trying zone $zone"
      gcloud config set compute/zone "${zone}"
      timeout 420 gcloud beta container clusters create \
          --machine-type e2-standard-4 \
          --num-nodes "${NUM_NODES}" \
          --disk-type=pd-standard \
          --disk-size=20GB \
          --create-subnetwork range=/28 \
          --cluster-ipv4-cidr=/20 \
          --services-ipv4-cidr=/24 \
          --enable-ip-alias \
          --tags="stackrox-scanner-ci,stackrox-scanner-ci-${CIRCLE_JOB}" \
          --labels="stackrox-ci=true,stackrox-scanner-ci=true,stackrox-scanner-ci-job=${CIRCLE_JOB},stackrox-scanner-ci-workflow=${CIRCLE_WORKFLOW_ID}" \
          "${CLUSTER_NAME}"
      status="$?"
      if [[ "${status}" == 0 ]];
      then
          success=1
          break
      elif [[ "${status}" == 124 ]];
      then
          echo >&2 "gcloud command timed out. Checking to see if cluster is still creating"
          if ! gcloud container clusters describe "${CLUSTER_NAME}" > /dev/null; then
            echo >&2 "Create cluster did not create the cluster in Google. Trying a different zone..."
          else
            for i in {1..120}; do
                if [[ "$(gcloud container clusters describe "${CLUSTER_NAME}" --format json | jq -r .status)" == "RUNNING" ]]; then
                  success=1
                  break
                fi
                sleep 5
                echo "Currently have waited $((i * 5)) for cluster ${CLUSTER_NAME} in ${zone} to move to running state"
            done
          fi

          if [[ "${success}" == 1 ]]; then
            echo "Successfully launched cluster ${CLUSTER_NAME}"
            break
          fi
          echo >&2 "Timed out after 10 more minutes. Trying another zone..."
          echo >&2 "Deleting the cluster"
          gcloud container clusters delete "${CLUSTER_NAME}" --async
      fi
  done

  if [[ "${success}" == "0" ]]; then
      echo "Cluster creation failed"
      return 1
  fi
}

wait-for-cluster() {
  while [[ $(kubectl -n kube-system get pod | tail -n +2 | wc -l) -lt 2 ]]; do
  	echo "Still waiting for kubernetes to create initial kube-system pods"
  	sleep 1
  done

  GRACE_PERIOD=0
  while true; do
    NUMSTARTING=$(kubectl -n kube-system get pod -o json | jq '[(.items[].status.containerStatuses // [])[].ready | select(. | not)] | length')
    if (( NUMSTARTING == 0 )); then
      LAST_START_TS="$(kubectl -n kube-system get pod -o json | jq '[(.items[].status.containerStatuses // [])[] | (.state.running.startedAt // (now | todate)) | fromdate] | max')"
      CURR_TS="$(date '+%s')"
      REMAINING_GRACE_PERIOD=$((LAST_START_TS + GRACE_PERIOD - CURR_TS))
      if (( REMAINING_GRACE_PERIOD <= 0 )); then
        break
      fi
      echo "Waiting for another $REMAINING_GRACE_PERIOD seconds for kube-system pods to stabilize"
      sleep "$REMAINING_GRACE_PERIOD"
    fi
    GRACE_PERIOD=30

    echo "Waiting for ${NUMSTARTING} kube-system containers to be initialized"
    sleep 10
  done
}
