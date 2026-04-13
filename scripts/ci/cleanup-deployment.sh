#!/usr/bin/env bash

# Copied from https://github.com/stackrox/stackrox/blob/master/scripts/ci/cleanup-deployment.sh

namespace=${1:-stackrox}

kubectl -n "${namespace}" get cm,deploy,ds,networkpolicy,pv,pvc,secret,svc,serviceaccount -o name | xargs kubectl -n "${namespace}" delete --wait
