#! /bin/bash

# Copied from https://github.com/stackrox/stackrox/blob/master/scripts/ci/cleanup-deployment.sh

kubectl -n stackrox get cm,deploy,ds,networkpolicy,pv,pvc,secret,svc,serviceaccount -o name | xargs kubectl -n stackrox delete --wait
