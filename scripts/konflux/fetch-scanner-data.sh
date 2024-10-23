#!/usr/bin/env bash

# This script is for downloading Scanner/Scanner-DB blobs that should be included in the container image.

set -euo pipefail

if [[ "$#" -lt "2" ]]; then
  >&2 echo "Error: please pass scanner tag, target directory and blob filename(s) as command line arguments."
  >&2 echo "For example:"
  >&2 echo "    $(basename "${BASH_SOURCE[0]}") 2.32.4 $(pwd) nvd-definitions.zip k8s-definitions.zip repo2cpe.zip genesis_manifests.json"
  exit 1
fi

SCANNER_TAG="$1"
# SCANNER_DATA_VERSION="latest"
SCANNER_DATA_VERSION="${SCANNER_TAG}"
# TODO: check if we are on master / not-tagged build

TARGET_DIR="$2"
shift

blobs=( "$@" )

for blob in "${blobs[@]}"; do

  url="https://storage.googleapis.com/definitions.stackrox.io/scanner-data/${SCANNER_DATA_VERSION}/${blob}"
  dest="${TARGET_DIR}/blob-${blob}"

  echo "Downloading ${url} > ${dest}"
  curl --fail -s --show-error --retry 4 --retry-max-time 30 --retry-connrefused \
    --output "${dest}" \
    "${url}"

done

if [[ "${#blobs[@]}" == "0" ]]; then
  echo "No blobs specified in arguments. Will not download anything."
fi

echo "Done"
