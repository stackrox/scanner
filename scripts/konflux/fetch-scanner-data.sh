#!/usr/bin/env bash

# This script is for downloading Scanner/Scanner-DB blobs that should be included in the container image.

set -euo pipefail

if [[ "$#" -lt "2" ]]; then
  >&2 echo "Error: please pass target directory and blob filename(s) as command line arguments."
  >&2 echo "For example:"
  >&2 echo "    $(basename "${BASH_SOURCE[0]}") $(pwd) nvd-definitions.zip k8s-definitions.zip repo2cpe.zip genesis_manifests.json"
  exit 1
fi

TARGET_DIR="$1"
shift

blobs=( "$@" )

for blob in "${blobs[@]}"; do

  # TODO(ROX-22130): Assign proper suffix for tagged commits instead of /latest/.
  url="https://storage.googleapis.com/definitions.stackrox.io/scanner-data/latest/${blob}"
  dest="${TARGET_DIR}/blob-${blob}"

  echo "Downloading ${url} > ${dest}"
  curl --fail -s --show-error --retry 4 --retry-max-time 30 --retry-connrefused \
    --output "${dest}" \
    "${url}"

done

echo "Done"
