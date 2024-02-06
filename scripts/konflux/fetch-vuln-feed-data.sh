#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" < 1 ]]; then
  echo "Please pass target directory."
  exit 1
fi

TARGET_DIR="$1"

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "$TARGET_DIR is not a valid directory"
  exit 1
fi

blobs=(
  nvd-definitions.zip
  k8s-definitions.zip
  repo2cpe.zip
  genesis_manifests.json
)

for blob in "${blobs[@]}"; do
  echo "Downloading https://storage.googleapis.com/definitions.stackrox.io/scanner-data/latest/${blob} > $TARGET_DIR/blob-${blob}"
  # TODO(ROX-22130): Assign proper suffix for tagged commits instead of /latest/.
  curl --fail -s --show-error --retry 4 --retry-max-time 30 --retry-connrefused \
    --output "$TARGET_DIR/blob-${blob}" \
    "https://storage.googleapis.com/definitions.stackrox.io/scanner-data/latest/${blob}"
done
