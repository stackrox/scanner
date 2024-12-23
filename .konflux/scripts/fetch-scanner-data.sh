#!/usr/bin/env bash

# This script is for downloading Scanner/Scanner-DB blobs that should be included in the container image.

set -euo pipefail

if [[ "$#" -lt "1" ]]; then
  >&2 echo "Error: please pass target directory and blob filename(s) as command line arguments."
  >&2 echo "For example:"
  >&2 echo "    $(basename "${BASH_SOURCE[0]}") $(pwd) nvd-definitions.zip k8s-definitions.zip repo2cpe.zip genesis_manifests.json"
  exit 1
fi

TARGET_DIR="$1"
shift

blobs=( "$@" )

# Ensure that we download scanner data for a release if this is a tagged build.

# First, try take git tag if it's a tagged commit.
tag="$(git tag --points-at)"
if [[ -z "${tag}" ]]; then
  # If not, use latest.
  SCANNER_DATA_VERSION="latest"
  RETRY_TIMES=4
elif [[ "$(wc -l <<< "${tag}")" -eq 1 ]]; then
  # If there is exactly one tag on the commit, use that.
  SCANNER_DATA_VERSION="${tag}"
  RETRY_TIMES=1000
else
  >&2 echo -e "Error: the HEAD commit has multiple tags, don't know which one to choose:\n${tag}"
  exit 5
fi

for blob in "${blobs[@]}"; do

  url="https://storage.googleapis.com/definitions.stackrox.io/scanner-data/${SCANNER_DATA_VERSION}/${blob}"
  dest="${TARGET_DIR}/blob-${blob}"

  echo """
Downloading ${url} > ${dest}, retrying ${RETRY_TIMES} times or until aborted by task timeout...
If the download times out for a tagged build, it is likely because the blobs were not published by the GitHub Workflow.
This usually takes about 1 hour after the tag is pushed.
Go to https://github.com/stackrox/scanner/actions to debug.
  """
  curl --fail --no-progress-bar --show-error --retry "${RETRY_TIMES}" --retry-delay 10 --retry-all-errors \
    --output "${dest}" \
    "${url}"

done

if [[ "${#blobs[@]}" == "0" ]]; then
  echo "No blobs specified in arguments. Will not download anything."
fi

echo "Done"
