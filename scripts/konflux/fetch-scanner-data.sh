#!/usr/bin/env bash

# This script is for downloading Scanner/Scanner-DB blobs that should be included in the container image.

set -exuo pipefail

if [[ "$#" -lt "2" ]]; then
  >&2 echo "Error: please pass scanner tag, target directory and blob filename(s) as command line arguments."
  >&2 echo "For example:"
  >&2 echo "    $(basename "${BASH_SOURCE[0]}") 2.32.4 $(pwd) nvd-definitions.zip k8s-definitions.zip repo2cpe.zip genesis_manifests.json"
  exit 1
fi

SCANNER_TAG="$1"
TARGET_DIR="$2"
shift 2
blobs=( "$@" )

# Ensure that we download scanner data for a release if this is a tagged build
# and that it is tagged with the exact SCANNER_TAG.

# First, try take git tag if it's a tagged commit.
tag="$(git tag --points-at)"
if [[ -z "$tag" ]]; then
  # If not, use latest.
  SCANNER_DATA_VERSION="latest"
elif [ "$tag" == "${SCANNER_TAG}" ]; then
  # Otherwise, ensure that the tags match.
  SCANNER_DATA_VERSION="${SCANNER_TAG}"
else
  >&2 echo -e "Error: the tag on the HEAD commit ($tag) does not match SCANNER_TAG ($SCANNER_TAG)"
  exit 5
fi

for blob in "${blobs[@]}"; do

  url="https://storage.googleapis.com/definitions.stackrox.io/scanner-data/${SCANNER_DATA_VERSION}/${blob}"
  dest="${TARGET_DIR}/blob-${blob}"

  echo "Downloading ${url} > ${dest}, retrying 1000 times or until killed..."
  curl --fail -s --show-error --retry 1000 --retry-delay 10 --retry-connrefused \
    --output "${dest}" \
    "${url}"

done

if [[ "${#blobs[@]}" == "0" ]]; then
  echo "No blobs specified in arguments. Will not download anything."
fi

echo "Done"
