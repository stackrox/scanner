#! /bin/bash

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "$1" ]]; then
  echo >&2 "<usage> <tag>"
  echo >&2 "tag must be specified as the first argument"
  exit 1
fi

tag="$1"

repos=( "scanner" "scanner-db" )
exts=( "" "-rhel")

function retag() {
  for repo in "${repos[@]}"; do
    for ext in "${exts[@]}"; do
      $1 docker pull "stackrox/${repo}${ext}:${tag}"
      $1 docker tag "stackrox/${repo}${ext}:${tag}" "stackrox.io/${repo}${ext}:${tag}"
      $1 "${DIR}/push-as-manifest-list.sh" "stackrox.io/${repo}${ext}:${tag}"
      echo
    done
  done
}

retag echo

read -p "Please check the above commands and ensure CloudFlare caching is disabled. Hit Enter to continue or Ctrl-C to stop:"

retag
