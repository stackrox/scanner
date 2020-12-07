#! /bin/sh

set -e

if [[ -z "$1" ]]; then
  echo >&2 "<usage> <tag>"
  echo >&2 "tag must be specified as the first argument"
  exit 1
fi

tag="$1"

repos=( "scanner" "scanner-db" )
exts=( "" "-rhel")

for repo in "${repos[@]}"; do
  for ext in "${exts[@]}"; do
    echo docker pull "stackrox/${repo}${ext}:${tag}"
    echo docker tag "stackrox/${repo}${ext}:${tag}" "stackrox.io/${repo}${ext}:${tag}"
    echo docker push "stackrox.io/${repo}${ext}:${tag}"
    echo
  done
done

read -p "About to run the above. Hit any key to continue and ctrl-c to stop:" VAR

for repo in "${repos[@]}"; do
  for ext in "${exts[@]}"; do
    docker pull "stackrox/${repo}${ext}:${tag}"
    docker tag "stackrox/${repo}${ext}:${tag}" "stackrox.io/${repo}${ext}:${tag}"
    docker push "stackrox.io/${repo}${ext}:${tag}"
  done
done

