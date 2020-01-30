#!/bin/bash

files=$(ls Dockerfile.*)

for file in $files; do
  distro=${file#"Dockerfile."}

  img="stackrox/vuln-images:${distro}-package-removal"
  docker build -t "${img}" -f "${file}" .
  docker push "${img}"
done
