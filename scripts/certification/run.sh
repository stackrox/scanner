#!/bin/bash

function cli() {
  if [[ -z $ROX_API_TOKEN ]]; then
    roxctl --insecure-skip-tls-verify -e localhost:8000 -p $(gpp) $@
  else
    roxctl --insecure-skip-tls-verify -e localhost:8000 $@
  fi
}

function jq_csv() {
  jq -r '.scan.components[]? | { name: .name, version: .version, vulns: .vulns[]? | { cve: .cve, cvss: .cvss, fixedBy: .fixedBy, link: .link, severity: .severity } | flatten } | flatten | @csv'
}

images=("stackrox/sandbox:nodejs-10" "stackrox/sandbox:jenkins-agent-maven-35-rhel7")
names=("nodejs" "jenkins")

i=0
for img in ${images[@]}; do
  name=${names[i]}
  cli image scan -i $img | jq_csv > output.csv
  python to_csv.py output.csv "$name".csv
  rm output.csv
  i=$((i+1))
done
