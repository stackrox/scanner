#!/usr/bin/env bash

set -euo pipefail

# Pull the vulnerability definitions data from a GCS bucket, if the "generate-dumps-on-pr" label is set.
# If it's not set, then local definitions stored in /tmp are used.
# Files are written to image/scanner/dump.

set +u
SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
set -u

source "$SCRIPTS_ROOT/scripts/ci/lib.sh"

require_executable "gsutil"

if pr_has_label "generate-dumps-on-pr"; then
    echo "Label generate-dumps-on-pr not set. Pulling dumps from GCS bucket"
    gsutil cp gs://stackrox-scanner-ci-vuln-dump/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
    gsutil cp gs://stackrox-scanner-ci-vuln-dump/nvd-definitions.zip /tmp/nvd-definitions.zip
    gsutil cp gs://stackrox-scanner-ci-vuln-dump/k8s-definitions.zip /tmp/k8s-definitions.zip
    gsutil cp gs://stackrox-scanner-ci-vuln-dump/repo2cpe.zip /tmp/repo2cpe.zip
else
    cp /tmp/postgres/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
    zip /tmp/genesis-dump/dump.zip 'nvd/*' --copy --out /tmp/nvd-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'k8s/*' --copy --out /tmp/k8s-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/repo2cpe.zip
fi

unzip -d image/scanner/dump /tmp/nvd-definitions.zip
unzip -d image/scanner/dump /tmp/k8s-definitions.zip
unzip -d image/scanner/dump /tmp/repo2cpe.zip
