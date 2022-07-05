#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/lib.sh"

# Set up GCP auth/config
require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"
setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"

"$ROOT/scripts/ci/sanity-check-vuln-updates.sh"
