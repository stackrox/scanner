#!/bin/sh

set -euo pipefail

/restore-all-dir-contents
/import-additional-cas
/trust-root-ca

exec /scanner
