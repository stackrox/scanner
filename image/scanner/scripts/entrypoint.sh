#!/bin/sh

set -xeuo pipefail

find /.init-dirs -ls || true
find /etc/pki/ca-trust -ls || true
find /etc/ssl/certs -ls || true

/restore-all-dir-contents
/import-additional-cas
/trust-root-ca

exec /scanner
