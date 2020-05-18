#!/bin/sh

set -e

/restore-all-dir-contents
/import-additional-cas

# Trust our own CA
cp /run/secrets/stackrox.io/certs/ca.pem /etc/ssl/certs/ca.pem

exec /scanner
