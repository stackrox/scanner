#!/bin/sh

set -e

/restore-all-dir-contents
/import-additional-cas
/trust-root-ca

exec /scanner
