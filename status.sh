#!/bin/sh

echo "STABLE_SCANNER_VERSION $(make --quiet --no-print-directory tag)"
echo "STABLE_GIT_SHORT_SHA $(git rev-parse --short HEAD)"
echo "BUILD_TIMESTAMP $(date '+%s')"
