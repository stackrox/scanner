#!/bin/sh

set -e

/restore-all-dir-contents
/import-additional-cas

exec /scanner
