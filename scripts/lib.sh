#!/usr/bin/env bash

set -euo pipefail

# A library of reusable bash functions

usage() {
    echo "lib.sh provides a library of reusable bash functions.
Invoke with:
  $ scripts/lib.sh method [args...]
Reuse with:
  . scripts/lib.sh
  method [args...]"
}

info() {
    echo "INFO: $(date): $*"
}

die() {
    echo >&2 "$@"
    exit 1
}

# Caution when editing: make sure groups would correspond to BASH_REMATCH use.
RELEASE_RC_TAG_BASH_REGEX='^([[:digit:]]+(\.[[:digit:]]+)*)(-rc\.[[:digit:]]+)?$'

is_release_version() {
    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: is_release_version <version>"
    fi
    [[ "$1" =~ $RELEASE_RC_TAG_BASH_REGEX && -z "${BASH_REMATCH[3]}" ]]
}

is_CI() {
    [[ "${CI:-}" == "true" ]]
}

is_CIRCLECI() {
    [[ "${CIRCLECI:-}" == "true" ]]
}

is_OPENSHIFT_CI() {
    [[ "${OPENSHIFT_CI:-}" == "true" ]]
}

is_darwin() {
    uname -a | grep -i darwin >/dev/null 2>&1
}

is_linux() {
    uname -a | grep -i linux >/dev/null 2>&1
}

require_environment() {
    if [[ "$#" -lt 1 ]]; then
        die "usage: require_environment NAME [reason]"
    fi

    (
        set +u
        if [[ -z "$(eval echo "\$$1")" ]]; then
            varname="$1"
            shift
            message="missing \"$varname\" environment variable"
            if [[ "$#" -gt 0 ]]; then
                message="$message: $*"
            fi
            die "$message"
        fi
    ) || exit 1
}

require_executable() {
    if [[ "$#" -lt 1 ]]; then
        die "usage: require_executable NAME [reason]"
    fi

    if ! command -v "$1" >/dev/null 2>&1; then
        varname="$1"
        shift
        message="missing \"$varname\" executable"
        if [[ "$#" -gt 0 ]]; then
            message="$message: $*"
        fi
        die "$message"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        usage
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
