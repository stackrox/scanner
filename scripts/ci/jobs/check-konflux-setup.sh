#!/usr/bin/env bash

# This script is to validate our Konflux setup.
# The script was adapted from the one in the StackRox repo.
# See https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/check-konflux-setup.sh

set -euo pipefail

FAIL_FLAG="$(mktemp)"
trap 'rm -f $FAIL_FLAG' EXIT

check_testdata_files_are_ignored() {
    # At the time of this writing, Konflux uses syft to generate SBOMs for built containers.
    # If we happen to have test rpmdb databases in the repo, syft will union their contents with RPMs that it finds
    # installed in the container resulting in a misleading SBOM.
    # An rpmdb located in ./pkg/rhelv2/rpm/testdata/rpmdb.sqlite and other files follow the similar pattern: they reside
    # in directories called `testdata`. This check is to make sure all `testdata` directories are in syft's exlude list.

    local -r syft_config=".syft.yaml"
    local -r exclude_attribute=".exclude"

    local actual_excludes
    actual_excludes="$(yq eval "${exclude_attribute}" "${syft_config}")"

    local expected_excludes
    expected_excludes="$(git ls-files -- '**/testdata/**' | sed 's@/testdata/.*$@/testdata/**@' | sort | uniq | sed 's/^/- .\//')"

    echo
    echo "➤ ${syft_config} // checking ${exclude_attribute}: all testdata files in the repo shall be mentioned."
    if ! compare "${expected_excludes}" "${actual_excludes}"; then
        echo >&2 "How to resolve:
1. Open ${syft_config} and replace ${exclude_attribute} contents with the following.
${expected_excludes}"
        record_failure "${FUNCNAME}"
    fi
}

compare() {
    local -r expected="$1"
    local -r actual="$2"

    if ! diff --brief <(echo "${expected}") <(echo "${actual}") > /dev/null; then
        echo >&2 "✗ ERROR: the expected contents (left) don't match the actual ones (right):"
        diff >&2 --side-by-side <(echo "${expected}") <(echo "${actual}") || true
        return 1
    else
        echo "✓ No diff detected."
    fi
}

record_failure() {
    local -r func="$1"
    echo "${func}" >> "${FAIL_FLAG}"
}

echo "Checking our Konflux pipelines and builds setup."
check_testdata_files_are_ignored

if [[ -s "$FAIL_FLAG" ]]; then
    echo >&2
    echo >&2 "✗ Some Konflux checks failed:"
    cat >&2 "$FAIL_FLAG"
    exit 1
else
    echo
    echo "✓ All checks passed."
fi
