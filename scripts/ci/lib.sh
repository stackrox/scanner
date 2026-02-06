#!/usr/bin/env bash

# A library of CI related reusable bash functions
# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/lib.sh

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
# shellcheck source=../../scripts/lib.sh
source "$SCRIPTS_ROOT/scripts/lib.sh"

set -euo pipefail

ensure_CI() {
    if ! is_CI; then
        die "A CI environment is required."
    fi
}

# ci_export is a wrapper around cci-export which persists exported variables
# between bash processes.
ci_export() {
    if [[ "$#" -ne 2 ]]; then
        die "missing args. usage: ci_export <env-name> <env-value>"
    fi

    local env_name="$1"
    local env_value="$2"

    if command -v cci-export >/dev/null; then
        cci-export "$env_name" "$env_value"
    else
        export "$env_name"="$env_value"
    fi
}

ci_exit_trap() {
    local exit_code="$?"
    info "Executing a general purpose exit trap for CI"
    echo "Exit code is: ${exit_code}"

    (send_slack_notice_for_failures_on_merge "${exit_code}") || { echo "ERROR: Could not slack a test failure message"; }

    while [[ -e /tmp/hold ]]; do
        info "Holding this job for debug"
        sleep 60
    done

    handle_dangling_processes
}

# handle_dangling_processes() - The OpenShift CI ci-operator will not complete a
# test job if there are processes remaining that were started by the job. While
# processes _should_ be cleaned up by their creators it is common that some are
# not, so this exists as a fail safe.
handle_dangling_processes() {
    if ! command -v ps >/dev/null; then
        return 0
    fi

    info "Process state at exit:"
    ps -e -O ppid

    local psline this_pid pid
    ps -e -O ppid | while read -r psline; do
        # trim leading whitespace
        psline="$(echo "$psline" | xargs)"
        if [[ "$psline" =~ ^PID ]]; then
            # Ignoring header
            continue
        fi
        this_pid="$$"
        if [[ "$psline" =~ ^$this_pid ]]; then
            echo "Ignoring self: $psline"
            continue
        fi
        # shellcheck disable=SC1087
        if [[ "$psline" =~ [[:space:]]$this_pid[[:space:]] ]]; then
            echo "Ignoring child: $psline"
            continue
        fi
        if [[ "$psline" =~ entrypoint|defunct ]]; then
            echo "Ignoring ci-operator entrypoint or defunct process: $psline"
            continue
        fi
        echo "A candidate to kill: $psline"
        pid="$(echo "$psline" | cut -d' ' -f1)"
        echo "Will kill $pid"
        kill "$pid" || {
            echo "Error killing $pid"
        }
    done
}

create_exit_trap() {
    trap ci_exit_trap EXIT
}

push_scanner_image_manifest_lists() {
    info "Pushing scanner and scanner-db images as manifest lists"

    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: push_scanner_image_manifest_lists <architectures (CSV)>"
    fi

    local architectures="$1"
    local scanner_image_set=("scanner" "scanner-db" "scanner-slim" "scanner-db-slim")
    local registries=("quay.io/rhacs-eng" "quay.io/stackrox-io")

    local tag
    tag="$(make --quiet --no-print-directory tag)"
    for registry in "${registries[@]}"; do
        registry_rw_login "$registry"
        for image in "${scanner_image_set[@]}"; do
            retry 5 true \
              "$SCRIPTS_ROOT/scripts/ci/push-as-multiarch-manifest-list.sh" "${registry}/${image}:${tag}" "$architectures" | cat
        done
    done
}

push_scanner_image_set() {
    info "Pushing scanner and scanner-db images"

    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: push_scanner_image_set <arch>"
    fi

    local arch="$1"

    local scanner_image_set=("scanner" "scanner-db" "scanner-slim" "scanner-db-slim")

    _push_scanner_image_set() {
        local registry="$1"
        local tag="$2"

        for image in "${scanner_image_set[@]}"; do
            retry 5 true \
              docker push "${registry}/${image}:${tag}" | cat
        done
    }

    _tag_scanner_image_set() {
        local local_tag="$1"
        local registry="$2"
        local remote_tag="$3"

        for image in "${scanner_image_set[@]}"; do
            docker tag "stackrox/${image}:${local_tag}" "${registry}/${image}:${remote_tag}"
        done
    }

    local registries=("quay.io/rhacs-eng" "quay.io/stackrox-io")

    local tag
    tag="$(make --quiet --no-print-directory tag)"
    for registry in "${registries[@]}"; do
        registry_rw_login "$registry"

        _tag_scanner_image_set "$tag" "$registry" "$tag-$arch"
        _push_scanner_image_set "$registry" "$tag-$arch"
    done
}

registry_rw_login() {
    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: registry_rw_login <registry>"
    fi

    local registry="$1"

    case "$registry" in
        quay.io/rhacs-eng)
            docker login -u "$QUAY_RHACS_ENG_RW_USERNAME" --password-stdin <<<"$QUAY_RHACS_ENG_RW_PASSWORD" quay.io
            ;;
        quay.io/stackrox-io)
            docker login -u "$QUAY_STACKROX_IO_RW_USERNAME" --password-stdin <<<"$QUAY_STACKROX_IO_RW_PASSWORD" quay.io
            ;;
        *)
            die "Unsupported registry login: $registry"
    esac
}

oc_image_mirror() {
    retry 5 true oc image mirror "$1" "$2"
}

poll_for_system_test_images() {
    info "Polling for images required for system tests"

    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: poll_for_system_test_images <seconds to wait>"
    fi

    local time_limit="$1"

    local tag
    tag="$(make --quiet tag)"
    local start_time
    start_time="$(date '+%s')"

    _image_exists() {
        local name="$1"
        local url="https://quay.io/api/v1/repository/stackrox-io/$name/tag?specificTag=$tag"
        info "Checking for $name using $url"
        local check
        check=$(curl --location -sS "$url")
        echo "$check"
        [[ "$(jq -r '.tags | first | .name' <<<"$check")" == "$tag" ]]
    }

    while true; do
        ### MODIFIED - Replaced with Scanner-related images
        if _image_exists "scanner" && _image_exists "scanner-db" && _image_exists "scanner-slim" && _image_exists "scanner-db-slim"; then
            info "All images exist"
            break
        fi
        if (( $(date '+%s') - start_time > time_limit )); then
           die "Timed out waiting for images after ${time_limit} seconds"
        fi
        sleep 60
    done
}

is_tagged() {
    local tags
    tags="$(git tag --contains)"
    [[ -n "$tags" ]]
}

is_nightly_run() {
    [[ "${NIGHTLY_TAG:-}" =~ -nightly- ]]
}

is_in_PR_context() {
    if is_GITHUB_ACTIONS && [[ -n "${GITHUB_BASE_REF:-}" ]]; then
        return 0
    elif is_OPENSHIFT_CI && [[ -n "${PULL_NUMBER:-}" ]]; then
        return 0
    elif is_OPENSHIFT_CI && [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
        # bin, test-bin, images
        local pull_request
        pull_request=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].number' 2>&1) || return 1
        [[ "$pull_request" =~ ^[0-9]+$ ]] && return 0
    fi

    return 1
}

get_PR_number() {
    if is_OPENSHIFT_CI && [[ -n "${PULL_NUMBER:-}" ]]; then
        echo "${PULL_NUMBER}"
        return 0
    elif is_OPENSHIFT_CI && [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
        # bin, test-bin, images
        local pull_request
        pull_request=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].number' 2>&1) || {
            echo 2>&1 "ERROR: Could not determine a PR number"
            return 1
        }
        if [[ "$pull_request" =~ ^[0-9]+$ ]]; then
            echo "$pull_request"
            return 0
        fi
    fi

    echo 2>&1 "ERROR: Could not determine a PR number"

    return 1
}

is_openshift_CI_rehearse_PR() {
    [[ "$(get_repo_full_name)" == "openshift/release" ]]
}

get_base_ref() {
    if is_OPENSHIFT_CI; then
        if [[ -n "${PULL_BASE_REF:-}" ]]; then
            # presubmit, postsubmit and batch runs
            # (ref: https://github.com/kubernetes/test-infra/blob/master/prow/jobs.md#job-environment-variables)
            echo "${PULL_BASE_REF}"
        elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
            # periodics - CLONEREFS_OPTIONS exists in binary_build_commands and images.
            local base_ref
            base_ref="$(jq -r <<<"${CLONEREFS_OPTIONS}" '.refs[0].base_ref')" || die "invalid CLONEREFS_OPTIONS yaml"
            if [[ "$base_ref" == "null" ]]; then
                die "expect: base_ref in CLONEREFS_OPTIONS.refs[0]"
            fi
            echo "${base_ref}"
        else
            die "Expect PULL_BASE_REF or CLONEREFS_OPTIONS"
        fi
    elif is_GITHUB_ACTIONS; then
        # GITHUB_BASE_REF is only set for PRs. Use GITHUB_REF_NAME for Prow's PULL_BASE_REF equivalent.
        if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
            echo "${GITHUB_REF_NAME}"
        else
            die "Expect GITHUB_REF_NAME"
        fi
    else
        die "unsupported"
    fi
}

get_repo_full_name() {
    if is_OPENSHIFT_CI; then
        if [[ -n "${REPO_OWNER:-}" ]]; then
            # presubmit, postsubmit and batch runs
            # (ref: https://github.com/kubernetes/test-infra/blob/master/prow/jobs.md#job-environment-variables)
            [[ -n "${REPO_NAME:-}" ]] || die "expect: REPO_NAME"
            echo "${REPO_OWNER}/${REPO_NAME}"
        elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
            # periodics - CLONEREFS_OPTIONS exists in binary_build_commands and images.
            local org
            local repo
            org="$(jq -r <<<"${CLONEREFS_OPTIONS}" '.refs[0].org')" || die "invalid CLONEREFS_OPTIONS yaml"
            repo="$(jq -r <<<"${CLONEREFS_OPTIONS}" '.refs[0].repo')" || die "invalid CLONEREFS_OPTIONS yaml"
            if [[ "$org" == "null" ]] || [[ "$repo" == "null" ]]; then
                die "expect: org and repo in CLONEREFS_OPTIONS.refs[0]"
            fi
            echo "${org}/${repo}"
        else
            die "Expect REPO_OWNER/NAME or CLONEREFS_OPTIONS"
        fi
    else
        die "unsupported"
    fi
}

pr_has_label() {
    if [[ -z "${1:-}" ]]; then
        die "usage: pr_has_label <expected label> [<pr details>]"
    fi

    local expected_label="$1"
    local pr_details
    local exitstatus=0
    pr_details="${2:-$(get_pr_details)}" || exitstatus="$?"
    if [[ "$exitstatus" != "0" ]]; then
        info "Warning: checking for a label in a non PR context"
        false
    fi
    jq '([.labels | .[].name]  // []) | .[]' -r <<<"$pr_details" | grep -qx "${expected_label}"
}

# get_pr_details() from GitHub and display the result. Exits 1 if not run in CI in a PR context.
_PR_DETAILS=""
_PR_DETAILS_CACHE_FILE="/tmp/PR_DETAILS_CACHE.json"
get_pr_details() {
    local pull_request
    local org
    local repo

    if [[ -n "${_PR_DETAILS}" ]]; then
        echo "${_PR_DETAILS}"
        return 0
    fi
    if [[ -e "${_PR_DETAILS_CACHE_FILE}" ]]; then
        _PR_DETAILS="$(cat "${_PR_DETAILS_CACHE_FILE}")"
        echo "${_PR_DETAILS}"
        return 0
    fi

    _not_a_PR() {
        echo "This does not appear to be a PR context" >&2
        echo '{ "msg": "this is not a PR" }'
        exit 1
    }

    if is_OPENSHIFT_CI; then
        if [[ -n "${JOB_SPEC:-}" ]]; then
            pull_request=$(jq -r <<<"$JOB_SPEC" '.refs.pulls[0].number')
            org=$(jq -r <<<"$JOB_SPEC" '.refs.org')
            repo=$(jq -r <<<"$JOB_SPEC" '.refs.repo')
        elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
            pull_request=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].number')
            org=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].org')
            repo=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].repo')
        else
            echo "Expect a JOB_SPEC or CLONEREFS_OPTIONS" >&2
            exit 2
        fi
        [[ "${pull_request}" == "null" ]] && _not_a_PR
    elif is_GITHUB_ACTIONS; then
        pull_request="$(jq -r .pull_request.number "${GITHUB_EVENT_PATH}")" || _not_a_PR
        [[ "${pull_request}" == "null" ]] && _not_a_PR
        org="${GITHUB_REPOSITORY_OWNER}"
        repo="${GITHUB_REPOSITORY#*/}"
    else
        echo "Unsupported CI" >&2
        exit 2
    fi

    local headers url pr_details

    headers=()
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        headers+=(-H "Authorization: token ${GITHUB_TOKEN}")
    fi

    url="https://api.github.com/repos/${org}/${repo}/pulls/${pull_request}"

    if ! pr_details=$(curl --retry 5 -sS "${headers[@]}" "${url}"); then
        echo "Github API error: $pr_details, exit code: $?" >&2
        exit 2
    fi

    if [[ "$(jq .id <<<"$pr_details")" == "null" ]]; then
        # A valid PR response is expected at this point
        echo "Invalid response from GitHub: $pr_details" >&2
        exit 2
    fi
    _PR_DETAILS="$pr_details"
    echo "$pr_details" | tee "${_PR_DETAILS_CACHE_FILE}"
}

GATE_JOBS_CONFIG="$SCRIPTS_ROOT/scripts/ci/gate-jobs-config.json"

gate_job() {
    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: gate_job <job>"
    fi

    local job="$1"
    local job_config
    job_config="$(jq -r .\""$job"\" "$GATE_JOBS_CONFIG")"

    info "Will determine whether to run: $job"

    # TODO(RS-509) remove once this behaves better
    if [[ "$job_config" == "null" ]]; then
        info "$job will run because there is no gating criteria for $job"
        return
    fi

    local pr_details
    local exitstatus=0
    pr_details="$(get_pr_details)" || exitstatus="$?"

    if [[ "$exitstatus" == "0" ]]; then
        if is_openshift_CI_rehearse_PR; then
            gate_openshift_release_rehearse_job "$job" "$pr_details"
        else
            gate_pr_job "$job_config" "$pr_details"
        fi
    elif [[ "$exitstatus" == "1" ]]; then
        gate_merge_job "$job_config"
    else
        die "Could not determine if this is a PR versus a merge"
    fi
}

get_var_from_job_config() {
    local var_name="$1"
    local job_config="$2"

    local value
    value="$(jq -r ."$var_name" <<<"$job_config")"
    if [[ "$value" == "null" ]]; then
        die "$var_name is not defined in this jobs config"
    fi
    if [[ "${value:0:1}" == "[" ]]; then
        value="$(jq -cr '.[]' <<<"$value")"
    fi
    echo "$value"
}

gate_pr_job() {
    local job_config="$1"
    local pr_details="$2"

    local run_with_labels=()
    local skip_with_label
    local run_with_changed_path
    local changed_path_to_ignore
    local run_with_labels_from_json
    run_with_labels_from_json="$(get_var_from_job_config run_with_labels "$job_config")"
    if [[ -n "${run_with_labels_from_json}" ]]; then
        mapfile -t run_with_labels <<<"${run_with_labels_from_json}"
    fi
    skip_with_label="$(get_var_from_job_config skip_with_label "$job_config")"
    run_with_changed_path="$(get_var_from_job_config run_with_changed_path "$job_config")"
    changed_path_to_ignore="$(get_var_from_job_config changed_path_to_ignore "$job_config")"

    if [[ -n "$skip_with_label" ]]; then
        if pr_has_label "${skip_with_label}" "${pr_details}"; then
            info "$job will not run because the PR has label $skip_with_label"
            exit 0
        fi
    fi

    for run_with_label in "${run_with_labels[@]}"; do
        if pr_has_label "${run_with_label}" "${pr_details}"; then
            info "$job will run because the PR has label $run_with_label"
            return
        fi
    done

    if [[ -n "${run_with_changed_path}" || -n "${changed_path_to_ignore}" ]]; then
        local diff_base
        if is_OPENSHIFT_CI; then
            if [[ -n "${PULL_BASE_SHA:-}" ]]; then
                diff_base="${PULL_BASE_SHA:-}"
            else
                diff_base="$(jq -r '.refs[0].base_sha' <<<"$CLONEREFS_OPTIONS")"
            fi
            echo "Determined diff-base as ${diff_base}"
            [[ "${diff_base}" != "null" ]] || die "Could not find base_sha in PULL_BASE_SHA nor CLONEREFS_OPTIONS"
        else
            die "unsupported"
        fi
        echo "Diffbase diff:"
        { git diff --name-only "${diff_base}" | cat ; } || true
        # TODO(RS-509) remove once this behaves better
        ignored_regex="${changed_path_to_ignore}"
        [[ -n "$ignored_regex" ]] || ignored_regex='$^' # regex that matches nothing
        match_regex="${run_with_changed_path}"
        [[ -n "$match_regex" ]] || match_regex='^.*$' # grep -E -q '' returns 0 even on empty input, so we have to specify some pattern
        if grep -E -q "$match_regex" < <({ git diff --name-only "${diff_base}" || echo "???" ; } | grep -E -v "$ignored_regex"); then
            info "$job will run because paths matching $match_regex (and not matching ${ignored_regex}) had changed."
            return
        fi
    fi

    info "$job will be skipped"
    exit 0
}

gate_merge_job() {
    local job_config="$1"

    local run_on_master
    local run_on_tags
    run_on_master="$(get_var_from_job_config run_on_master "$job_config")"
    run_on_tags="$(get_var_from_job_config run_on_tags "$job_config")"

    local base_ref
    base_ref="$(get_base_ref)" || {
        info "Warning: error running get_base_ref():"
        echo "${base_ref}"
        info "will continue with tests."
    }

    if [[ "${base_ref}" == "master" && "${run_on_master}" == "true" ]]; then
        info "$job will run because this is master and run_on_master==true"
        return
    fi

    if is_tagged && [[ "${run_on_tags}" == "true" ]]; then
        info "$job will run because the head of this branch is tagged and run_on_tags==true"
        return
    fi

    info "$job will be skipped - neither master/run_on_master or tagged/run_on_tags"
    exit 0
}

# gate_openshift_release_rehearse_job() - use the PR description to indicate if
# the pj-rehearse job should run for configured jobs.
gate_openshift_release_rehearse_job() {
    local job="$1"
    local pr_details="$2"

    if [[ "$(jq -r '.body' <<<"$pr_details")" =~ open.the.gate.*$job ]]; then
        info "$job will run because the gate was opened"
        return
    fi

    cat << _EOH_
$job will be skipped. If you want to run a gated job during openshift/release pj-rehearsal
update the PR description with:
open the gate: $job
_EOH_
    exit 0
}

openshift_ci_mods() {
    info "BEGIN OpenShift CI mods"

    info "Env A-Z dump:"
    env | sort | grep -E '^[A-Z]' || true

    ensure_writable_home_dir

    # Prevent "detected dubious ownership in repository" errors introduced in
    # Git 2.28.0.  This message appears when the ownership of a repository is
    # not clear.
    git config --global --add safe.directory "$(pwd)"

    info "Git log:"
    git log --oneline --decorate -n 20 || true

    info "Recent git refs:"
    git for-each-ref --format='%(creatordate) %(refname)' --sort=creatordate | tail -20

    info "Current Status:"
    "$ROOT/status.sh" || true

    # For ci_export(), override BASH_ENV from stackrox-test with something that is writable.
    BASH_ENV=$(mktemp)
    export BASH_ENV
    info "BASH_ENV is now ${BASH_ENV}"

    # These are not set in the binary_build_commands or image build envs.
    export CI=true
    export OPENSHIFT_CI=true

    if is_in_PR_context && ! is_openshift_CI_rehearse_PR; then
        local sha
        if [[ -n "${PULL_PULL_SHA:-}" ]]; then
            sha="${PULL_PULL_SHA}"
        else
            sha=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].pulls[0].sha') || warn "Cannot find pull sha"
        fi
        if [[ -n "${sha:-}" ]] && [[ "$sha" != "null" ]]; then
            info "Will checkout SHA to match PR: $sha"
            git checkout "$sha"
        else
            warn "Could not determine a SHA for this PR, ${sha:-}"
        fi
    fi

    handle_nightly_runs

    handle_release_runs

    info "Status after mods:"
    "$ROOT/status.sh" || true

    info "END OpenShift CI mods"
}

ensure_writable_home_dir() {
    # Single step test jobs do not have HOME
    if [[ -z "${HOME:-}" ]] || ! touch "${HOME}/openshift-ci-write-test"; then
        info "HOME (${HOME:-unset}) is not set or not writeable, using mktemp dir"
        HOME=$( mktemp -d )
        export HOME
        info "HOME is now $HOME"
    fi
}

openshift_ci_import_creds() {
    shopt -s nullglob
    for cred in /tmp/secret/**/[A-Z]*; do
        export "$(basename "$cred")"="$(cat "$cred")"
    done
    for cred in /tmp/vault/**/[A-Z]*; do
        export "$(basename "$cred")"="$(cat "$cred")"
    done
}

unset_namespace_env_var() {
    # NAMESPACE is injected by OpenShift CI for the cluster that is running the
    # tests but this can have side effects for scanner tests due to its use as
    # the default namespace e.g. with helm.
    if [[ -n "${NAMESPACE:-}" ]]; then
        export OPENSHIFT_CI_NAMESPACE="$NAMESPACE"
        unset NAMESPACE
    fi
}

openshift_ci_e2e_mods() {
    unset_namespace_env_var

    # The incoming KUBECONFIG is for the openshift/release cluster and not the
    # e2e test cluster.
    if [[ -n "${KUBECONFIG:-}" ]]; then
        info "There is an incoming KUBECONFIG in ${KUBECONFIG}"
        export OPENSHIFT_CI_KUBECONFIG="$KUBECONFIG"
    fi
    KUBECONFIG="$(mktemp)"
    info "KUBECONFIG set: ${KUBECONFIG}"
    export KUBECONFIG

    # KUBERNETES_{PORT,SERVICE} env values interact with commandline kubectl tests
    if env | grep -e ^KUBERNETES_; then
        local envfile
        envfile="$(mktemp)"
        info "Will clear ^KUBERNETES_ env"
        env | grep -e ^KUBERNETES_ | cut -d= -f1 | awk '{ print "unset", $1 }' > "$envfile"
        # shellcheck disable=SC1090
        source "$envfile"
    fi
}

handle_nightly_runs() {
    if ! is_OPENSHIFT_CI; then
        die "Only for OpenShift CI"
    fi

    local nightly_tag_prefix
    nightly_tag_prefix="$(git describe --tags --abbrev=0 --exclude '*-nightly-*')-nightly-"
    if ! is_in_PR_context && [[ "${JOB_NAME_SAFE:-}" =~ ^nightly- ]]; then
        ci_export NIGHTLY_TAG "${nightly_tag_prefix}$(date '+%Y%m%d')"
    fi
}

handle_release_runs() {
    if ! is_OPENSHIFT_CI; then
        die "Only for OpenShift CI"
    fi

    local base_ref
    base_ref="$(get_base_ref)"
    if is_tagged && [[ "$base_ref" =~ ^release- ]]; then
        ci_export RELEASE_TAG "$(git tag --sort=creatordate --contains | tail -1)"
    fi
}

handle_gha_tagged_build() {
  if [[ -z "${GITHUB_REF:-}" ]]; then
        echo "No GITHUB_REF in env"
        exit 0
    fi
    echo "GITHUB_REF: ${GITHUB_REF}"
    if [[ "${GITHUB_REF:-}" =~ ^refs/tags/ ]]; then
        tag="${GITHUB_REF#refs/tags/*}"
        echo "This is a tagged build: $tag"
        echo "RELEASE_TAG=$tag" >> "$GITHUB_ENV"
    else
        echo "This is not a tagged build"
    fi
}

store_test_results() {
    if [[ "$#" -ne 2 ]]; then
        die "missing args. usage: store_test_results <from> <to>"
    fi

    if ! is_OPENSHIFT_CI; then
        return
    fi

    local from="$1"
    local to="$2"

    info "Copying test results from $from to $to"

    local dest="${ARTIFACT_DIR}/$to"

    cp -a "$from" "$dest" || true # (best effort)
}

send_slack_notice_for_failures_on_merge() {
    local exitstatus="${1:-}"

    if ! is_OPENSHIFT_CI || [[ "$exitstatus" == "0" ]] || is_in_PR_context || is_nightly_run; then
        return 0
    fi

    local tag
    tag="$(make --quiet tag)"
    if [[ "$tag" =~ $RELEASE_RC_TAG_BASH_REGEX ]]; then
        return 0
    fi

    local webhook_url="${TEST_FAILURES_NOTIFY_WEBHOOK}"

    if [[ -n "${JOB_SPEC:-}" ]]; then
        org=$(jq -r <<<"$JOB_SPEC" '.refs.org')
        repo=$(jq -r <<<"$JOB_SPEC" '.refs.repo')
    elif [[ -n "${CLONEREFS_OPTIONS:-}" ]]; then
        org=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].org')
        repo=$(jq -r <<<"$CLONEREFS_OPTIONS" '.refs[0].repo')
    else
        echo "Expect a JOB_SPEC or CLONEREFS_OPTIONS"
        return 1
    fi
    [[ "$org" != "null" ]] && [[ "$repo" != "null" ]] || return 1
    local commit_details_url="https://api.github.com/repos/${org}/${repo}/commits/${OPENSHIFT_BUILD_COMMIT}"
    local commit_details
    commit_details=$(curl --retry 5 -sS "${commit_details_url}") || return 1

    local job_name="${JOB_NAME_SAFE#merge-}"

    local commit_msg
    commit_msg=$(jq -r <<<"$commit_details" '.commit.message') || return 1
    commit_msg="${commit_msg%%$'\n'*}" # use first line of commit msg
    local commit_url
    commit_url=$(jq -r <<<"$commit_details" '.html_url') || return 1
    local author
    author=$(jq -r <<<"$commit_details" '.commit.author.name') || return 1
    [[ "$commit_msg" != "null" ]] && [[ "$commit_url" != "null" ]] && [[ "$author" != "null" ]] || return 1

    local log_url="https://prow.ci.openshift.org/view/gs/origin-ci-test/logs/${JOB_NAME}/${BUILD_ID}"

    # shellcheck disable=SC2016
    local body='
{
    "text": "*Job Name:* \($job_name)",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Prow job failure: \($job_name)"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Commit:* <\($commit_url)|\($commit_msg)>\n*Repo:* \($repo)\n*Author:* \($author)\n*Log:* \($log_url)"
            }
        },
        {
          "type": "divider"
        }
    ]
}
'

    echo "About to post:"
    jq --null-input --arg job_name "$job_name" --arg commit_url "$commit_url" --arg commit_msg "$commit_msg" \
       --arg repo "$repo" --arg author "$author" --arg log_url "$log_url" "$body"

    jq --null-input --arg job_name "$job_name" --arg commit_url "$commit_url" --arg commit_msg "$commit_msg" \
       --arg repo "$repo" --arg author "$author" --arg log_url "$log_url" "$body" | \
    curl -XPOST -d @- -H 'Content-Type: application/json' "$webhook_url"
}

send_slack_notice_for_vuln_check_failure() {
    if ! is_OPENSHIFT_CI && ! is_GITHUB_ACTIONS; then
        return 0
    fi

    require_environment "SLACK_WEBHOOK_ONCALL"
    local webhook_url="${SLACK_WEBHOOK_ONCALL}"

    local repo="scanner"
    local job_name="sanity-check-vuln-updates"
    local mentions="@acs-scanner-primary"
    local log_url="https://prow.ci.openshift.org/view/gs/origin-ci-test/logs/${JOB_NAME}/${BUILD_ID}"

    # shellcheck disable=SC2016
    local body='
{
    "text": "*Job Name:* \($job_name)",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Prow job failure: \($job_name)"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Repo:* \($repo)\n*Log:* \($log_url)\n*Mentions:* \($mentions)"
            }
        },
        {
            "type": "divider"
        }
    ]
}
'

    echo "About to post:"
    jq --null-input --arg job_name "$job_name" --arg repo "$repo" \
       --arg log_url "$log_url" --arg mentions "$mentions" "$body"

    jq --null-input --arg job_name "$job_name" --arg repo "$repo" \
       --arg log_url "$log_url" --arg mentions "$mentions" "$body" | \
    curl -XPOST -d @- -H 'Content-Type: application/json' "$webhook_url"
}

generate_genesis_dump() {
    info "Generating genesis dump"
    mkdir -p /tmp/genesis-dump
    bin/updater generate-dump --out-file /tmp/genesis-dump/genesis-dump.zip
    ls -lrt /tmp/genesis-dump

    info "Printing some stats"
    bin/updater print-stats /tmp/genesis-dump/genesis-dump.zip

    info "Extracting dumps"
    mkdir -p /tmp/vuln-dump
    zip /tmp/genesis-dump/genesis-dump.zip 'nvd/*' --copy --out /tmp/vuln-dump/nvd-definitions.zip
    zip /tmp/genesis-dump/genesis-dump.zip 'k8s/*' --copy --out /tmp/vuln-dump/k8s-definitions.zip
    zip /tmp/genesis-dump/genesis-dump.zip 'istio/*' --copy --out /tmp/vuln-dump/istio-definitions.zip
    zip /tmp/genesis-dump/genesis-dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/vuln-dump/repo2cpe.zip
}

get_genesis_dump() {
    info "Retrieving Genesis dump"

    ls -lrt /tmp/vuln-dump || info "No local genesis dump"

    if is_in_PR_context && ! pr_has_label "generate-dumps-on-pr"; then
        info "Label generate-dumps-on-pr not set. Pulling dumps from GCS bucket"
        mkdir -p /tmp/vuln-dump
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/nvd-definitions.zip /tmp/vuln-dump/nvd-definitions.zip
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/k8s-definitions.zip /tmp/vuln-dump/k8s-definitions.zip
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/istio-definitions.zip /tmp/vuln-dump/istio-definitions.zip
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/repo2cpe.zip /tmp/vuln-dump/repo2cpe.zip
    fi

    unzip -d image/scanner/dump /tmp/vuln-dump/nvd-definitions.zip
    unzip -d image/scanner/dump /tmp/vuln-dump/k8s-definitions.zip
    unzip -d image/scanner/dump /tmp/vuln-dump/istio-definitions.zip
    unzip -d image/scanner/dump /tmp/vuln-dump/repo2cpe.zip
}

generate_db_dump() {
    info "Generating DB dump"

    groupadd -g 1001 pg
    adduser pg -u 1001 -g 1001 -d /var/lib/postgresql -s /bin/sh

    # The PATH is not completely preserved, so set the PATH here to ensure postgres-related commands can be found.
    runuser -l pg -c "PATH=$PATH $SCRIPTS_ROOT/scripts/ci/postgres.sh start_postgres"

    # Configure PostgreSQL for bulk loading performance
    # These settings are safe for CI because:
    # - The database is temporary (destroyed after dump creation)
    # - Transaction commits ensure data visibility regardless of disk sync
    # - Any failure causes the entire CI job to fail
    info "Configuring PostgreSQL for bulk loading"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET fsync = off;"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET synchronous_commit = off;"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET full_page_writes = off;"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET maintenance_work_mem = '1GB';"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET max_wal_size = '2GB';"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET checkpoint_timeout = '30min';"
    psql -U postgres -h 127.0.0.1 -c "ALTER SYSTEM SET autovacuum = off;"
    psql -U postgres -h 127.0.0.1 -c "SELECT pg_reload_conf();"
    info "PostgreSQL configured for bulk loading"

    bin/updater load-dump --postgres-host 127.0.0.1 --postgres-port 5432 --dump-file /tmp/genesis-dump/genesis-dump.zip

    mkdir /tmp/postgres
    pg_dump -U postgres postgres://127.0.0.1:5432 > /tmp/postgres/pg-definitions.sql
    ls -lrt /tmp/postgres
    gzip --best /tmp/postgres/pg-definitions.sql
    ls -lrt /tmp/postgres
}

get_db_dump() {
    info "Retrieving DB dump"

    ls -lrt /tmp/postgres || info "No local DB dump"

    if is_in_PR_context && ! pr_has_label "generate-dumps-on-pr"; then
        info "Label generate-dumps-on-pr not set. Pulling dumps from GCS bucket"
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
    else
        cp /tmp/postgres/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "$#" -lt 1 ]]; then
        die "When invoked at the command line a method is required."
    fi
    fn="$1"
    shift
    "$fn" "$@"
fi
