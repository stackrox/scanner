#!/usr/bin/env bash
#
# Setup:
#   pip install --upgrade cryptography gsutil google-cloud
#   gcloud components update
#
# Usage:
#   ./sanity-check-vuln-updates.sh [diff_id]
#
# Note:
#   This work was tracked in https://stack-rox.atlassian.net/browse/ROX-7271.
#   This test downloads ~500 MiB of vulnerability diffs with each run.
#   gsutil stat "gs://definitions.stackrox.io/*/diff.zip"
set -eu

function is_mac   { uname | grep -qi 'darwin'; }
function is_linux { uname | grep -qi 'linux'; }

function manual_repro_check {
  local diff_id=${1:-e8f8b9ab-6a75-433a-8b86-15586ec41a7b}

  cf_url="https://definitions.stackrox.io/$diff_id/diff.zip"
  gcs_https_url="https://storage.googleapis.com/definitions.stackrox.io/$diff_id/diff.zip"
  gcs_gs_url="gs://definitions.stackrox.io/$diff_id/diff.zip"

  echo "diff_id => $diff_id"
  echo "cf_url => $cf_url"
  wget -q "$cf_url" && unzip -q -c diff.zip manifest.json | jq -cr '.' && rm -f diff.zip
  echo "gcs_https_url => $gcs_https_url"
  wget -q "$gcs_https_url" && unzip -q -c diff.zip manifest.json | jq -cr '.' && rm -f diff.zip
  echo "gcs_gs_url=> $gcs_gs_url"
  gsutil stat "$gcs_gs_url" | sed -Ene 's/^ +Update time: +(.*)/\1/p'
}

function parse_date_to_epoch_sec {
  local date_string date_format
  date_string=$1
  date_format=$2

  if is_linux; then
    date --date "$date_string" "+%s"
  elif is_mac; then
    date -j -f "$date_format" "$date_string" "+%s"
  fi
}

function get_manifest_content_from_zip {
  local fpath_zipfile=$1
  unzip -q -c "$fpath_zipfile" manifest.json || error "failed to unzip '$fpath_zipfile'"
}

function validate_manifest_until {
  if ! echo "$1" | grep -qE "^$DIGIT{4}-$DIGIT{2}-$DIGIT{2}T$DIGIT{2}:$DIGIT{2}:$DIGIT{2} GMT$"; then
    bash_exit_failure "BAD manifest_until value [$1]"
  fi
}

function validate_epoch_sec {
  if ! echo "$1" | grep -qE "^$DIGIT{10}$"; then
    bash_exit_failure "BAD epoch_sec value [$1]"
  fi
}

function validate_manifest_content {
  if ! echo "$1" | jq -r '.' &>/dev/null; then
    bash_exit_failure "BAD manifest_content [$1]"
  fi
}

function validate_integer {
  if ! echo "$1" | grep -qE "^$DIGIT+$"; then
    bash_exit_failure "BAD integer [$1]"
  fi
}

function get_manifest_age_seconds_from_zip {
  local fpath_zipfile manifest_content manifest_until manifest_until_epoch_sec now_epoch_sec age_seconds
  fpath_zipfile=$1

  manifest_content=$(get_manifest_content_from_zip "$fpath_zipfile")
  validate_manifest_content "$manifest_content"

  manifest_until=$(echo "$manifest_content" | jq -r ".until" | sed -Ee 's#\.[0-9]+Z# GMT#')
  validate_manifest_until "$manifest_until"

  manifest_until_epoch_sec=$(parse_date_to_epoch_sec "$manifest_until" "%Y-%M-%dT%H:%M:%S %Z")
  validate_epoch_sec "$manifest_until_epoch_sec"

  now_epoch_sec=$(date "+%s")
  validate_epoch_sec "$now_epoch_sec"

  age_seconds=$(( now_epoch_sec - manifest_until_epoch_sec ))
  validate_integer "$age_seconds"

  echo "$age_seconds"
}

function run_tests_for_diff_id {
  local DIFF_ID GCS_CONSOLE_URL DIFF1_CLOUDFLARE_URL DIFF2_GCS_URL

  DIFF_ID="$1"
  GCS_CONSOLE_URL="https://console.cloud.google.com/storage/browser/definitions.stackrox.io/$DIFF_ID"
  DIFF1_CLOUDFLARE_URL="https://definitions.stackrox.io/$DIFF_ID/diff.zip"
  DIFF2_GCS_URL="https://storage.googleapis.com/definitions.stackrox.io/$DIFF_ID/diff.zip"

  info "--------"
  info "DIFF_ID              => $DIFF_ID"
  info "GCS_CONSOLE_URL      => $GCS_CONSOLE_URL"
  info "DIFF1_CLOUDFLARE_URL => $DIFF1_CLOUDFLARE_URL"
  info "DIFF2_GCS_URL        => $DIFF2_GCS_URL"
  info "WORKING_DIR          => $WORKING_DIR"

  rm -f diff{1,2}.zip

  info "downloading diff1.zip from $DIFF1_CLOUDFLARE_URL"
  diff1_cache_control=$(curl -s -o ./diff1.zip -v "$DIFF1_CLOUDFLARE_URL" 2>&1 \
    | grep "cache-control" | sed -e "s#^< ##g; s#\r##g;") \
    || bash_exit_failure "curl failed on $DIFF1_CLOUDFLARE_URL"

  info "downloading diff2.zip from $DIFF2_GCS_URL"
  diff2_cache_control=$(curl -s -o ./diff2.zip -v "$DIFF2_GCS_URL" 2>&1 \
    | grep "cache-control" | sed -e "s#^< ##g; s#\r##g;") \
    || bash_exit_failure "curl failed on $DIFF2_GCS_URL"

  local gcs_object_age_seconds diff1_manifest_content diff2_manifest_content \
    diff1_manifest_age_seconds diff2_manifest_age_seconds diff1_archive_md5 \
    diff2_archive_md5

  gcs_object_age_seconds=$(get_gcs_object_age_seconds "$DIFF_ID")
  diff1_manifest_content=$(get_manifest_content_from_zip "diff1.zip")
  diff2_manifest_content=$(get_manifest_content_from_zip "diff2.zip")
  diff1_manifest_age_seconds=$(get_manifest_age_seconds_from_zip "diff1.zip")
  diff2_manifest_age_seconds=$(get_manifest_age_seconds_from_zip "diff2.zip")
  diff1_archive_md5=$(md5sum "diff1.zip" | cut -d" " -f1)
  diff2_archive_md5=$(md5sum "diff2.zip" | cut -d" " -f1)
  info "gcs_object_age_seconds     => $gcs_object_age_seconds"
  info "diff1_manifest_content     => $diff1_manifest_content"
  info "diff2_manifest_content     => $diff2_manifest_content"
  info "diff1_manifest_age_seconds => $diff1_manifest_age_seconds"
  info "diff2_manifest_age_seconds => $diff2_manifest_age_seconds"
  info "diff1_archive_md5          => $diff1_archive_md5"
  info "diff2_archive_md5          => $diff2_archive_md5"
  info "diff1_cache_control        => $diff1_cache_control"
  info "diff2_cache_control        => $diff2_cache_control"

  if [[ "$gcs_object_age_seconds" -gt "$MAX_GCS_OBJECT_AGE_SECONDS" ]]; then
    warn "gcs_object_age_seconds exceeds target"
  fi

  if [[ "$diff1_archive_md5" != "$diff2_archive_md5" ]]; then
    warn "(diff1_archive_md5 != diff2_archive_md5)"
  fi

  if [[ "$diff1_manifest_age_seconds" -gt "$MAX_MANIFEST_AGE_SECONDS" ]]; then
    testfail "diff1_manifest_age_seconds exceeds target"
  fi

  if [[ "$diff2_manifest_age_seconds" -gt "$MAX_MANIFEST_AGE_SECONDS" ]]; then
    testfail "diff2_manifest_age_seconds exceeds target"
  fi

  if [[ "$diff1_cache_control" != "cache-control: public, max-age=3600" ]]; then
    testfail "incorrect diff1_cache_control"
  fi

  if [[ "$diff2_cache_control" != "cache-control: public, max-age=3600" ]]; then
    testfail "incorrect diff2_cache_control"
  fi
}

function get_gcs_object_age_seconds {
  local diff_id created_time_raw created_time_epoch_sec now_epoch_sec obj_age_seconds

  diff_id="$1"
  created_time_raw=$(grep -A3 "$diff_id" "$FPATH_DIFF_GSUTIL_STAT" | sed -Ene 's/^ +Update time: +(.*)/\1/p')
  created_time_epoch_sec=$(parse_date_to_epoch_sec "$created_time_raw" "%a, %d %b %Y %H:%M:%S %Z")
  now_epoch_sec=$(date "+%s")
  obj_age_seconds=$(( now_epoch_sec - created_time_epoch_sec ))
  echo "$obj_age_seconds"
}

function info { >&2 echo "INFO: $*"; }
function warn { >&2 echo "WARN: $*"; }
function error { >&2 echo "ERROR: $*"; }
function testfail { >&2 echo "FAIL: $*"; (( FAILURE_COUNT += 1 )); }
function bash_true { ((0 == 0)); }
function bash_false { ((0 == 1)); }
function bash_exit_success { info "$@"; bash_true; exit $?; }
function bash_exit_failure { error "$@"; bash_false; exit $?; }


# __MAIN__
DIGIT="[[:digit:]]"
WORKING_DIR="/tmp/ROX-7271"
FPATH_DIFF_LIST="$WORKING_DIR/diff.txt"
FPATH_DIFF_ID_LIST="$WORKING_DIR/ids.txt"
FPATH_DIFF_GSUTIL_STAT="$WORKING_DIR/metadata.txt"
FPATH_TRANSCRIPT="$WORKING_DIR/transcript.txt"
MAX_GCS_OBJECT_AGE_SECONDS=$((4 * 3600))
MAX_MANIFEST_AGE_SECONDS=$((4 * 3600))
FAILURE_COUNT=0

# Initialize working dir
rm -rf "$WORKING_DIR"
mkdir -p "$WORKING_DIR"
cd "$WORKING_DIR"
exec > >(tee -i "$FPATH_TRANSCRIPT") 2>&1

# Construct the list of diffs to run tests against
if [[ $# -eq 1 ]]; then
  diff_id="$1"
  echo "gs://definitions.stackrox.io/$diff_id/diff.zip" > "$FPATH_DIFF_LIST"
else
  gsutil ls -r "gs://definitions.stackrox.io/*/diff.zip" > "$FPATH_DIFF_LIST"
fi

# Extract the ids (uniquely identifying hashes)
sed -Ee "s#gs://definitions.stackrox.io/##g; s#/diff.zip##g;" < "$FPATH_DIFF_LIST" > "$FPATH_DIFF_ID_LIST"

# List metadata for each diff
paste -sd ' ' $FPATH_DIFF_LIST | xargs gsutil stat > "$FPATH_DIFF_GSUTIL_STAT"

# Check metadata for each diffs
while read -r line; do
  run_tests_for_diff_id "$line"
done < "$FPATH_DIFF_ID_LIST"

# Cleanup, report, exit
rm -f diff{1,2}.zip
info "--------"
info "ran to completion -- see $FPATH_TRANSCRIPT"
if [[ $FAILURE_COUNT -gt 0 ]]; then
  bash_exit_failure "$FAILURE_COUNT test failures"
fi
bash_exit_success "$FAILURE_COUNT test failures"
