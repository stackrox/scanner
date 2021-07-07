#!/usr/bin/env bash
#
# Setup:
#   pip install --upgrade cryptography gsutil google-cloud
#   gcloud components update
#
# Usage:
#   ./sanity-check-vuln-updates.sh
set -eu

function is_mac   { uname | grep -qi 'darwin'; }
function is_linux { uname | grep -qi 'linux'; }

function parse_date_to_epoch_sec {
  local date_string=$1
  local date_format=$2

  if is_linux; then
    date --date "$date_string" "+%s"
  elif is_mac; then
    date -j -f "$date_format" "$date_string" "+%s"
  fi
}

function get_manifest_content_from_zip {
  local fpath_zipfile=$1
  unzip -q -c "$fpath_zipfile" manifest.json
}

function get_manifest_age_seconds_from_zip {
  local fpath_zipfile=$1
  local manifest_until_raw=$(get_manifest_content_from_zip "$fpath_zipfile" \
      | jq -r ".until" | sed -Ee 's#\.[0-9]+Z# GMT#')
  local manifest_until_epoch_sec=$(parse_date_to_epoch_sec "$manifest_until_raw" "%Y-%M-%dT%H:%M:%S %Z")
  local now_epoch_sec=$(date "+%s")
  local age_seconds=$(( $now_epoch_sec - $manifest_until_epoch_sec ))
  echo "$age_seconds"
}

function run_tests_for_diff_id {
  local DIFF_ID="$1"
  local GCS_CONSOLE_URL="https://console.cloud.google.com/storage/browser/definitions.stackrox.io/$DIFF_ID"
  local DIFF1_CLOUDFLARE_URL="https://definitions.stackrox.io/$DIFF_ID/diff.zip"
  local DIFF2_GCS_URL="https://storage.googleapis.com/definitions.stackrox.io/$DIFF_ID/diff.zip"

  info "--------"
  info "DIFF_ID              => $DIFF_ID"
  info "GCS_CONSOLE_URL      => $GCS_CONSOLE_URL"
  info "DIFF1_CLOUDFLARE_URL => $DIFF1_CLOUDFLARE_URL"
  info "DIFF2_GCS_URL        => $DIFF2_GCS_URL"
  info "WORKING_DIR          => $WORKING_DIR"

  rm -f diff{1,2}.zip

  info "downloading diff1.zip from $DIFF1_CLOUDFLARE_URL"
  diff1_cache_control=$(curl -s -o ./diff1.zip -v "$DIFF1_CLOUDFLARE_URL" 2>&1 \
    | grep "cache-control" | sed -e "s#^< ##g; s#\r##g;")

  info "downloading diff2.zip from $DIFF2_GCS_URL"
  diff2_cache_control=$(curl -s -o ./diff2.zip -v "$DIFF2_GCS_URL" 2>&1 \
    | grep "cache-control" | sed -e "s#^< ##g; s#\r##g;")

  local gcs_object_age_seconds=$(get_gcs_object_age_seconds $DIFF_ID)
  local diff1_manifest_content=$(get_manifest_content_from_zip "diff1.zip")
  local diff2_manifest_content=$(get_manifest_content_from_zip "diff2.zip")
  local diff1_manifest_age_seconds=$(get_manifest_age_seconds_from_zip "diff1.zip")
  local diff2_manifest_age_seconds=$(get_manifest_age_seconds_from_zip "diff2.zip")
  local diff1_archive_md5=$(md5sum "diff1.zip" | cut -d" " -f1)
  local diff2_archive_md5=$(md5sum "diff2.zip" | cut -d" " -f1)
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
    testfail "gcs_object_age_seconds exceeds target"
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
  local diff_id="$1"
  local created_datestamp_raw=$(grep -A2 "$diff_id" "$FPATH_DIFF_GSUTIL_STAT" \
    | grep "Creation time:" | sed -Ee 's/ +/ /g; s/^ +//;' | cut -d' ' -f3-)
  local created_datestamp_epoch_sec=$(parse_date_to_epoch_sec "$created_datestamp_raw" "%a, %d %b %Y %H:%M:%S %Z")
  local now_epoch_sec=$(date "+%s")
  local obj_age_seconds=$(( $now_epoch_sec - $created_datestamp_epoch_sec ))
  echo "$obj_age_seconds"
}

function info { >&1 echo "INFO: $@"; }
function warn { >&1 echo "WARN: $@"; }
function error { >&2 echo "ERROR: $@"; }
function testfail { >&2 echo "FAIL: $@"; (( FAILURE_COUNT += 1 )); }
function bash_true { ((0 == 0)); }
function bash_false { ((0 == 1)); }
function bash_exit_success { info "$@"; bash_true; exit $?; }
function bash_exit_failure { error "$@"; bash_false; exit $?; }


# __MAIN__
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

# Get a list of diffs (incremental vulnerability db updates)
gsutil ls -r "gs://definitions.stackrox.io/*/diff.zip" > "$FPATH_DIFF_LIST"

# Extract the ids (uniquely identifying hashes).
sed -Ee "s#gs://definitions.stackrox.io/##g; s#/diff.zip##g;" \
  < "$FPATH_DIFF_LIST" > "$FPATH_DIFF_ID_LIST"

# List metadata for each diff
gsutil stat $(cat "$FPATH_DIFF_LIST") > "$FPATH_DIFF_GSUTIL_STAT"

# Check metadata for each diffs
for entry in $(cat "$FPATH_DIFF_ID_LIST"); do
  run_tests_for_diff_id "$entry"
done

# Cleanup files we don't want archived by the ci job
rm -f diff{1,2}.zip

info "--------"
info "ran to completion -- see $FPATH_TRANSCRIPT"

if [[ $FAILURE_COUNT -gt 0 ]]; then
  bash_exit_failure "$FAILURE_COUNT test failures"
fi
bash_exit_success "$FAILURE_COUNT test failures"
