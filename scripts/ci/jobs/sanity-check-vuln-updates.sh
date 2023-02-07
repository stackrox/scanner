#!/usr/bin/env bash

# Setup:
#   pip install --upgrade cryptography google-cloud-storage
#   gcloud components update
#
# Usage:
#   ./sanity-check-vuln-updates.sh [diff_id]
#
# Note:
#   This work was tracked in https://issues.redhat.com/browse/ROX-7271.
#   This test downloads ~500 MiB of vulnerability diffs with each run.
#   gsutil stat "gs://definitions.stackrox.io/*/diff.zip"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

function is_mac   { uname | grep -qi 'darwin'; }
function is_linux { uname | grep -qi 'linux'; }

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
  local diff_id gsutil_last_update
  local url_gsutil url_cloudflare url_gcs_https
  local metadata_cloudflare metadata_gcs_https
  local cache_control_cloudflare cache_control_gcs_https cache_age_cloudflare_secs
  local md5sum_cloudflare md5sum_gcs_https
  local gcs_object_age_seconds gcs_object_age_secs_now update_time_epoc_secs 
  local curl_verbose_cloudflare
  local diff_archive_cloudflare diff_archive_gcs

  diff_id=${1:-0133c2cf-8abe-4d79-9250-9b64b5b3e43e}

  url_cloudflare="https://definitions.stackrox.io/$diff_id/diff.zip"
  url_gcs_https="https://storage.googleapis.com/definitions.stackrox.io/$diff_id/diff.zip"

  diff_archive_cloudflare="$WORKING_DIR/diff1.zip"
  diff_archive_gcs="$WORKING_DIR/diff2.zip"

  curl_verbose_cloudflare=$(curl -s -H 'Accept-encoding: gzip' -o "$diff_archive_cloudflare" \
    -v "$url_cloudflare" 2>&1 | sed -e "s#^< ##g; s#\r##g;") \
    || bash_exit_failure "curl failed on $url_cloudflare"
  cache_control_gcs_https=$(curl -s -H 'Accept-encoding: gzip' -o "$diff_archive_gcs" \
    -v "$url_gcs_https" 2>&1 | grep "cache-control" | sed -e "s#^< ##g; s#\r##g;") \
    || bash_exit_failure "curl failed on $url_gcs_https"

  md5sum_cloudflare=$(md5sum "$diff_archive_cloudflare" | awk '{print $1}')
  md5sum_gcs_https=$(md5sum "$diff_archive_gcs" | awk '{print $1}')

  metadata_cloudflare=$(unzip -q -c "$diff_archive_cloudflare" manifest.json | jq -cr '.' && rm -f $diff_archive_cloudflare) \
    || bash_exit_failure "metadata extraction failed on $diff_archive_cloudflare"
  metadata_gcs_https=$(unzip -q -c "$diff_archive_gcs" manifest.json | jq -cr '.' && rm -f "$diff_archive_gcs") \
    || bash_exit_failure "metadata extraction failed on $diff_archive_gcs"

  cache_control_cloudflare=$(echo "$curl_verbose_cloudflare" | grep "cache-control") \
    || bash_exit_failure "extract cache-control failed on $url_cloudflare"

  # On CloudFlare cache miss there will be no age header, in that case assume the cache age is 0
  cache_age_cloudflare_secs=$(echo "$curl_verbose_cloudflare" | grep "age: " | sed -e "s#age: ##g" ) \
    || cache_age_cloudflare_secs=0

  gcs_object_age_seconds=$(get_gcs_object_age_seconds "$diff_id")

  url_gsutil="gs://definitions.stackrox.io/$diff_id/diff.zip"
  gsutil_last_update=$(gsutil stat "$url_gsutil" | sed -Ene 's/^ +Update time: +(.*)/\1/p')
  update_time_epoc_secs=$(parse_date_to_epoch_sec "$gsutil_last_update" "%a, %d %b %Y %H:%M:%S %Z")
  gcs_object_age_secs_now=$(get_age_seconds "$update_time_epoc_secs")

  cat <<EOF
-----------------------------------------------------------------------
diff_id                  : $diff_id
gsutil_last_update       : $gsutil_last_update
gcs_object_age_seconds   : $gcs_object_age_seconds
gcs_object_age_secs_now  : $gcs_object_age_secs_now

url_gsutil               : $url_gsutil
url_cloudflare           : $url_cloudflare
url_gcs_https            : $url_gcs_https

metadata_cloudflare      : $metadata_cloudflare
metadata_gcs_https       : $metadata_gcs_https

cache_age_cloudflare     : $cache_age_cloudflare_secs
cache_control_cloudflare : $cache_control_cloudflare
cache_control_gcs_https  : $cache_control_gcs_https

md5sum_cloudflare        : $md5sum_cloudflare
md5sum_gcs_https         : $md5sum_gcs_https

EOF

  if [[ "$gcs_object_age_seconds" -gt "$MAX_GCS_OBJECT_AGE_SECONDS" ]]; then
    testfail "gcs_object_age_seconds exceeds target"
  fi

  if [[ "$cache_control_cloudflare" != "cache-control: public, max-age=3600" ]]; then
    # known issue -- https://stack-rox.atlassian.net/browse/RS-307
    testfail "Incorrect cloudflare cache control setting, expected max-age=3600"
  fi

  if [[ "$cache_control_gcs_https" != "cache-control: public, max-age=3600" ]]; then
    testfail "Incorrect gcs cache control setting, expected max-age=3600"
  fi

  # If the gcs object age is over 1h, then the CDN cache should have been invalidated
  # based on the cache-control max-age value. Therefore the checksum should match that
  # from the content pulled directly from the gcs-https endpoint. But the object is
  # updated hourly so I might need to track hashes across runs to test this properly.
  #
  # Using gcs_object_age_secs_now instead of previously used gcs_object_age_seconds to
  # reduce the liklihood of a race condition if the GCS bucket was updated after this job
  # had started
  if [[ "$gcs_object_age_secs_now" -gt 3600 ]]; then
    if [[ "$md5sum_cloudflare" != "$md5sum_gcs_https" ]]; then
      testfail "Cloudflare CDN content mistmatch against reference after cache should have been invalidated"
    fi
  fi
}

function get_gcs_object_age_seconds {
  local diff_id created_time_raw created_time_epoch_sec

  diff_id="$1"
  created_time_raw=$(grep -A3 "$diff_id" "$FPATH_DIFF_GSUTIL_STAT" | sed -Ene 's/^ +Update time: +(.*)/\1/p')
  created_time_epoch_sec=$(parse_date_to_epoch_sec "$created_time_raw" "%a, %d %b %Y %H:%M:%S %Z")

  get_age_seconds "$created_time_epoch_sec"
}

function get_age_seconds {
  local last_update_secs now_epoch_sec obj_age_seconds

  last_update_secs="$1"
  now_epoch_sec=$(date "+%s")
  obj_age_seconds=$(( now_epoch_sec - last_update_secs ))

  echo "$obj_age_seconds"
}

function testfail { >&2 echo "FAIL: $*"; (( FAILURE_COUNT += 1 )); }
function bash_true { ((0 == 0)); }
function bash_false { ((0 == 1)); }
function bash_exit_success { info "$@"; bash_true; exit $?; }
function bash_exit_failure { error "$@"; bash_false; exit $?; }


# __MAIN__
DIGIT="[[:digit:]]"
NAME="sanity-check-vuln-updates"
WORKING_DIR="/tmp/$NAME"
FPATH_DIFF_LIST="$WORKING_DIR/diff.txt"
FPATH_DIFF_ID_LIST="$WORKING_DIR/ids.txt"
FPATH_DIFF_GSUTIL_STAT="$WORKING_DIR/metadata.txt"
FPATH_TRANSCRIPT="$WORKING_DIR/transcript.txt"
MAX_GCS_OBJECT_AGE_SECONDS=$((4 * 3600))
FAILURE_COUNT=0

# Setup GCP
require_environment "GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER"
setup_gcp "${GOOGLE_SA_STACKROX_HUB_VULN_DUMP_UPLOADER}"

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
store_test_results "$WORKING_DIR" "$NAME"
if [[ $FAILURE_COUNT -gt 0 ]]; then
  send_slack_notice_for_vuln_check_failure
  bash_exit_failure "$FAILURE_COUNT test failures"
fi
bash_exit_success "$FAILURE_COUNT test failures"
