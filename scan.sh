#!/usr/bin/env bash
# Arko Scan — GitHub Actions composite-action entrypoint.
#
# Zips the checked-out source (minus junk dirs), uploads it to Arko via a
# presigned S3 PUT, starts an async build scan, polls to completion,
# annotates findings as workflow commands, writes a step summary, and sets
# the action outputs.
#
# Inputs arrive as ARKO_* environment variables (see action.yml).
#
# Posture: Arko is advisory in CI by default. FINDINGS only fail this step
# when `fail-on` is set. Infrastructure errors (bad token, upload failure,
# scan failure, timeout) always exit 1 — a scan that never produced advice
# must never be silently green.
#
# Requires: bash, curl, jq, zip (all present on ubuntu-* hosted runners).

set -euo pipefail

# ---------------------------------------------------------------------------
# Inputs / environment
# ---------------------------------------------------------------------------
API_TOKEN="${ARKO_API_TOKEN:-}"
BEARER_TOKEN="${ARKO_BEARER_TOKEN:-}"
API_BASE="${ARKO_API_BASE:-https://arko.devsecai.io}"
API_BASE="${API_BASE%/}"
PROJECT_NAME="${ARKO_PROJECT_NAME:-}"
BRANCH="${ARKO_BRANCH:-}"
FAIL_ON="$(printf '%s' "${ARKO_FAIL_ON:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
MAX_WAIT_SECONDS="${ARKO_MAX_WAIT_SECONDS:-1200}"
USER_EXCLUDES="${ARKO_EXCLUDE:-}"
CONSOLE_BASE="${ARKO_CONSOLE_BASE:-https://app.arko.devsecai.io}"
POLL_SECONDS="${ARKO_POLL_SECONDS:-8}"

WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"
TMP_ROOT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/null}"
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-/dev/null}"

# Fallbacks when action.yml defaults come through empty (e.g. events with no
# repository payload).
if [[ -z "$PROJECT_NAME" ]]; then
  PROJECT_NAME="${GITHUB_REPOSITORY##*/}"
fi
PROJECT_NAME="${PROJECT_NAME:-project}"
BRANCH="${BRANCH:-${GITHUB_REF_NAME:-unknown}}"

SCAN_ID=""
CRIT=0; HIGH=0; MED=0; LOW=0
MAX_UPLOAD_BYTES=5368709120   # 5 GB server-side cap on size_bytes

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Internal pipeline phase names are not customer vocabulary — map them to the
# same labels the Arko console shows (unknown phases just get tidied).
phase_label() {
  case "$1" in
    provisioning_worker) printf 'provisioning scanner' ;;
    downloading_tar)     printf 'downloading artefact' ;;
    extracting_zip)      printf 'extracting archive' ;;
    cloning_repo)        printf 'fetching repository' ;;
    running_trivy)       printf 'scanning for vulnerabilities' ;;
    parsing_results)     printf 'parsing results' ;;
    enriching_cves)      printf 'enriching with exploit intelligence' ;;
    writing_findings)    printf 'saving findings' ;;
    dispatched_to_sast)  printf 'deep code analysis' ;;
    summarizing)         printf 'summarising the codebase' ;;
    threat_modeling)     printf 'threat modelling' ;;
    validation)          printf 'validating findings' ;;
    *)                   printf '%s' "${1//_/ }" ;;
  esac
}

console_link() { printf '%s/build-scans/%s' "$CONSOLE_BASE" "$SCAN_ID"; }

write_outputs() {
  # $1 = verdict
  {
    printf 'scan-id=%s\n' "$SCAN_ID"
    printf 'verdict=%s\n' "$1"
    printf 'critical-count=%s\n' "${CRIT:-0}"
    printf 'high-count=%s\n' "${HIGH:-0}"
    printf 'medium-count=%s\n' "${MED:-0}"
    printf 'low-count=%s\n' "${LOW:-0}"
  } >> "$OUTPUT_FILE"
}

die() {
  # Fatal path: actionable message + (if the scan started) scan id and
  # console link, outputs set, exit 1.
  printf '::error::Arko Scan: %s\n' "$(esc_msg "$1")"
  if [[ -n "$SCAN_ID" ]]; then
    printf 'Scan id: %s\n' "$SCAN_ID"
    printf 'Console: %s\n' "$(console_link)"
    {
      printf '## Arko Scan — did not finish\n\n'
      printf '%s\n\n' "$1"
      printf '[Open this scan in the Arko console](%s)\n' "$(console_link)"
    } >> "$SUMMARY_FILE"
  fi
  write_outputs "error"
  exit 1
}

# GitHub workflow-command escaping. Message data escapes % \r \n; property
# values additionally escape : and , (per the runner's command parser).
esc_msg() {
  local s="${1-}"
  s="${s//'%'/%25}"
  s="${s//$'\r'/%0D}"
  s="${s//$'\n'/%0A}"
  printf '%s' "$s"
}
esc_prop() {
  local s
  s="$(esc_msg "${1-}")"
  s="${s//:/%3A}"
  s="${s//,/%2C}"
  printf '%s' "$s"
}

# Findings often come back with an absolute or extraction-root prefix.
# Strip leading components until the path exists in the checkout so
# `file=` annotations land on the right file.
resolve_path() {
  local p="${1#/}"
  p="${p#./}"
  local q="$p" tries=0
  while [[ ! -f "$WORKSPACE/$q" && "$q" == */* && $tries -lt 12 ]]; do
    q="${q#*/}"
    tries=$((tries + 1))
  done
  if [[ -n "$q" && -f "$WORKSPACE/$q" ]]; then
    printf '%s' "$q"
  else
    printf '%s' "$p"
  fi
}

# ---------------------------------------------------------------------------
# Validation + auth setup (token never echoed, never on a curl command line)
# ---------------------------------------------------------------------------
case "$FAIL_ON" in
  ''|critical|high|medium) : ;;
  *) die "invalid fail-on value '${FAIL_ON}'. Use critical, high, medium, or leave it empty for advisory mode." ;;
esac

if ! [[ "$MAX_WAIT_SECONDS" =~ ^[0-9]+$ ]]; then
  die "max-wait-seconds must be a whole number of seconds (got '${MAX_WAIT_SECONDS}')."
fi

if [[ -z "$API_TOKEN" && -z "$BEARER_TOKEN" ]]; then
  die "no credentials provided. Set api-token (an Arko API token from Admin → API Access, stored as a repository secret) or bearer-token."
fi

WORK_DIR="$(mktemp -d "${TMP_ROOT}/arko-scan.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

# The auth header lives in a 0600 curl config file so the token never
# appears in the process list or any log line.
AUTH_CFG="$WORK_DIR/auth.cfg"
(umask 077 && : > "$AUTH_CFG")
if [[ -n "$API_TOKEN" ]]; then
  printf 'header = "X-Arko-Token: %s"\n' "$API_TOKEN" >> "$AUTH_CFG"
else
  printf 'header = "Authorization: Bearer %s"\n' "$BEARER_TOKEN" >> "$AUTH_CFG"
fi

BODY_FILE="$WORK_DIR/response.json"
HTTP_STATUS=""

# api_request METHOD PATH [JSON_BODY]
# Body lands in $BODY_FILE, status code in $HTTP_STATUS.
# Returns non-zero only on transport failure (no HTTP response at all).
api_request() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(
    -sS --config "$AUTH_CFG"
    -X "$method"
    -H 'Accept: application/json'
    -o "$BODY_FILE"
    -w '%{http_code}'
    --max-time 90
  )
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' --data "$body")
  fi
  HTTP_STATUS="$(curl "${args[@]}" "${API_BASE}${path}")" || return 1
}

body_excerpt() { head -c 300 "$BODY_FILE" 2>/dev/null | tr -d '\r\n' || true; }

# ---------------------------------------------------------------------------
# Step 1 — zip the checkout
# ---------------------------------------------------------------------------
ZIP_PATH="$WORK_DIR/source.zip"
declare -a ZIP_EXCLUDES=('*.zip')
for name in .git node_modules dist build .venv; do
  ZIP_EXCLUDES+=("$name" "$name/*" "*/$name" "*/$name/*")
done
if [[ -n "$USER_EXCLUDES" ]]; then
  while IFS= read -r pat; do
    pat="${pat#"${pat%%[![:space:]]*}"}"
    pat="${pat%"${pat##*[![:space:]]}"}"
    if [[ -n "$pat" ]]; then
      ZIP_EXCLUDES+=("$pat")
    fi
  done <<< "$USER_EXCLUDES"
fi

echo "Zipping ${WORKSPACE} for upload..."
if ! (cd "$WORKSPACE" && zip -r -q -X "$ZIP_PATH" . -x "${ZIP_EXCLUDES[@]}"); then
  die "failed to zip the checkout. Check the exclude patterns (zip -x syntax) and that the workspace is not empty."
fi

SIZE_BYTES="$(wc -c < "$ZIP_PATH" | tr -d '[:space:]')"
if command -v zipinfo >/dev/null 2>&1; then
  FILE_COUNT="$(zipinfo -1 "$ZIP_PATH" | wc -l | tr -d '[:space:]')"
else
  FILE_COUNT="$(zip -sf "$ZIP_PATH" | sed -n 's/^Total \([0-9][0-9]*\) entries.*/\1/p')"
fi
echo "Archive: ${SIZE_BYTES} bytes, ${FILE_COUNT} entries"

if (( SIZE_BYTES > MAX_UPLOAD_BYTES )); then
  die "archive is ${SIZE_BYTES} bytes — over the 5 GB upload cap. Add exclude patterns for large generated directories."
fi
if (( SIZE_BYTES > 52428800 )); then
  echo "::notice::Arko Scan: archive is over 50 MB — cold scanner provisioning can add 60-120s before the first phase starts."
fi

if command -v sha256sum >/dev/null 2>&1; then
  read -r SHA256 _ < <(sha256sum "$ZIP_PATH")
else
  read -r SHA256 _ < <(shasum -a 256 "$ZIP_PATH")
fi

# Server filename rule: ^[\w\-. ]+\.(tar|tar.gz|tgz|zip)$ — sanitise the
# project name into that charset and fall back to "src".
FNAME="$(printf '%s' "$PROJECT_NAME" | tr -c 'A-Za-z0-9._ -' '_')"
FNAME="${FNAME:0:100}"
case "$FNAME" in
  *[A-Za-z0-9]*) : ;;
  *) FNAME="src" ;;
esac
ZIP_FILENAME="${FNAME}.zip"

# ---------------------------------------------------------------------------
# Step 2 — request the presigned upload URL
# ---------------------------------------------------------------------------
echo "Requesting upload URL from ${API_BASE}..."
UPLOAD_PAYLOAD="$(jq -n \
  --arg filename "$ZIP_FILENAME" \
  --argjson size_bytes "$SIZE_BYTES" \
  --arg project_name "$PROJECT_NAME" \
  --arg branch "$BRANCH" \
  --arg sha256 "$SHA256" \
  '{filename: $filename, size_bytes: $size_bytes, project_name: $project_name, branch: $branch, sha256: $sha256}')"

if ! api_request POST "/scan/build/upload-url" "$UPLOAD_PAYLOAD"; then
  die "could not reach ${API_BASE} (network error). Check api-base and the runner's egress."
fi
case "$HTTP_STATUS" in
  200) : ;;
  401|403)
    die "the API rejected the credentials (${HTTP_STATUS}). Check the api-token secret is a valid Arko API token (Admin → API Access) and that Build Scan is enabled for your organisation — new organisations need it switched on by an Arko admin. Response: $(body_excerpt)"
    ;;
  422)
    die "the API rejected the upload request (422 validation). Response: $(body_excerpt)"
    ;;
  *)
    die "unexpected ${HTTP_STATUS} from POST /scan/build/upload-url. Response: $(body_excerpt)"
    ;;
esac

SCAN_ID="$(jq -er '.scan_id // empty' "$BODY_FILE")" \
  || die "could not parse scan_id from the upload-url response: $(body_excerpt)"
PRESIGNED_URL="$(jq -er '.presigned_url // empty' "$BODY_FILE")" \
  || die "could not parse presigned_url from the upload-url response: $(body_excerpt)"

echo "Scan id: ${SCAN_ID}"
echo "Console: $(console_link)"

# ---------------------------------------------------------------------------
# Step 3 — upload the archive (presigned PUT)
# ---------------------------------------------------------------------------
# The presigned URL signs the EXACT Content-Length (= size_bytes above,
# which curl -T sets from the same file) and the SSE header below. Any
# mismatch breaks the SigV4 signature and S3 returns 403.
echo "Uploading archive (${SIZE_BYTES} bytes)..."
if ! HTTP_STATUS="$(curl -sS -o "$BODY_FILE" -w '%{http_code}' \
    -X PUT \
    -H 'x-amz-server-side-encryption: AES256' \
    --upload-file "$ZIP_PATH" \
    --max-time 1800 \
    "$PRESIGNED_URL")"; then
  die "network error uploading the archive to S3. Re-run the job; if it persists, check the runner's egress to S3."
fi
if [[ "$HTTP_STATUS" != "200" ]]; then
  if [[ "$HTTP_STATUS" == "403" ]]; then
    die "S3 rejected the upload (403). The presigned PUT signs the exact Content-Length (${SIZE_BYTES}) and the 'x-amz-server-side-encryption: AES256' header — a mismatch in either breaks the signature. The URL also expires; re-run the job if the upload was slow to start. Response: $(body_excerpt)"
  fi
  die "S3 upload failed with ${HTTP_STATUS}. Response: $(body_excerpt)"
fi
echo "Upload complete."

# ---------------------------------------------------------------------------
# Step 4 — start the scan
# ---------------------------------------------------------------------------
if ! api_request POST "/scan/build/${SCAN_ID}/start"; then
  die "could not reach the API to start the scan (network error). The archive was uploaded; re-running the whole job is safe."
fi
case "$HTTP_STATUS" in
  202) : ;;
  401|403)
    die "the API rejected the credentials on start (${HTTP_STATUS}). Check the api-token secret and that Build Scan is enabled for your organisation. Response: $(body_excerpt)"
    ;;
  409)
    die "the scan is not awaiting upload (409) — it may already have been started, or the upload slot expired. Check the console, then re-run the job to create a fresh scan."
    ;;
  412)
    die "the API could not find the uploaded archive in S3 (412) — the upload likely failed or landed on an expired URL. Re-run the job."
    ;;
  *)
    die "unexpected ${HTTP_STATUS} from POST /scan/build/${SCAN_ID}/start. Response: $(body_excerpt)"
    ;;
esac
echo "Scan started."

# ---------------------------------------------------------------------------
# Step 5 — poll to completion
# ---------------------------------------------------------------------------
echo "Waiting for the scan to complete (max ${MAX_WAIT_SECONDS}s)..."
START_EPOCH="$(date +%s)"
DEADLINE=$((START_EPOCH + MAX_WAIT_SECONDS))
POLL_ERRORS=0
LAST_PHASE=""
SCAN_STATUS=""

while :; do
  NOW="$(date +%s)"
  if (( NOW >= DEADLINE )); then
    die "timed out after ${MAX_WAIT_SECONDS}s waiting for the scan. Large archives can spend 60-120s in cold provisioning first, and the server fails scans with no heartbeat at ~20 minutes. The scan may still finish — check the console."
  fi
  if api_request GET "/scan/build/${SCAN_ID}" && [[ "$HTTP_STATUS" == "200" ]]; then
    POLL_ERRORS=0
    SCAN_STATUS="$(jq -r '.status // empty' "$BODY_FILE" 2>/dev/null || true)"
    PHASE="$(jq -r '.current_phase // empty' "$BODY_FILE" 2>/dev/null || true)"
    if [[ -n "$PHASE" && "$PHASE" != "$LAST_PHASE" ]]; then
      echo "  phase: $(phase_label "$PHASE") ($((NOW - START_EPOCH))s elapsed)"
      LAST_PHASE="$PHASE"
    fi
    case "$SCAN_STATUS" in
      completed|completed_partial)
        break
        ;;
      failed)
        ERR_MSG="$(jq -r '.error_message // "no error message recorded"' "$BODY_FILE" 2>/dev/null || echo 'no error message recorded')"
        die "the scan failed server-side: ${ERR_MSG}"
        ;;
    esac
  else
    POLL_ERRORS=$((POLL_ERRORS + 1))
    if (( POLL_ERRORS >= 6 )); then
      die "lost contact with the API while polling (6 consecutive errors, last HTTP status '${HTTP_STATUS:-none}'). The scan may still finish — check the console."
    fi
  fi
  sleep "$POLL_SECONDS"
done

FOUND_TOTAL="$(jq -r '.vulnerabilities_found // 0' "$BODY_FILE" 2>/dev/null || echo 0)"
echo "Scan ${SCAN_STATUS} — ${FOUND_TOTAL} finding(s) reported."

# ---------------------------------------------------------------------------
# Step 6 — fetch findings (full payload, lean fallback for the ALB 1MB cap)
# ---------------------------------------------------------------------------
FINDINGS_JSON="$WORK_DIR/findings.json"

fetch_findings() {
  # $1 = extra query string ('' or '&view=list')
  api_request GET "/org/vulnerabilities?scan_id=${SCAN_ID}&status=all&limit=500${1}" || return 1
  [[ "$HTTP_STATUS" == "200" ]] || return 1
  jq -e '.items | type == "array"' "$BODY_FILE" >/dev/null 2>&1 || return 1
  cp "$BODY_FILE" "$FINDINGS_JSON"
}

FINDINGS_MODE="none"
if fetch_findings ""; then
  FINDINGS_MODE="full"
elif fetch_findings "&view=list"; then
  # The full payload can blow past the load balancer's 1 MB response cap on
  # finding-heavy scans; the lean view keeps severity/title/file/line but
  # drops the fix text.
  FINDINGS_MODE="lean"
  echo "::notice::Arko Scan: full findings payload unavailable (likely over the 1 MB response cap) — using the lean view; fix suggestions appear in the console."
else
  echo "::warning::Arko Scan: could not fetch the findings list (HTTP ${HTTP_STATUS:-none}) — see the console for details: $(console_link)"
fi

TOTAL_REPORTED="$FOUND_TOTAL"
ITEMS_FETCHED=0
if [[ "$FINDINGS_MODE" != "none" ]]; then
  ITEMS_FETCHED="$(jq -r '.items | length' "$FINDINGS_JSON")"
  TOTAL_REPORTED="$(jq -r '.total // (.items | length)' "$FINDINGS_JSON")"
  if ! read -r CRIT HIGH MED LOW < <(jq -r '
        [.items[] | (.severity // "" | ascii_downcase)] as $s
        | [ ($s | map(select(. == "critical")) | length),
            ($s | map(select(. == "high"))     | length),
            ($s | map(select(. == "medium"))   | length),
            ($s | map(select(. == "low"))      | length) ]
        | @tsv' "$FINDINGS_JSON"); then
    CRIT=0; HIGH=0; MED=0; LOW=0
    FINDINGS_MODE="none"
  fi
fi

# ---------------------------------------------------------------------------
# Step 7 — annotations (top 50, most severe first) + summary rows (top 10)
# ---------------------------------------------------------------------------
ROWS_TSV="$WORK_DIR/findings.tsv"
if [[ "$FINDINGS_MODE" != "none" ]]; then
  # One TSV row per finding: severity, title, file, line, description,
  # first line of the recommendation. Free-text fields have \r \n \t and
  # backslashes flattened so @tsv stays 1-row-per-finding after read.
  jq -r '
    def rank: {"critical": 0, "high": 1, "medium": 2, "low": 3};
    def flat: (. // "") | tostring | gsub("[\\r\\n\\t\\\\]"; " ");
    [ .items[]
      | .severity = ((.severity // "low") | ascii_downcase)
      | . + {r: (rank[.severity] // 4)} ]
    | sort_by(.r)
    | .[0:50][]
    | [ .severity,
        ((.title // .name) | flat | if . == "" then "Security finding" else . end),
        ((.file // .file_path // .location) | flat),
        ((.line // "") | tostring),
        (.description | flat | .[0:220]),
        (.recommendation | flat | .[0:160]) ]
    | @tsv' "$FINDINGS_JSON" > "$ROWS_TSV"

  while IFS=$'\t' read -r sev title fpath line desc _rec; do
    # GitHub's annotation vocabulary is fixed (error/warning/notice) — use it
    # honestly: an advisory run failed nothing, so findings render as
    # warnings/notices; "Error" is reserved for findings that will actually
    # fail the job under the customer's opt-in fail-on gate.
    gated=false
    case "$FAIL_ON" in
      critical) [[ "$sev" == "critical" ]] && gated=true ;;
      high)     case "$sev" in critical|high) gated=true ;; esac ;;
      medium)   case "$sev" in critical|high|medium) gated=true ;; esac ;;
    esac
    if [[ "$gated" == true ]]; then
      level="error"
    elif [[ "$sev" == "low" ]]; then
      level="notice"
    else
      level="warning"
    fi
    sev_upper="$(printf '%s' "$sev" | tr '[:lower:]' '[:upper:]')"
    msg="$(esc_msg "${sev} · ${title}${desc:+ — ${desc}}")"
    props="title=$(esc_prop "Arko · ${sev_upper} · ${title}")"
    if [[ -n "$fpath" ]]; then
      rel="$(resolve_path "$fpath")"
      props="${props},file=$(esc_prop "$rel")"
      if [[ -n "$line" && "$line" != "null" && "$line" != "0" ]]; then
        props="${props},line=$(esc_prop "$line")"
      fi
    fi
    printf '::%s %s::%s\n' "$level" "$props" "$msg"
  done < "$ROWS_TSV"
fi

# ---------------------------------------------------------------------------
# Step 8 — verdict + exit code
# ---------------------------------------------------------------------------
GATE_COUNT=0
case "$FAIL_ON" in
  critical) GATE_COUNT="$CRIT" ;;
  high)     GATE_COUNT=$((CRIT + HIGH)) ;;
  medium)   GATE_COUNT=$((CRIT + HIGH + MED)) ;;
esac

VERDICT="passing"
EXIT_CODE=0
GATE_NOTE=""
if [[ -z "$FAIL_ON" ]]; then
  if (( FOUND_TOTAL > 0 )); then
    VERDICT="advisory"
  fi
  GATE_NOTE="No \`fail-on\` gate is set — this check never blocks merges."
else
  if [[ "$FINDINGS_MODE" == "none" && "$FOUND_TOTAL" -gt 0 ]]; then
    # Findings exist but could not be classified — with a gate configured,
    # fail closed rather than silently pass unreviewed findings.
    VERDICT="failing"
    EXIT_CODE=1
    GATE_NOTE="The scan reported ${FOUND_TOTAL} finding(s) but the severity breakdown could not be fetched — gating conservatively (\`fail-on: ${FAIL_ON}\`)."
  elif (( GATE_COUNT > 0 )); then
    VERDICT="failing"
    EXIT_CODE=1
    GATE_NOTE="${GATE_COUNT} finding(s) at or above the \`fail-on: ${FAIL_ON}\` gate."
  else
    GATE_NOTE="No findings at or above the \`fail-on: ${FAIL_ON}\` gate."
  fi
fi

# ---------------------------------------------------------------------------
# Step 9 — step summary
# ---------------------------------------------------------------------------
{
  printf '## Arko Scan — %s @ %s\n\n' "$PROJECT_NAME" "$BRANCH"
  case "$VERDICT" in
    passing)  printf '**Verdict: passing.** %s\n\n' "$GATE_NOTE" ;;
    advisory) printf '**Verdict: advisory.** %s finding(s) to review. %s\n\n' "$FOUND_TOTAL" "$GATE_NOTE" ;;
    failing)  printf '**Verdict: failing.** %s\n\n' "$GATE_NOTE" ;;
  esac
  if [[ "$SCAN_STATUS" == "completed_partial" ]]; then
    printf '> The scan completed partially — some phases did not finish, so results may be incomplete.\n\n'
  fi
  printf '| Severity | Count |\n|---|---:|\n'
  printf '| Critical | %s |\n' "$CRIT"
  printf '| High | %s |\n' "$HIGH"
  printf '| Medium | %s |\n' "$MED"
  printf '| Low | %s |\n' "$LOW"
  printf '\n'
  if [[ "$FINDINGS_MODE" == "none" && "$FOUND_TOTAL" -gt 0 ]]; then
    printf '_The scan reported %s finding(s) but the breakdown could not be fetched — open the console for the full list._\n\n' "$FOUND_TOTAL"
  elif (( TOTAL_REPORTED > ITEMS_FETCHED )); then
    printf '_Showing the first %s of %s findings — the full list is in the console._\n\n' "$ITEMS_FETCHED" "$TOTAL_REPORTED"
  fi
  if [[ -s "${ROWS_TSV:-/dev/null}" ]]; then
    printf '### Top findings\n\n'
    printf '| Severity | Finding | Location | Suggested fix |\n|---|---|---|---|\n'
    count=0
    while IFS=$'\t' read -r sev title fpath line _desc rec; do
      count=$((count + 1))
      if (( count > 10 )); then break; fi
      loc='—'
      if [[ -n "$fpath" ]]; then
        rel="$(resolve_path "$fpath")"
        loc="\`${rel//|/\\|}\`"
        if [[ -n "$line" && "$line" != "null" && "$line" != "0" ]]; then
          loc="\`${rel//|/\\|}:${line}\`"
        fi
      fi
      fix="${rec:-—}"
      printf '| %s | %s | %s | %s |\n' "$sev" "${title//|/\\|}" "$loc" "${fix//|/\\|}"
    done < "$ROWS_TSV"
    printf '\n'
  fi
  printf '[View the full report in the Arko console](%s)\n\n' "$(console_link)"
  # shellcheck disable=SC2016  # literal markdown backticks, not an expansion
  printf -- '---\n\nArko is advisory in CI by default — set `fail-on` to gate merges.\n'
} >> "$SUMMARY_FILE"

# ---------------------------------------------------------------------------
# Step 10 — outputs + exit
# ---------------------------------------------------------------------------
write_outputs "$VERDICT"
echo "Verdict: ${VERDICT} (critical=${CRIT} high=${HIGH} medium=${MED} low=${LOW})"
echo "Full report: $(console_link)"
exit "$EXIT_CODE"
