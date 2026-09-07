#!/usr/bin/env bash
# Lightweight recon pipeline for explicitly authorized targets only.

set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$ROOT_DIR/config/settings.conf"
ENV_FILE="$ROOT_DIR/.env"
RUN_DIR=""

usage() {
  cat <<'EOF'
Usage: ./recon.sh <domain>

Runs the default, low-impact workflow for a domain that is explicitly in scope:
  1. passive subdomain discovery
  2. HTTP/HTTPS reachability check
  3. limited URL and JavaScript discovery
  4. summary generation

No port scanning, fuzzing, or vulnerability scanning is included.
EOF
}

log() {
  printf '[*] %s\n' "$*"
}

fail() {
  printf '[!] %s\n' "$*" >&2
  exit 1
}

# Keep only the target domain and its subdomains. Crawlers commonly report
# CDN, analytics, and other third-party absolute URLs found in pages.
in_scope_url() {
  local url="${1,,}"
  local authority host

  [[ "$url" =~ ^https?:// ]] || return 1
  authority="${url#*://}"
  authority="${authority%%[/?#]*}"
  authority="${authority##*@}"
  host="${authority%%:*}"
  host="${host%.}"

  [[ "$host" =~ $DOMAIN_PATTERN ]] || return 1
  [[ "$host" == "$TARGET" || "$host" == *."$TARGET" ]]
}

filter_scoped_hosts() {
  local input="$1" output="$2"
  local host

  while IFS= read -r host; do
    host="${host,,}"
    host="${host%.}"
    [[ "$host" =~ $DOMAIN_PATTERN ]] || continue
    [[ "$host" == "$TARGET" || "$host" == *."$TARGET" ]] || continue
    printf '%s\n' "$host"
  done < "$input" | LC_ALL=C sort -fu > "$output"
}

# Preserve a tool's complete line (such as httpx status/title fields), while
# determining scope from its first URL field.
filter_scoped_url_lines() {
  local input="$1" output="$2"
  local line url

  while IFS= read -r line; do
    url="${line%%[[:space:]]*}"
    in_scope_url "$url" || continue
    printf '%s\n' "$line"
  done < "$input" | LC_ALL=C sort -fu > "$output"
}

filter_javascript_urls() {
  local input="$1" output="$2"

  # Match the extension after removing a query string/fragment, but retain
  # the original URL so every result can be fetched directly.
  awk '{
    candidate = tolower($0)
    sub(/[?#].*$/, "", candidate)
    if (candidate ~ /\\.(js|mjs|cjs)$/) print $0
  }' "$input" | LC_ALL=C sort -fu > "$output"
}

on_error() {
  local exit_code=$?
  if [[ -n "$RUN_DIR" ]]; then
    printf '[!] Stopped (exit %s). Partial results: %s\n' "$exit_code" "$RUN_DIR" >&2
  fi
  exit "$exit_code"
}
trap on_error ERR

[[ -f "$CONFIG_FILE" ]] || fail "Missing configuration: $CONFIG_FILE"
# These files are local and user-controlled. Neither file is printed or logged.
# shellcheck disable=SC1090
source "$CONFIG_FILE"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
TARGET="${1,,}"

# Accept a hostname/domain only; URLs, IP addresses, paths, and shell metacharacters are rejected.
DOMAIN_PATTERN='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
[[ "$TARGET" =~ $DOMAIN_PATTERN ]] || fail "Use a domain name only (for example: example.com)."

for tool in subfinder httpx-toolkit katana; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required tool is not available: $tool"
done

if [[ ! -t 0 ]]; then
  fail "Interactive scope confirmation is required; run this command in a terminal."
fi

printf '\nThis tool may only be used on a target explicitly authorized by its owner or bug-bounty scope.\n'
printf 'Confirm that %s is in scope by typing AUTHORIZED: ' "$TARGET"
read -r AUTHORIZATION
[[ "$AUTHORIZATION" == "AUTHORIZED" ]] || fail "No scope confirmation received; no network activity was performed."
unset AUTHORIZATION

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ROOT_DIR/results/$TARGET/$TIMESTAMP"
mkdir -p "$RUN_DIR"

SUBDOMAINS_RAW="$RUN_DIR/01-subdomains-raw.txt"
SUBDOMAINS="$RUN_DIR/01-subdomains.txt"
HTTP_DETAILS="$RUN_DIR/02-http-details.txt"
LIVE_HOSTS="$RUN_DIR/02-live-hosts.txt"
SELECTED_HOSTS="$RUN_DIR/02-selected-live-hosts.txt"
URLS_RAW="$RUN_DIR/03-urls-raw.txt"
URLS="$RUN_DIR/03-urls.txt"
JAVASCRIPT="$RUN_DIR/03-javascript.txt"
SUMMARY="$RUN_DIR/summary.txt"

SUBFINDER_CONFIG="${SUBFINDER_CONFIG:-$ROOT_DIR/config/subfinder-config.yaml}"
[[ -f "$SUBFINDER_CONFIG" ]] || fail "Subfinder config does not exist: $SUBFINDER_CONFIG"

PROVIDER_ARGS=()
if [[ -n ${SUBFINDER_PROVIDER_CONFIG:-} ]]; then
  [[ -f "$SUBFINDER_PROVIDER_CONFIG" ]] || fail "Provider config does not exist: $SUBFINDER_PROVIDER_CONFIG"
  PROVIDER_ARGS=(-pc "$SUBFINDER_PROVIDER_CONFIG")
fi

log "Results: $RUN_DIR"
log "1/4 Passive subdomain discovery (subfinder)"
subfinder -d "$TARGET" -silent -duc -config "$SUBFINDER_CONFIG" "${PROVIDER_ARGS[@]}" -o "$SUBDOMAINS_RAW"
filter_scoped_hosts "$SUBDOMAINS_RAW" "$SUBDOMAINS"

if [[ ! -s "$SUBDOMAINS" ]]; then
  log "No subdomains were returned. Writing an empty summary and stopping."
  : > "$HTTP_DETAILS"
  : > "$LIVE_HOSTS"
  : > "$SELECTED_HOSTS"
  : > "$URLS_RAW"
  : > "$URLS"
  : > "$JAVASCRIPT"
else
  log "2/4 HTTP/HTTPS reachability check (httpx-toolkit)"
  httpx-toolkit -l "$SUBDOMAINS" -silent -status-code -title -o "$HTTP_DETAILS"
  filter_scoped_url_lines "$HTTP_DETAILS" "$HTTP_DETAILS.filtered"
  mv "$HTTP_DETAILS.filtered" "$HTTP_DETAILS"
  awk '{print $1}' "$HTTP_DETAILS" | sort -fu > "$LIVE_HOSTS"
  head -n "$MAX_LIVE_HOSTS" "$LIVE_HOSTS" > "$SELECTED_HOSTS"

  if [[ -s "$SELECTED_HOSTS" ]]; then
    log "3/4 Limited URL and JavaScript discovery on up to $MAX_LIVE_HOSTS live hosts (katana)"
    TARGET_REGEX="${TARGET//./\\.}"
    katana -list "$SELECTED_HOSTS" -silent -d "$KATANA_DEPTH" -ct "$KATANA_DURATION" -jc \
      -cs "^https?://([a-z0-9-]+\\.)*${TARGET_REGEX}([/:?#]|$)" -o "$URLS_RAW"
    filter_scoped_url_lines "$URLS_RAW" "$URLS"
    filter_javascript_urls "$URLS" "$JAVASCRIPT"
  else
    log "No live HTTP/HTTPS hosts were found; skipping Katana."
    : > "$URLS_RAW"
    : > "$URLS"
    : > "$JAVASCRIPT"
  fi
fi

log "4/4 Writing summary"
{
  printf 'Recon pipeline summary\n'
  printf 'Target: %s\n' "$TARGET"
  printf 'Run: %s\n' "$TIMESTAMP"
  printf 'Scope confirmation: provided interactively\n'
  printf '\nCounts\n'
  printf 'Subdomains: %s\n' "$(wc -l < "$SUBDOMAINS")"
  printf 'Live HTTP/HTTPS hosts: %s\n' "$(wc -l < "$LIVE_HOSTS")"
  printf 'Hosts sent to Katana: %s\n' "$(wc -l < "$SELECTED_HOSTS")"
  printf 'Unique URLs/endpoints: %s\n' "$(wc -l < "$URLS")"
  printf 'JavaScript URLs: %s\n' "$(wc -l < "$JAVASCRIPT")"
  printf '\nFiles\n'
  printf '%s\n' "$(basename "$SUBDOMAINS")"
  printf '%s\n' "$(basename "$HTTP_DETAILS")"
  printf '%s\n' "$(basename "$LIVE_HOSTS")"
  printf '%s\n' "$(basename "$SELECTED_HOSTS")"
  printf '%s\n' "$(basename "$URLS")"
  printf '%s\n' "$(basename "$JAVASCRIPT")"
} > "$SUMMARY"

log "Done. Read: $SUMMARY"
