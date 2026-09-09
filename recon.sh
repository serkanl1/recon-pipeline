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
  1. passive subdomain discovery (subfinder, + assetfinder if installed)
  2. DNS resolution filter (dnsx, if installed; skipped otherwise)
  3. HTTP/HTTPS reachability check
  4. limited URL and JavaScript discovery (katana, + gau/waybackurls
     archive enrichment if installed)
  5. summary generation

No port scanning, fuzzing, or vulnerability scanning is included.

Optional tools (assetfinder, dnsx, gau, waybackurls) are used automatically
when present on PATH and skipped otherwise. Only subfinder, httpx-toolkit,
and katana are required.
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
  local host raw_count kept_count

  while IFS= read -r host; do
    host="${host,,}"
    host="${host%.}"
    [[ "$host" =~ $DOMAIN_PATTERN ]] || continue
    [[ "$host" == "$TARGET" || "$host" == *."$TARGET" ]] || continue
    printf '%s\n' "$host"
  done < "$input" | LC_ALL=C sort -fu > "$output"

  raw_count=$(wc -l < "$input")
  kept_count=$(wc -l < "$output")
  log "Scope filter (hosts): kept $kept_count of $raw_count raw entries for $TARGET"
}

# Preserve a tool's complete line (such as httpx status/title fields), while
# determining scope from its first URL field.
filter_scoped_url_lines() {
  local input="$1" output="$2"
  local line url raw_count kept_count

  while IFS= read -r line; do
    url="${line%%[[:space:]]*}"
    in_scope_url "$url" || continue
    printf '%s\n' "$line"
  done < "$input" | LC_ALL=C sort -fu > "$output"

  raw_count=$(wc -l < "$input")
  kept_count=$(wc -l < "$output")
  log "Scope filter (URLs): kept $kept_count of $raw_count raw entries for $TARGET"
}

filter_javascript_urls() {
  local input="$1" output="$2"

  # Match the extension after removing a query string/fragment, but retain
  # the original URL so every result can be fetched directly.
  # NOTE: single backslash for a literal dot in the awk ERE — a doubled
  # backslash here would match a literal "\" character instead of ".".
  awk '{
    candidate = tolower($0)
    sub(/[?#].*$/, "", candidate)
    if (candidate ~ /\.(js|mjs|cjs)$/) print $0
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

HAVE_ASSETFINDER=0; command -v assetfinder >/dev/null 2>&1 && HAVE_ASSETFINDER=1
HAVE_DNSX=0; command -v dnsx >/dev/null 2>&1 && HAVE_DNSX=1
HAVE_GAU=0; command -v gau >/dev/null 2>&1 && HAVE_GAU=1
HAVE_WAYBACKURLS=0; command -v waybackurls >/dev/null 2>&1 && HAVE_WAYBACKURLS=1

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
RESOLVED_SUBDOMAINS="$RUN_DIR/01-resolved-subdomains.txt"
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

# ---------------------------------------------------------------------------
# 1/5 Passive subdomain discovery
# ---------------------------------------------------------------------------
log "1/5 Passive subdomain discovery (subfinder$([[ $HAVE_ASSETFINDER -eq 1 ]] && echo ' + assetfinder'))"
subfinder -d "$TARGET" -silent -duc -config "$SUBFINDER_CONFIG" "${PROVIDER_ARGS[@]}" -o "$SUBDOMAINS_RAW"

if [[ $HAVE_ASSETFINDER -eq 1 ]]; then
  assetfinder --subs-only "$TARGET" >> "$SUBDOMAINS_RAW" || true
else
  log "assetfinder not found on PATH; using subfinder results only"
fi

filter_scoped_hosts "$SUBDOMAINS_RAW" "$SUBDOMAINS"

if [[ ! -s "$SUBDOMAINS" ]]; then
  log "No subdomains were returned. Writing an empty summary and stopping."
  : > "$RESOLVED_SUBDOMAINS"
  : > "$HTTP_DETAILS"
  : > "$LIVE_HOSTS"
  : > "$SELECTED_HOSTS"
  : > "$URLS_RAW"
  : > "$URLS"
  : > "$JAVASCRIPT"
else
  # -------------------------------------------------------------------------
  # 2/5 DNS resolution filter (optional)
  # -------------------------------------------------------------------------
  HTTPX_INPUT="$SUBDOMAINS"
  if [[ $HAVE_DNSX -eq 1 ]]; then
    log "2/5 DNS resolution filter (dnsx)"
    dnsx -l "$SUBDOMAINS" -silent -o "$RESOLVED_SUBDOMAINS" || true
    if [[ -s "$RESOLVED_SUBDOMAINS" ]]; then
      HTTPX_INPUT="$RESOLVED_SUBDOMAINS"
    else
      log "dnsx returned no resolvable hosts; falling back to the unresolved subdomain list"
    fi
  else
    log "2/5 DNS resolution filter skipped (dnsx not installed)"
    : > "$RESOLVED_SUBDOMAINS"
  fi

  # -------------------------------------------------------------------------
  # 3/5 HTTP/HTTPS reachability check
  # -------------------------------------------------------------------------
  log "3/5 HTTP/HTTPS reachability check (httpx-toolkit)"
  httpx-toolkit -l "$HTTPX_INPUT" -silent -status-code -title -o "$HTTP_DETAILS"
  filter_scoped_url_lines "$HTTP_DETAILS" "$HTTP_DETAILS.filtered"
  mv "$HTTP_DETAILS.filtered" "$HTTP_DETAILS"
  awk '{print $1}' "$HTTP_DETAILS" | sort -fu > "$LIVE_HOSTS"
  head -n "$MAX_LIVE_HOSTS" "$LIVE_HOSTS" > "$SELECTED_HOSTS"

  if [[ -s "$SELECTED_HOSTS" ]]; then
    # -----------------------------------------------------------------------
    # 4/5 URL and JavaScript discovery
    # -----------------------------------------------------------------------
    ARCHIVE_NOTE=""
    [[ $HAVE_GAU -eq 1 ]] && ARCHIVE_NOTE=" + gau"
    [[ $HAVE_GAU -eq 0 && $HAVE_WAYBACKURLS -eq 1 ]] && ARCHIVE_NOTE=" + waybackurls"
    log "4/5 Limited URL and JavaScript discovery on up to $MAX_LIVE_HOSTS live hosts (katana$ARCHIVE_NOTE)"
    TARGET_REGEX="${TARGET//./\\.}"
    katana -list "$SELECTED_HOSTS" -silent -d "$KATANA_DEPTH" -ct "$KATANA_DURATION" -jc \
      -cs "^https?://([a-z0-9-]+\\.)*${TARGET_REGEX}([/:?#]|$)" -o "$URLS_RAW"

    if [[ $HAVE_GAU -eq 1 ]]; then
      gau --subs "$TARGET" >> "$URLS_RAW" 2>/dev/null || true
    elif [[ $HAVE_WAYBACKURLS -eq 1 ]]; then
      printf '%s\n' "$TARGET" | waybackurls >> "$URLS_RAW" 2>/dev/null || true
    else
      log "gau/waybackurls not found on PATH; skipping archive URL enrichment"
    fi

    filter_scoped_url_lines "$URLS_RAW" "$URLS"
    filter_javascript_urls "$URLS" "$JAVASCRIPT"
  else
    log "No live HTTP/HTTPS hosts were found; skipping Katana."
    : > "$URLS_RAW"
    : > "$URLS"
    : > "$JAVASCRIPT"
  fi
fi

log "5/5 Writing summary"
{
  printf 'Recon pipeline summary\n'
  printf 'Target: %s\n' "$TARGET"
  printf 'Run: %s\n' "$TIMESTAMP"
  printf 'Scope confirmation: provided interactively\n'
  printf 'Optional tools used: assetfinder=%s dnsx=%s gau=%s waybackurls=%s\n' \
    "$([[ $HAVE_ASSETFINDER -eq 1 ]] && echo yes || echo no)" \
    "$([[ $HAVE_DNSX -eq 1 ]] && echo yes || echo no)" \
    "$([[ $HAVE_GAU -eq 1 ]] && echo yes || echo no)" \
    "$([[ $HAVE_WAYBACKURLS -eq 1 ]] && echo yes || echo no)"
  printf '\nCounts\n'
  printf 'Subdomains (in scope): %s\n' "$(wc -l < "$SUBDOMAINS")"
  printf 'Resolved subdomains (dnsx): %s\n' "$(wc -l < "$RESOLVED_SUBDOMAINS")"
  printf 'Live HTTP/HTTPS hosts: %s\n' "$(wc -l < "$LIVE_HOSTS")"
  printf 'Hosts sent to Katana: %s\n' "$(wc -l < "$SELECTED_HOSTS")"
  printf 'Unique URLs/endpoints: %s\n' "$(wc -l < "$URLS")"
  printf 'JavaScript URLs: %s\n' "$(wc -l < "$JAVASCRIPT")"
  printf '\nFiles\n'
  printf '%s (raw, unfiltered)\n' "$(basename "$SUBDOMAINS_RAW")"
  printf '%s (in scope)\n' "$(basename "$SUBDOMAINS")"
  printf '%s\n' "$(basename "$RESOLVED_SUBDOMAINS")"
  printf '%s\n' "$(basename "$HTTP_DETAILS")"
  printf '%s\n' "$(basename "$LIVE_HOSTS")"
  printf '%s\n' "$(basename "$SELECTED_HOSTS")"
  printf '%s (raw, unfiltered)\n' "$(basename "$URLS_RAW")"
  printf '%s (in scope)\n' "$(basename "$URLS")"
  printf '%s\n' "$(basename "$JAVASCRIPT")"
} > "$SUMMARY"

log "Done. Read: $SUMMARY"
