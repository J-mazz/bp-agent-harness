#!/usr/bin/env bash
# auth-api-probe.sh — scope-gated, READ-ONLY authenticated REST API probe of the
# local GitLab lab VM (program: local-lab, 192.168.122.7).
#
# SAFETY (matches AGENTS.md rules of engagement):
#   - Target is hard-pinned to the lab VM IP; every base call is verified against
#     scope-authorization-guard before any request is sent.
#   - GET requests ONLY. No POST/PUT/PATCH/DELETE — this never mutates lab state.
#   - Uses a read_api token minted on the lab (revocable). Token is read from a
#     600-perm file and never printed.
#   - --max-time on every request; serial; courteous. No off-host follow.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"

VM_IP="${VM_IP:-192.168.122.7}"
BASE="http://${VM_IP}"
PROGRAM="local-lab"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.gl_ro_token}"

TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT="${OUT:-${REPO_ROOT}/findings/${PROGRAM}/${TS}/dast-auth}"
mkdir -p "$OUT"

log()  { printf '\033[1;34m[auth-probe]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[auth-probe]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[auth-probe] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- scope gate (same parser as autopilot) -----------------------------------
scope_list() {
  awk -v sec="$1" '
    $0 ~ "^"sec":" { inblk=1; next }
    inblk && /^[a-z_]+:/ && $0 !~ /^[[:space:]]/ { inblk=0 }
    inblk { line=$0; sub(/#.*/,"",line);
      if (line ~ /^[[:space:]]*-[[:space:]]*/){ sub(/^[[:space:]]*-[[:space:]]*/,"",line); gsub(/[" ]/,"",line); if(line!="") print line } }
  ' "$SCOPE_FILE"
}
IN_LIST="$(scope_list in_scope | paste -sd, -)"
OUT_LIST="$(scope_list out_of_scope | paste -sd, -)"
[ -n "$IN_LIST" ] || die "in_scope empty in $SCOPE_FILE"
node "$GUARD" --target "$VM_IP" --in "$IN_LIST" --out "$OUT_LIST" >/dev/null \
  || die "scope guard BLOCKED $VM_IP — refusing to run."
log "Scope OK: $VM_IP ALLOWED (read-only authenticated probe)."

[ -s "$TOKEN_FILE" ] || die "token file $TOKEN_FILE missing/empty (mint a read_api PAT first)."
TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"

# --- GET-only request helper --------------------------------------------------
# get <slug> <path-with-leading-slash>
get() {
  local slug="$1" path="$2"
  local url="${BASE}${path}"
  # Defense in depth: re-pin host. The path is constructed locally, never from
  # a server response, so it cannot redirect us off-host.
  local code
  code=$(curl -s -o "$OUT/${slug}.json" -w '%{http_code}' \
    --max-time 15 --connect-timeout 5 \
    -H "PRIVATE-TOKEN: ${TOKEN}" -H "Accept: application/json" \
    -X GET "$url")
  printf '%-32s GET %-44s -> HTTP %s\n' "$slug" "$path" "$code" | tee -a "$OUT/INDEX.txt"
}

log "Writing results to $OUT"
: > "$OUT/INDEX.txt"

# --- 1. identity / instance metadata -----------------------------------------
get version                 "/api/v4/version"
get metadata                "/api/v4/metadata"
get current_user            "/api/v4/user"
get user_prefs              "/api/v4/user/preferences"
get personal_tokens_self    "/api/v4/personal_access_tokens/self"

# --- 2. broad listings (authz surface — what can this token enumerate?) -------
get projects_all            "/api/v4/projects?per_page=100&simple=true"
get projects_membership     "/api/v4/projects?membership=true&per_page=100"
get groups_all              "/api/v4/groups?per_page=100"
get users_list              "/api/v4/users?per_page=100"
get snippets_public         "/api/v4/snippets/public?per_page=50"

# --- 3. admin-only endpoints (token is non-admin read_api -> expect 403) ------
#     A 200 here on a non-admin token would be a real privilege-escalation finding.
get admin_settings          "/api/v4/application/settings"
get admin_statistics        "/api/v4/application/statistics"
get admin_appearance        "/api/v4/application/appearance"
get admin_ci_variables      "/api/v4/admin/ci/variables"

# --- 4. feature/auth probes ---------------------------------------------------
get features                "/api/v4/features"
get broadcast_messages      "/api/v4/broadcast_messages"
get keys_self               "/api/v4/user/keys"
get gpg_keys_self           "/api/v4/user/gpg_keys"

log "Done. Index:"
cat "$OUT/INDEX.txt" >&2

# --- quick triage hints -------------------------------------------------------
log "Triage hints (unexpected authorizations):"
awk '
  /^admin_/ && / 200$/ { print "  [!] ADMIN endpoint returned 200 on read_api token: " $0 }
  / 500$/ { print "  [?] 500 (server error worth a look): " $0 }
' "$OUT/INDEX.txt" >&2 || true
echo "$OUT"
