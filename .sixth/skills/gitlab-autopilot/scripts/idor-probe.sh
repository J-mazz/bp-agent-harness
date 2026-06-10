#!/usr/bin/env bash
# idor-probe.sh — scope-gated Broken-Object-Level-Authorization (IDOR/BOLA) tests
# against the local GitLab lab fixtures. GET-only, non-destructive, IP-pinned.
#
# A non-admin (bob/carol/anon) receiving HTTP 200 on a resource they should not
# see is a SECURITY FINDING. Positive controls confirm legitimate access works.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"
VM_IP="${VM_IP:-192.168.122.7}"
BASE="http://${VM_IP}"
PROGRAM="local-lab"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
TOK_ENV="${TOK_ENV:-$HOME/.gl_fixtures_tokens.env}"
ADMIN_TOK_FILE="${ADMIN_TOK_FILE:-$HOME/.gl_ro_token}"

TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT="${OUT:-${REPO_ROOT}/findings/${PROGRAM}/${TS}/idor}"
mkdir -p "$OUT"; BODY="$OUT/.body"

c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_rst=$'\033[0m'
log(){ printf '%s\n' "$*" >&2; }

# --- scope gate (shared, safety-critical parser lives in scope-lib.sh) --------
# shellcheck source=/dev/null
. "${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/scope-lib.sh"
scope_guard "$VM_IP" "$SCOPE_FILE" "$GUARD" >/dev/null || { log "SCOPE BLOCKED $VM_IP"; exit 1; }
log "Scope OK: $VM_IP ALLOWED — IDOR/BOLA suite (GET-only)"

# --- tokens -------------------------------------------------------------------
# shellcheck disable=SC1090
source "$TOK_ENV"
declare -A TOK=( [alice]="${alice:-}" [bob]="${bob:-}" [carol]="${carol:-}" [admin]="$(tr -d '\r\n' < "$ADMIN_TOK_FILE")" [anon]="" )

PASS=0; FAIL=0; FINDING=0
req(){ # who method path  -> echoes http_code, writes body to $BODY
  local who="$1" method="$2" path="$3" tok="${TOK[$1]}"
  local h=(-H "Accept: application/json")
  [ -n "$tok" ] && h+=(-H "PRIVATE-TOKEN: $tok")
  curl -s -o "$BODY" -w '%{http_code}' --max-time 15 --connect-timeout 5 -X "$method" "${h[@]}" "$BASE$path"
}

# check WHO METHOD PATH EXPECT_REGEX DESC
check(){
  local who="$1" method="$2" path="$3" expect="$4" desc="$5"
  local code; code="$(req "$who" "$method" "$path")"
  if [[ "$code" =~ ^($expect)$ ]]; then
    printf '%sPASS%s [%-5s] %s %-58s -> %s  :: %s\n' "$c_grn" "$c_rst" "$who" "$method" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"
    PASS=$((PASS+1))
  elif [[ "$expect" == *"404"* || "$expect" == *"403"* || "$expect" == *"401"* ]] && [ "$code" = "200" ]; then
    printf '%sFINDING%s [%-5s] %s %-58s -> %s (expected %s) :: %s  <== UNAUTHORIZED ACCESS\n' "$c_red" "$c_rst" "$who" "$method" "$path" "$code" "$expect" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/finding_${who}_$(echo "$path" | tr '/?=&' '____').json" 2>/dev/null || true
    FINDING=$((FINDING+1))
  else
    printf '%sMISMATCH%s [%-5s] %s %-58s -> %s (expected %s) :: %s\n' "$c_yel" "$c_rst" "$who" "$method" "$path" "$code" "$expect" "$desc" | tee -a "$OUT/RESULTS.txt"
    FAIL=$((FAIL+1))
  fi
}

# body-absence assertion: WHO PATH NEEDLE DESC  (non-admin listing must NOT leak NEEDLE)
absent(){
  local who="$1" path="$2" needle="$3" desc="$4"
  local code; code="$(req "$who" GET "$path")"
  if [ "$code" = "200" ] && ! grep -q "$needle" "$BODY"; then
    printf '%sPASS%s [%-5s] GET %-54s -> 200, %q absent :: %s\n' "$c_grn" "$c_rst" "$who" "$path" "$needle" "$desc" | tee -a "$OUT/RESULTS.txt"; PASS=$((PASS+1))
  elif grep -q "$needle" "$BODY" 2>/dev/null; then
    printf '%sFINDING%s [%-5s] GET %-54s leaks %q :: %s  <== PRIVATE RESOURCE IN LISTING\n' "$c_red" "$c_rst" "$who" "$path" "$needle" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/leak_${who}.json" 2>/dev/null || true; FINDING=$((FINDING+1))
  else
    printf '%sMISMATCH%s [%-5s] GET %-54s -> %s :: %s\n' "$c_yel" "$c_rst" "$who" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"; FAIL=$((FAIL+1))
  fi
}

gql(){ # who query expect_null_path desc
  local who="$1" q="$2" jqpath="$3" desc="$4" tok="${TOK[$1]}"
  local code; code="$(curl -s -o "$BODY" -w '%{http_code}' --max-time 15 \
    -H "Content-Type: application/json" ${tok:+-H "PRIVATE-TOKEN: $tok"} \
    -X POST "$BASE/api/graphql" --data "{\"query\":\"$q\"}")"
  local val; val="$(jq -r "$jqpath" "$BODY" 2>/dev/null)"
  if [ "$val" = "null" ] || [ -z "$val" ]; then
    printf '%sPASS%s [%-5s] GraphQL %-50s -> null :: %s\n' "$c_grn" "$c_rst" "$who" "$jqpath" "$desc" | tee -a "$OUT/RESULTS.txt"; PASS=$((PASS+1))
  else
    printf '%sFINDING%s [%-5s] GraphQL %-50s -> %q :: %s  <== UNAUTHORIZED FIELD\n' "$c_red" "$c_rst" "$who" "$jqpath" "$val" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/gqlfinding_${who}.json" 2>/dev/null || true; FINDING=$((FINDING+1))
  fi
}

: > "$OUT/RESULTS.txt"
log "=== POSITIVE CONTROLS (legitimate access must succeed) ==="
check alice GET "/api/v4/projects/1"                 200       "owner reads own private project (secret-app)"
check alice GET "/api/v4/projects/1/issues/1"        200       "author reads own confidential issue"
check anon  GET "/api/v4/projects/4"                 200       "anon reads PUBLIC project (public-site)"
check bob   GET "/api/v4/projects/8"                 200       "authed user reads INTERNAL project (team-wiki)"
check carol GET "/api/v4/projects/8"                 200       "authed user reads INTERNAL project (team-wiki)"

log "=== IDOR/BOLA: private project objects (expect 404) ==="
check anon  GET "/api/v4/projects/8"                 "401|404" "anon must NOT read INTERNAL project (team-wiki)"
check bob   GET "/api/v4/projects/3"                 "403|404" "bob reads private-in-private-group project (internal-lib clamped to private)"
check bob   GET "/api/v4/projects/1"                 "403|404" "bob reads alice PRIVATE project"
check carol GET "/api/v4/projects/1"                 "403|404" "carol reads alice PRIVATE project"
check anon  GET "/api/v4/projects/1"                 "401|404" "anon reads alice PRIVATE project"
check carol GET "/api/v4/projects/2"                 "403|404" "carol reads bob PRIVATE project (secret-tool)"

log "=== IDOR/BOLA: confidential issue (expect 404) ==="
check bob   GET "/api/v4/projects/1/issues/1"        "403|404" "bob reads alice CONFIDENTIAL issue"
check carol GET "/api/v4/projects/1/issues/1"        "403|404" "carol reads alice CONFIDENTIAL issue"
check bob   GET "/api/v4/projects/1/issues"          "403|404" "bob lists alice private project issues"

log "=== IDOR/BOLA: private group (expect 404) ==="
check bob   GET "/api/v4/groups/6"                   "403|404" "bob reads PRIVATE group (engineering)"
check carol GET "/api/v4/groups/6"                   "403|404" "carol reads PRIVATE group (engineering)"

log "=== IDOR/BOLA: private snippet (expect 404) ==="
check bob   GET "/api/v4/snippets/1"                 "403|404" "bob reads alice PRIVATE personal snippet"
check bob   GET "/api/v4/snippets/1/raw"             "403|404" "bob reads alice PRIVATE snippet RAW content"
check carol GET "/api/v4/snippets/1/raw"             "403|404" "carol reads alice PRIVATE snippet RAW content"

log "=== IDOR/BOLA: private repo content (expect 404) ==="
check bob   GET "/api/v4/projects/5/repository/tree"          "403|404" "bob lists alice private repo tree (mirror-hello)"
check bob   GET "/api/v4/projects/5/repository/files/README%2Emd/raw?ref=master" "403|404" "bob reads alice private repo raw file"
check carol GET "/api/v4/projects/6/repository/tree"          "403|404" "carol lists bob private repo tree (mirror-spoon)"

log "=== Listing leakage (private projects must NOT appear) ==="
absent carol "/api/v4/projects?per_page=100&simple=true" "secret-app"  "carol project listing excludes alice private"
absent carol "/api/v4/projects?per_page=100&simple=true" "secret-tool" "carol project listing excludes bob private"
absent anon  "/api/v4/projects?per_page=100&simple=true" "secret-app"  "anon project listing excludes private"

log "=== GraphQL field-level authz (expect null) ==="
gql bob   "query{project(fullPath:\\\"alice/secret-app\\\"){id name}}"            ".data.project.name"  "bob GraphQL reads alice private project"
gql carol "query{project(fullPath:\\\"bob/secret-tool\\\"){id name}}"             ".data.project.name"  "carol GraphQL reads bob private project"
gql anon  "query{project(fullPath:\\\"alice/secret-app\\\"){id name}}"            ".data.project.name"  "anon GraphQL reads alice private project"

rm -f "$BODY"
echo
printf '%s========== IDOR/BOLA SUMMARY ==========%s\n' "$c_grn" "$c_rst" | tee -a "$OUT/RESULTS.txt"
printf 'PASS=%d  MISMATCH=%d  FINDINGS=%d\n' "$PASS" "$FAIL" "$FINDING" | tee -a "$OUT/RESULTS.txt"
if [ "$FINDING" -gt 0 ]; then
  printf '%s*** %d SECURITY FINDING(S) — review %s/finding_* ***%s\n' "$c_red" "$FINDING" "$OUT" "$c_rst" | tee -a "$OUT/RESULTS.txt"
else
  printf '%sNo authorization bypass found — all private resources correctly denied.%s\n' "$c_grn" "$c_rst" | tee -a "$OUT/RESULTS.txt"
fi
echo "$OUT"
