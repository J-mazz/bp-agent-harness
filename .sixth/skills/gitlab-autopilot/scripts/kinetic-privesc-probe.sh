#!/usr/bin/env bash
# kinetic-privesc-probe.sh — SCOPE-GATED, state-changing tests for the 3 GitLab
# finding classes: (1) authz/role escalation, (2) GraphQL/REST IDOR (write side),
# (3) CI/CD privilege escalation. Owned local VM only; VM egress is host-blocked.
#
# Each low-privilege WRITE is attempted then classified:
#   * 403/404  -> correctly DENIED (PASS, nothing changed)
#   * 2xx      -> FINDING (privesc/IDOR) — evidence captured AND auto-reverted
#                  with alice (project OWNER) so fixtures stay intact.
# No DoS, no project deletion. Reversible by construction.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"
VM_IP="${VM_IP:-192.168.122.7}"
BASE="http://${VM_IP}"
PROGRAM="local-lab"
PROJ="${PROJ:-9}"; PROJ_PATH="alice/shared-app"
FOREIGN1="${FOREIGN1:-1}"; FOREIGN2="${FOREIGN2:-2}"   # projects the roles are NOT members of
CAROL_ID="${CAROL_ID:-5}"; DAVE_ID="${DAVE_ID:-6}"; BOB_ID="${BOB_ID:-4}"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
SCOPE_LIB="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/scope-lib.sh"
EGRESS_VERIFY="${REPO_ROOT}/.sixth/skills/gitlab-test-vm/scripts/egress-verify.sh"
SSH_USER="${SSH_USER:-debian}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
TOK_ENV="${TOK_ENV:-$HOME/.gl_role_tokens.env}"

TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT="${OUT:-${REPO_ROOT}/findings/${PROGRAM}/${TS}/kinetic-privesc}"
mkdir -p "$OUT"; BODY="$OUT/.body"

c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_rst=$'\033[0m'
log(){ printf '%s\n' "$*" >&2; }

# --- scope gate (shared, safety-critical parser lives in scope-lib.sh) --------
# shellcheck source=/dev/null
. "$SCOPE_LIB"
scope_guard "$VM_IP" "$SCOPE_FILE" "$GUARD" >/dev/null || { log "SCOPE BLOCKED $VM_IP"; exit 1; }
log "Scope OK: $VM_IP ALLOWED — KINETIC privesc/IDOR suite (write, auto-revert)"

# --- egress containment assertion (FAIL CLOSED before any write) --------------
# Delegated to egress-verify.sh, which proves over SSH (honouring SSH_USER/
# SSH_KEY) that the VM cannot reach off-host and treats ANY uncertainty — SSH
# failure, missing curl, indeterminate result — as ABORT. The old inline check
# was fail-OPEN: a non-zero ssh for any reason was misread as "contained".
VM_IP="$VM_IP" SSH_USER="$SSH_USER" SSH_KEY="$SSH_KEY" bash "$EGRESS_VERIFY" || {
  log "${c_red}ABORT: VM egress containment is UNPROVEN — run egress-lockdown.sh apply first.${c_rst}"; exit 3
}
log "Egress containment verified: VM cannot reach the internet."

# --- tokens -------------------------------------------------------------------
# shellcheck disable=SC1090
source "$TOK_ENV"
declare -A TOK=( [alice]="${ALICE_TOKEN:-}" [bob]="${BOB_TOKEN:-}" [carol]="${CAROL_TOKEN:-}" [dave]="${DAVE_TOKEN:-}" [anon]="" )
declare -A ROLE=( [alice]="OWNER(50)" [bob]="DEVELOPER(30)" [dave]="REPORTER(20)" [carol]="GUEST(10)" [anon]="ANON" )

PASS=0; FAIL=0; FINDING=0
api(){ # who method path [data]
  local who="$1" method="$2" path="$3" data="${4:-}" tok="${TOK[$1]}"
  local h=(-H "Accept: application/json")
  [ -n "$tok" ] && h+=(-H "PRIVATE-TOKEN: $tok")
  [ -n "$data" ] && h+=(-H "Content-Type: application/json")
  curl -s -o "$BODY" -w '%{http_code}' --max-time 20 --connect-timeout 5 -X "$method" "${h[@]}" \
    ${data:+--data "$data"} "$BASE$path"
}

# wcheck WHO METHOD PATH DATA DESC [REVERT_CMD]
# expectation: write must be DENIED (403/404/401). 2xx => FINDING; run REVERT_CMD.
wcheck(){
  local who="$1" method="$2" path="$3" data="$4" desc="$5" revert="${6:-}"
  local code; code="$(api "$who" "$method" "$path" "$data")"
  if [[ "$code" =~ ^(401|403|404|405|422)$ ]]; then
    printf '%sPASS%s [%-12s] %-6s %-46s -> %s (denied) :: %s\n' "$c_grn" "$c_rst" "${ROLE[$who]}" "$method" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"
    PASS=$((PASS+1))
  elif [[ "$code" =~ ^2 ]]; then
    printf '%sFINDING%s [%-12s] %-6s %-46s -> %s :: %s  <== UNAUTHORIZED WRITE\n' "$c_red" "$c_rst" "${ROLE[$who]}" "$method" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/finding_${who}_${method}_$(echo "$path" | tr '/?=&' '____').json" 2>/dev/null || true
    FINDING=$((FINDING+1))
    if [ -n "$revert" ]; then log "  -> reverting: $revert"; eval "$revert" >/dev/null 2>&1 && log "  -> reverted." || log "  -> REVERT FAILED, manual cleanup needed."; fi
  else
    printf '%sMISMATCH%s [%-12s] %-6s %-46s -> %s :: %s\n' "$c_yel" "$c_rst" "${ROLE[$who]}" "$method" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"
    FAIL=$((FAIL+1))
  fi
}

: > "$OUT/RESULTS.txt"

log "=== (1) AUTHZ/ROLE ESCALATION — CI variable writes need MAINTAINER(40)+ ==="
wcheck bob   POST   "/api/v4/projects/${PROJ}/variables" '{"key":"PWN_DEV","value":"x"}'   "DEVELOPER creates CI variable" \
  "api alice DELETE /api/v4/projects/${PROJ}/variables/PWN_DEV"
wcheck dave  POST   "/api/v4/projects/${PROJ}/variables" '{"key":"PWN_REP","value":"x"}'   "REPORTER creates CI variable" \
  "api alice DELETE /api/v4/projects/${PROJ}/variables/PWN_REP"
wcheck carol POST   "/api/v4/projects/${PROJ}/variables" '{"key":"PWN_GST","value":"x"}'   "GUEST creates CI variable" \
  "api alice DELETE /api/v4/projects/${PROJ}/variables/PWN_GST"
wcheck bob   PUT    "/api/v4/projects/${PROJ}/variables/NORMAL_VAR" '{"value":"tampered"}'  "DEVELOPER updates existing CI variable" \
  "api alice PUT /api/v4/projects/${PROJ}/variables/NORMAL_VAR '{\"value\":\"normal_value\"}'"
wcheck bob   DELETE "/api/v4/projects/${PROJ}/variables/MASKED_SECRET" '' "DEVELOPER deletes MASKED CI variable" \
  "api alice POST /api/v4/projects/${PROJ}/variables '{\"key\":\"MASKED_SECRET\",\"value\":\"FAKEMASKEDSECRET12345678\",\"masked\":true}'"

log "=== (1) AUTHZ — membership self-escalation (needs OWNER/MAINTAINER) ==="
wcheck carol PUT  "/api/v4/projects/${PROJ}/members/${CAROL_ID}" '{"access_level":50}' "GUEST escalates SELF to OWNER" \
  "api alice PUT /api/v4/projects/${PROJ}/members/${CAROL_ID} '{\"access_level\":10}'"
wcheck dave  PUT  "/api/v4/projects/${PROJ}/members/${DAVE_ID}"  '{"access_level":40}' "REPORTER escalates SELF to MAINTAINER" \
  "api alice PUT /api/v4/projects/${PROJ}/members/${DAVE_ID} '{\"access_level\":20}'"
wcheck bob   POST "/api/v4/projects/${PROJ}/members" '{"user_id":'"${DAVE_ID}"',"access_level":50}' "DEVELOPER adds a co-OWNER" \
  "api alice DELETE /api/v4/projects/${PROJ}/members/${DAVE_ID}; api alice POST /api/v4/projects/${PROJ}/members '{\"user_id\":${DAVE_ID},\"access_level\":20}'"

log "=== (1+3) CI/CD — triggers, deploy tokens, branch protection (need MAINTAINER+) ==="
wcheck bob   POST   "/api/v4/projects/${PROJ}/triggers" '{"description":"pwn"}'            "DEVELOPER creates pipeline trigger" ""
wcheck bob   POST   "/api/v4/projects/${PROJ}/deploy_tokens" '{"name":"pwn","scopes":["read_repository"]}' "DEVELOPER creates deploy token" ""
wcheck bob   DELETE "/api/v4/projects/${PROJ}/protected_branches/main" ''                  "DEVELOPER unprotects main branch" \
  "api alice POST '/api/v4/projects/${PROJ}/protected_branches' '{\"name\":\"main\",\"push_access_level\":40,\"merge_access_level\":40}'"
wcheck dave  POST   "/api/v4/projects/${PROJ}/runners" '{}'                                "REPORTER creates a runner" ""

log "=== (2) IDOR (write) — non-members acting on FOREIGN private projects ==="
wcheck bob   POST "/api/v4/projects/${FOREIGN1}/issues" '{"title":"idor"}'                 "DEVELOPER@9 creates issue in foreign proj ${FOREIGN1}" ""
wcheck bob   PUT  "/api/v4/projects/${FOREIGN1}" '{"description":"idor"}'                   "DEVELOPER@9 edits foreign project ${FOREIGN1}" ""
wcheck carol POST "/api/v4/projects/${FOREIGN1}/issues/1/notes" '{"body":"idor"}'          "GUEST@9 comments on foreign confidential issue ${FOREIGN1}/1" ""
wcheck dave  POST "/api/v4/projects/${FOREIGN2}/variables" '{"key":"IDOR","value":"x"}'    "REPORTER@9 creates CI var in foreign proj ${FOREIGN2}" ""

log "=== (2) IDOR (write) — GraphQL mutation on foreign project ==="
gqlmut(){ # who query desc
  local who="$1" q="$2" desc="$3" tok="${TOK[$1]}"
  curl -s -o "$BODY" -w '%{http_code}' --max-time 20 -H "Content-Type: application/json" \
    ${tok:+-H "PRIVATE-TOKEN: $tok"} -X POST "$BASE/api/graphql" --data "{\"query\":\"$q\"}" >/dev/null
  local errs; errs="$(jq -r '.errors[0].message // (.data|to_entries[0].value.errors[0]) // empty' "$BODY" 2>/dev/null)"
  local created; created="$(jq -r '.data|to_entries[0].value // {} | (.issue.iid // .project.id // empty)' "$BODY" 2>/dev/null)"
  if [ -n "$errs" ] || [ -z "$created" ]; then
    printf '%sPASS%s [%-12s] GraphQL mutation denied :: %s\n' "$c_grn" "$c_rst" "${ROLE[$who]}" "$desc" | tee -a "$OUT/RESULTS.txt"; PASS=$((PASS+1))
  else
    printf '%sFINDING%s [%-12s] GraphQL mutation SUCCEEDED (%s) :: %s  <== IDOR WRITE\n' "$c_red" "$c_rst" "${ROLE[$who]}" "$created" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/gqlfinding_${who}.json" 2>/dev/null || true; FINDING=$((FINDING+1))
  fi
}
gqlmut bob "mutation{createIssue(input:{projectPath:\\\"alice/secret-app\\\",title:\\\"idor\\\"}){issue{iid}errors}}" "DEVELOPER GraphQL createIssue on foreign private project"

rm -f "$BODY"
echo
printf '%s========== KINETIC PRIVESC / IDOR SUMMARY ==========%s\n' "$c_grn" "$c_rst" | tee -a "$OUT/RESULTS.txt"
printf 'PASS(denied)=%d  MISMATCH=%d  FINDINGS=%d\n' "$PASS" "$FAIL" "$FINDING" | tee -a "$OUT/RESULTS.txt"
if [ "$FINDING" -gt 0 ]; then
  printf '%s*** %d FINDING(S) — review %s/finding_* (objects auto-reverted) ***%s\n' "$c_red" "$FINDING" "$OUT" "$c_rst" | tee -a "$OUT/RESULTS.txt"
else
  printf '%sNo privilege escalation / IDOR write — every unauthorized write correctly denied.%s\n' "$c_grn" "$c_rst" | tee -a "$OUT/RESULTS.txt"
fi
echo "$OUT"
