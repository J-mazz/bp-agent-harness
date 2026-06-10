#!/usr/bin/env bash
# role-privesc-probe.sh — scope-gated tests for the ONLY three GitLab finding
# classes that matter here: (1) authz/role-boundary bypass, (2) GraphQL/REST
# IDOR/BOLA, (3) CI/CD privilege escalation. GET-only, non-destructive, IP-pinned.
#
# Surface: alice/shared-app (project id 9) with a DISTINCT-role membership ladder:
#   alice=OWNER(50)  bob=DEVELOPER(30)  dave=REPORTER(20)  carol=GUEST(10)
# CI/CD objects: NORMAL_VAR, PROTECTED_TOKEN(protected), MASKED_SECRET(masked),
#   pipeline trigger token, protected branch `main` (push/merge = MAINTAINER).
#
# RULE: a role BELOW the documented minimum receiving 200 + privileged data is a
# FINDING. CI/CD variables & triggers require MAINTAINER(40)+. Guest cannot read
# repository code in a private project. Positive controls confirm legit access.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"
VM_IP="${VM_IP:-192.168.122.7}"
BASE="http://${VM_IP}"
PROGRAM="local-lab"
PROJ="${PROJ:-9}"                     # alice/shared-app
PROJ_PATH="alice/shared-app"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
TOK_ENV="${TOK_ENV:-$HOME/.gl_role_tokens.env}"

TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT="${OUT:-${REPO_ROOT}/findings/${PROGRAM}/${TS}/role-privesc}"
mkdir -p "$OUT"; BODY="$OUT/.body"

c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_rst=$'\033[0m'
log(){ printf '%s\n' "$*" >&2; }

# --- scope gate (default-deny; out_of_scope wins) -----------------------------
scope_list(){ awk -v sec="$1" '
  $0 ~ "^"sec":" { inblk=1; next }
  inblk && /^[a-z_]+:/ && $0 !~ /^[[:space:]]/ { inblk=0 }
  inblk { line=$0; sub(/#.*/,"",line);
    if (line ~ /^[[:space:]]*-[[:space:]]*/){ sub(/^[[:space:]]*-[[:space:]]*/,"",line); gsub(/[" ]/,"",line); if(line!="") print line } }
' "$SCOPE_FILE"; }
IN="$(scope_list in_scope | paste -sd, -)"; OUT_L="$(scope_list out_of_scope | paste -sd, -)"
node "$GUARD" --target "$VM_IP" --in "$IN" --out "$OUT_L" >/dev/null || { log "SCOPE BLOCKED $VM_IP"; exit 1; }
log "Scope OK: $VM_IP ALLOWED — role/authz/IDOR/CI-CD-privesc suite (GET-only)"

# --- tokens -------------------------------------------------------------------
# shellcheck disable=SC1090
source "$TOK_ENV"
declare -A TOK=( [alice]="${ALICE_TOKEN:-}" [bob]="${BOB_TOKEN:-}" [carol]="${CAROL_TOKEN:-}" [dave]="${DAVE_TOKEN:-}" [anon]="" )
declare -A ROLE=( [alice]="OWNER(50)" [bob]="DEVELOPER(30)" [dave]="REPORTER(20)" [carol]="GUEST(10)" [anon]="ANON" )

PASS=0; FAIL=0; FINDING=0
req(){ # who method path
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
    printf '%sPASS%s [%-12s] %s %-52s -> %s  :: %s\n' "$c_grn" "$c_rst" "${ROLE[$who]}" "$method" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"
    PASS=$((PASS+1))
  elif [[ "$expect" == *"404"* || "$expect" == *"403"* || "$expect" == *"401"* ]] && [ "$code" = "200" ]; then
    printf '%sFINDING%s [%-12s] %s %-52s -> %s (expected %s) :: %s  <== AUTHZ BYPASS\n' "$c_red" "$c_rst" "${ROLE[$who]}" "$method" "$path" "$code" "$expect" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/finding_${who}_$(echo "$path" | tr '/?=&' '____').json" 2>/dev/null || true
    FINDING=$((FINDING+1))
  else
    printf '%sMISMATCH%s [%-12s] %s %-52s -> %s (expected %s) :: %s\n' "$c_yel" "$c_rst" "${ROLE[$who]}" "$method" "$path" "$code" "$expect" "$desc" | tee -a "$OUT/RESULTS.txt"
    FAIL=$((FAIL+1))
  fi
}

# leak WHO PATH NEEDLE DESC — non-privileged role's 200 body must NOT contain NEEDLE
# (privilege escalation: secret value disclosed to a role below MAINTAINER)
leak(){
  local who="$1" path="$2" needle="$3" desc="$4"
  local code; code="$(req "$who" GET "$path")"
  if grep -qF "$needle" "$BODY" 2>/dev/null; then
    printf '%sFINDING%s [%-12s] GET %-48s leaks %q :: %s  <== CI/CD SECRET DISCLOSURE\n' "$c_red" "$c_rst" "${ROLE[$who]}" "$path" "$needle" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/leak_${who}_$(echo "$path" | tr '/?=&' '____').json" 2>/dev/null || true; FINDING=$((FINDING+1))
  else
    printf '%sPASS%s [%-12s] GET %-48s -> %s, secret absent :: %s\n' "$c_grn" "$c_rst" "${ROLE[$who]}" "$path" "$code" "$desc" | tee -a "$OUT/RESULTS.txt"; PASS=$((PASS+1))
  fi
}

# gqlfield WHO QUERY JQPATH DESC — expect empty/null for roles below threshold
gql(){
  local who="$1" q="$2" jqpath="$3" desc="$4" tok="${TOK[$1]}"
  curl -s -o "$BODY" -w '%{http_code}' --max-time 15 \
    -H "Content-Type: application/json" ${tok:+-H "PRIVATE-TOKEN: $tok"} \
    -X POST "$BASE/api/graphql" --data "{\"query\":\"$q\"}" >/dev/null
  local val; val="$(jq -r "$jqpath" "$BODY" 2>/dev/null)"
  if [ "$val" = "null" ] || [ -z "$val" ]; then
    printf '%sPASS%s [%-12s] GraphQL %-44s -> null :: %s\n' "$c_grn" "$c_rst" "${ROLE[$who]}" "$jqpath" "$desc" | tee -a "$OUT/RESULTS.txt"; PASS=$((PASS+1))
  else
    printf '%sFINDING%s [%-12s] GraphQL %-44s -> %q :: %s  <== UNAUTHORIZED FIELD\n' "$c_red" "$c_rst" "${ROLE[$who]}" "$jqpath" "$val" "$desc" | tee -a "$OUT/RESULTS.txt"
    cp "$BODY" "$OUT/gqlfinding_${who}.json" 2>/dev/null || true; FINDING=$((FINDING+1))
  fi
}

: > "$OUT/RESULTS.txt"

log "=== POSITIVE CONTROLS (legit access must succeed) ==="
check alice GET "/api/v4/projects/${PROJ}"                 200 "owner reads shared-app"
check bob   GET "/api/v4/projects/${PROJ}"                 200 "developer reads shared-app (is a member)"
check carol GET "/api/v4/projects/${PROJ}"                 200 "guest reads shared-app (is a member)"
check dave  GET "/api/v4/projects/${PROJ}"                 200 "reporter reads shared-app (is a member)"
check alice GET "/api/v4/projects/${PROJ}/variables"       200 "OWNER lists CI variables (allowed)"
check alice GET "/api/v4/projects/${PROJ}/members"         200 "owner lists members"
check carol GET "/api/v4/projects/${PROJ}/members"         200 "guest may list members (by design)"

log "=== (1+3) CI/CD VARIABLE authz — require MAINTAINER(40)+; lower roles expect 403 ==="
check bob   GET "/api/v4/projects/${PROJ}/variables"                  "403" "DEVELOPER lists CI variables"
check dave  GET "/api/v4/projects/${PROJ}/variables"                  "403" "REPORTER lists CI variables"
check carol GET "/api/v4/projects/${PROJ}/variables"                  "403" "GUEST lists CI variables"
check anon  GET "/api/v4/projects/${PROJ}/variables"                  "401|404" "ANON lists CI variables"
check bob   GET "/api/v4/projects/${PROJ}/variables/PROTECTED_TOKEN"  "403" "DEVELOPER reads PROTECTED variable"
check bob   GET "/api/v4/projects/${PROJ}/variables/MASKED_SECRET"    "403" "DEVELOPER reads MASKED variable"
check dave  GET "/api/v4/projects/${PROJ}/variables/MASKED_SECRET"    "403" "REPORTER reads MASKED variable"
check carol GET "/api/v4/projects/${PROJ}/variables/MASKED_SECRET"    "403" "GUEST reads MASKED variable"

log "=== (3) CI/CD SECRET-VALUE disclosure to a role below MAINTAINER (privesc) ==="
leak bob   "/api/v4/projects/${PROJ}/variables/PROTECTED_TOKEN" "glpatFAKEPROTECTED123456" "DEVELOPER sees PROTECTED_TOKEN value"
leak bob   "/api/v4/projects/${PROJ}/variables/MASKED_SECRET"   "FAKEMASKEDSECRET12345678" "DEVELOPER sees MASKED_SECRET value"
leak dave  "/api/v4/projects/${PROJ}/variables/MASKED_SECRET"   "FAKEMASKEDSECRET12345678" "REPORTER sees MASKED_SECRET value"
leak carol "/api/v4/projects/${PROJ}/variables/MASKED_SECRET"   "FAKEMASKEDSECRET12345678" "GUEST sees MASKED_SECRET value"

log "=== (1+3) PIPELINE TRIGGER tokens — require MAINTAINER(40)+; lower roles expect 403 ==="
check bob   GET "/api/v4/projects/${PROJ}/triggers"        "403" "DEVELOPER lists pipeline trigger tokens"
check dave  GET "/api/v4/projects/${PROJ}/triggers"        "403" "REPORTER lists pipeline trigger tokens"
check carol GET "/api/v4/projects/${PROJ}/triggers"        "403" "GUEST lists pipeline trigger tokens"
check bob   GET "/api/v4/projects/${PROJ}/triggers/1"      "403" "DEVELOPER reads a trigger token by id"

log "=== (1) GUEST cannot read repository CODE in a private project (expect 403/404) ==="
check carol GET "/api/v4/projects/${PROJ}/repository/tree"            "403|404" "GUEST lists private repo tree"
check carol GET "/api/v4/projects/${PROJ}/repository/files/README%2Emd/raw?ref=main" "403|404" "GUEST reads private repo raw file"
check bob   GET "/api/v4/projects/${PROJ}/repository/tree"            "200"     "DEVELOPER lists repo tree (allowed)"
check dave  GET "/api/v4/projects/${PROJ}/repository/tree"            "200"     "REPORTER lists repo tree (allowed)"

log "=== (2) IDOR/BOLA — members of shared-app must NOT reach OTHER private projects ==="
check bob   GET "/api/v4/projects/1/variables"            "403|404" "DEVELOPER@9 reads CI vars of foreign project 1"
check dave  GET "/api/v4/projects/2/variables"            "403|404" "REPORTER@9 reads CI vars of foreign project 2"
check carol GET "/api/v4/projects/1"                      "403|404" "GUEST@9 reads foreign PRIVATE project 1"

log "=== (2+3) GraphQL field-level authz — ciVariables only for MAINTAINER+ (expect null) ==="
gql bob   "query{project(fullPath:\\\"${PROJ_PATH}\\\"){ciVariables{nodes{key}}}}"   ".data.project.ciVariables.nodes[0].key" "DEVELOPER GraphQL reads ciVariables keys"
gql carol "query{project(fullPath:\\\"${PROJ_PATH}\\\"){ciVariables{nodes{key}}}}"   ".data.project.ciVariables.nodes[0].key" "GUEST GraphQL reads ciVariables keys"
gql dave  "query{project(fullPath:\\\"${PROJ_PATH}\\\"){ciVariables{nodes{key}}}}"   ".data.project.ciVariables.nodes[0].key" "REPORTER GraphQL reads ciVariables keys"

rm -f "$BODY"
echo
printf '%s========== ROLE / AUTHZ / IDOR / CI-CD-PRIVESC SUMMARY ==========%s\n' "$c_grn" "$c_rst" | tee -a "$OUT/RESULTS.txt"
printf 'PASS=%d  MISMATCH=%d  FINDINGS=%d\n' "$PASS" "$FAIL" "$FINDING" | tee -a "$OUT/RESULTS.txt"
if [ "$FINDING" -gt 0 ]; then
  printf '%s*** %d SECURITY FINDING(S) — review %s/finding_* and leak_* ***%s\n' "$c_red" "$FINDING" "$OUT" "$c_rst" | tee -a "$OUT/RESULTS.txt"
else
  printf '%sNo role/authz/IDOR/CI-CD bypass found — boundaries correctly enforced.%s\n' "$c_grn" "$c_rst" | tee -a "$OUT/RESULTS.txt"
fi
echo "$OUT"
