#!/usr/bin/env bash
# attack-emulation.sh — controlled, READ-ONLY MITRE ATT&CK adversary emulation
# against the local GitLab lab (program local-lab, http://192.168.122.7).
#
# Threat model: a Valid-Accounts adversary holding a compromised admin PAT walks
# the kill chain:  Valid Accounts -> Discovery -> Credential Access -> Collection
#                  -> (quantified) Exfiltration.
#
# SAFETY (AGENTS.md RoE):
#   - Scope-gated to 192.168.122.7 ONLY (guard runs first; off-host = abort).
#   - 100% GET requests. No mutation, no persistence, no privilege change.
#   - Impact-tactic techniques (T1485/T1486/T1490) are DELIBERATELY NOT performed
#     and are recorded as "available, not executed".
#   - Any "secrets" surfaced are planted fixtures (glpat-FAKE-FIXTURE...).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"
VM_IP="${VM_IP:-192.168.122.7}"; BASE="http://${VM_IP}"
PROGRAM="local-lab"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
ADMIN_TOK_FILE="${ADMIN_TOK_FILE:-$HOME/.gl_ro_token}"

TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT="${OUT:-${REPO_ROOT}/findings/${PROGRAM}/${TS}/attack}"
mkdir -p "$OUT"; EV="$OUT/evidence"; mkdir -p "$EV"
RESULTS="$OUT/RESULTS.txt"; : > "$RESULTS"
LAYER="$OUT/attack-navigator-layer.json"

c_g=$'\033[1;32m'; c_y=$'\033[1;33m'; c_b=$'\033[1;34m'; c_r=$'\033[0m'
log(){ printf '%s\n' "$*" >&2; }
row(){ printf '%s\n' "$*" >>"$RESULTS"; printf '%s\n' "$*" >&2; }

# --- scope gate ---------------------------------------------------------------
scope_list(){ awk -v sec="$1" '
  $0 ~ "^"sec":" { inblk=1; next }
  inblk && /^[a-z_]+:/ && $0 !~ /^[[:space:]]/ { inblk=0 }
  inblk { line=$0; sub(/#.*/,"",line);
    if (line ~ /^[[:space:]]*-[[:space:]]*/){ sub(/^[[:space:]]*-[[:space:]]*/,"",line); gsub(/[" ]/,"",line); if(line!="") print line } }
' "$SCOPE_FILE"; }
IN="$(scope_list in_scope | paste -sd, -)"; OUTL="$(scope_list out_of_scope | paste -sd, -)"
node "$GUARD" --target "$VM_IP" --in "$IN" --out "$OUTL" >/dev/null || { log "SCOPE BLOCKED $VM_IP"; exit 1; }
log "${c_b}Scope OK: $VM_IP ALLOWED — read-only ATT&CK emulation${c_r}"
[ -s "$ADMIN_TOK_FILE" ] || { log "admin token $ADMIN_TOK_FILE missing"; exit 1; }
TOKEN="$(tr -d '\r\n' < "$ADMIN_TOK_FILE")"

EXEC_OK=""   # comma list of techniques with confirmed evidence -> drives the layer
mark(){ case ",$EXEC_OK," in *",$1,"*) ;; *) EXEC_OK="${EXEC_OK:+$EXEC_OK,}$1";; esac; }

# get TECH SLUG PATH  -> writes evidence/SLUG.json, echoes http code
get(){ local tech="$1" slug="$2" path="$3"
  curl -s -o "$EV/${slug}.json" -w '%{http_code}' --max-time 20 --connect-timeout 5 \
    -H "PRIVATE-TOKEN: $TOKEN" -H "Accept: application/json" -X GET "$BASE$path"; }
# count array length (or '-' )
n(){ jq 'if type=="array" then length else 1 end' "$EV/$1.json" 2>/dev/null || echo '-'; }

hdr(){ row ""; row "${c_b}== $1 ==${c_r}"; }

# =============================================================================
log "Writing evidence to $OUT"
row "MITRE ATT&CK emulation — local-lab @ $BASE — $(date -u +%FT%TZ)"
row "All requests GET / read-only. Secrets shown are planted fixtures."

# --- TA0001/TA0005 Valid Accounts (T1078) ------------------------------------
hdr "Initial Access — Valid Accounts (T1078)"
code=$(get T1078 whoami "/api/v4/user")
who=$(jq -r '"\(.username) admin=\(.is_admin)"' "$EV/whoami.json" 2>/dev/null)
row "[T1078] GET /user -> $code :: identity=$who (compromised admin PAT)"; [ "$code" = 200 ] && mark T1078

# --- TA0007 Discovery ---------------------------------------------------------
hdr "Discovery"
code=$(get T1526 svc "/api/v4/metadata")
ver=$(jq -r '.version' "$EV/svc.json" 2>/dev/null)
row "[T1526] Cloud Service Discovery   /metadata -> $code :: GitLab $ver"; [ "$code" = 200 ] && mark T1526
code=$(get T1518 feats "/api/v4/features"); row "[T1518] Software Discovery        /features -> $code :: $(n feats) feature flags"; [ "$code" = 200 ] && mark T1518
code=$(get T1087 users "/api/v4/users?per_page=100")
unames=$(jq -r '[.[].username]|join(",")' "$EV/users.json" 2>/dev/null)
row "[T1087] Account Discovery          /users -> $code :: $(n users) users [$unames]"; [ "$code" = 200 ] && mark T1087
code=$(get T1069 groups "/api/v4/groups?all_available=true&per_page=100")
row "[T1069] Permission Groups Disc.    /groups -> $code :: $(n groups) groups"; [ "$code" = 200 ] && mark T1069
gid=$(jq -r '.[0].id // empty' "$EV/groups.json" 2>/dev/null)
if [ -n "$gid" ]; then code=$(get T1069 grpmembers "/api/v4/groups/$gid/members/all"); row "[T1069]   group $gid members -> $code :: $(n grpmembers) members"; fi
code=$(get T1083 tree "/api/v4/projects/7/repository/tree?recursive=true&per_page=100")
row "[T1083] File & Directory Discovery /projects/7/tree -> $code :: $(n tree) entries (mirror-gitignore)"; [ "$code" = 200 ] && mark T1083

# --- TA0006 Credential Access -------------------------------------------------
hdr "Credential Access"
# T1528 Steal Application Access Token — enumerate PATs (admin view)
code=$(get T1528 pats "/api/v4/personal_access_tokens?per_page=100")
if [ "$code" = 200 ]; then
  row "[T1528] Steal App Access Token    /personal_access_tokens -> 200 :: $(n pats) tokens visible to admin"; mark T1528
else
  row "[T1528] Steal App Access Token    /personal_access_tokens -> $code :: (read_api insufficient — good)"
fi
# T1552.001 Credentials In Files — project-scoped blob search (basic search, no ES needed)
hdr "Credential Access — Unsecured Credentials in Files (T1552.001)"
hits_total=0
for pid in 5 6 7; do
  for pat in "PRIVATE KEY" "password" "secret" "api_key" "token" "AKIA"; do
    enc=$(printf '%s' "$pat" | jq -sRr @uri)
    slug="blob_${pid}_$(echo "$pat" | tr ' A-Z' '_a-z')"
    code=$(get T1552 "$slug" "/api/v4/projects/$pid/search?scope=blobs&search=$enc&per_page=20")
    if [ "$code" = 200 ]; then c=$(jq 'if type=="array" then length else 0 end' "$EV/$slug.json" 2>/dev/null); else c=0; fi
    c=${c:-0}; hits_total=$((hits_total + c))
    [ "$c" -gt 0 ] && row "[T1552.001] proj $pid blob '$pat' -> $code :: $c hit(s)"
  done
done
row "[T1552.001] total blob hits across imported repos (5,6,7): $hits_total"
[ "$hits_total" -gt 0 ] && mark T1552.001
# planted-secret retrieval (snippet raw + confidential issue) proves the data path
code=$(get T1552 snippet_raw "/api/v4/snippets/1/raw")
if grep -qi 'glpat-FAKE-FIXTURE\|password=' "$EV/snippet_raw.json" 2>/dev/null; then
  row "[T1552.001] private snippet /snippets/1/raw -> $code :: PLANTED creds retrieved (fixture)"; mark T1552.001
else
  row "[T1552.001] private snippet /snippets/1/raw -> $code"
fi

# --- TA0009 Collection --------------------------------------------------------
hdr "Collection — Data from Information Repositories (T1213)"
code=$(get T1213 conf_issue "/api/v4/projects/1/issues/1")
conf=$(jq -r '.confidential' "$EV/conf_issue.json" 2>/dev/null)
row "[T1213] confidential issue /projects/1/issues/1 -> $code :: confidential=$conf, body harvested"; [ "$code" = 200 ] && mark T1213
code=$(get T1213 raw_readme "/api/v4/projects/5/repository/files/README/raw?ref=master")
row "[T1213] private repo file /projects/5/.../README/raw -> $code :: $(wc -c <"$EV/raw_readme.json" 2>/dev/null) bytes (mirror-hello)"

# --- TA0010 Exfiltration (quantified, NOT sent off-host) ----------------------
hdr "Exfiltration — Over Web Service (T1567) — QUANTIFIED ONLY"
bytes=$(du -sb "$EV" 2>/dev/null | awk '{print $1}')
row "[T1567] Exfiltration Over Web Service :: $bytes bytes harvestable via API"
row "        (data NOT transmitted off-host — that would violate scope; volume measured only)"
mark T1567

# --- Not performed (documented) ----------------------------------------------
hdr "Persistence / Impact — AVAILABLE, NOT PERFORMED"
row "[T1098.001] Additional Cloud Credentials (PAT mint) — controlled mint done earlier for fixtures; not re-run."
row "[T1136]     Create Account — NOT performed (mutation)."
row "[T1485]     Data Destruction — DELIBERATELY EXCLUDED (no security insight)."
row "[T1486]     Data Encrypted for Impact — EXCLUDED."
row "[T1490]     Inhibit System Recovery — EXCLUDED."

# --- emit ATT&CK Navigator layer ---------------------------------------------
EXEC_OK="$EXEC_OK" OUT_LAYER="$LAYER" BASE="$BASE" node <<'NODE'
const fs=require('node:fs');
const exec=new Set((process.env.EXEC_OK||'').split(',').filter(Boolean));
const cat=[
  ['T1078','initial-access','Valid Accounts — compromised admin PAT'],
  ['T1046','discovery','Network Service Discovery — nmap 22/ssh,80/nginx (prior recon)'],
  ['T1526','discovery','Cloud Service Discovery — /metadata version'],
  ['T1518','discovery','Software Discovery — feature flags'],
  ['T1087','discovery','Account Discovery — /users enumeration'],
  ['T1069','discovery','Permission Groups Discovery — /groups + members'],
  ['T1083','discovery','File and Directory Discovery — repo tree'],
  ['T1528','credential-access','Steal Application Access Token — PAT listing'],
  ['T1552.001','credential-access','Unsecured Credentials in Files — blob search + snippet/issue'],
  ['T1213','collection','Data from Information Repositories — confidential issue + repo files'],
  ['T1567','exfiltration','Exfiltration Over Web Service — quantified only'],
];
const notPerf=[
  ['T1098.001','persistence','Additional Cloud Credentials — controlled earlier, not re-run'],
  ['T1136','persistence','Create Account — not performed (mutation)'],
  ['T1485','impact','Data Destruction — deliberately excluded'],
  ['T1486','impact','Data Encrypted for Impact — excluded'],
  ['T1490','impact','Inhibit System Recovery — excluded'],
];
const T=[];
// T1046 was done in prior recon phase, count as executed
const priorExec=new Set(['T1046']);
for(const [id,tac,cm] of cat){
  const done = exec.has(id) || priorExec.has(id);
  T.push({techniqueID:id,tactic:tac,score:done?100:50,color:done?'#e74c3c':'#f1c40f',
          comment:cm+(done?' [EXECUTED read-only]':' [attempted]'),enabled:true,metadata:[],showSubtechniques:id.includes('.')});
}
for(const [id,tac,cm] of notPerf)
  T.push({techniqueID:id,tactic:tac,score:10,color:'#95a5a6',comment:cm+' [NOT PERFORMED]',enabled:true,metadata:[]});
const layer={name:'GitLab local-lab — read-only ATT&CK emulation',
  versions:{attack:'15',navigator:'4.9.5',layer:'4.5'},domain:'enterprise-attack',
  description:`Controlled read-only adversary emulation vs ${process.env.BASE} (operator lab). Red=executed read-only, yellow=attempted, grey=available/not performed.`,
  techniques:T,
  gradient:{colors:['#ffffff','#e74c3c'],minValue:0,maxValue:100},
  legendItems:[{label:'executed (read-only)',color:'#e74c3c'},{label:'attempted',color:'#f1c40f'},{label:'available, not performed',color:'#95a5a6'}],
  metadata:[{name:'engagement',value:'local-lab'},{name:'rules',value:'GET-only, IP-pinned, non-destructive'}],
  showTacticRowBackground:true,tacticRowBackground:'#205b8f',selectTechniquesAcrossTactics:true};
fs.writeFileSync(process.env.OUT_LAYER,JSON.stringify(layer,null,2));
console.error(`[attack] navigator layer -> ${process.env.OUT_LAYER} (${T.length} techniques, ${[...exec,...priorExec].length} executed)`);
NODE

row ""
row "${c_g}== EMULATION COMPLETE ==${c_r}"
row "Executed (read-only): $EXEC_OK,T1046"
row "Evidence: $EV/   Layer: $LAYER"
log "${c_g}Done.${c_r} Import $LAYER at https://mitre-attack.github.io/attack-navigator/ (offline build OK)."
echo "$OUT"
