#!/usr/bin/env bash
# autopilot.sh — scope-gated static (SAST) + dynamic (DAST) analysis of the
# operator-owned local GitLab VM (program: local-lab, 192.168.122.7).
#
# Every networked phase is gated by scope-authorization-guard. The ONLY in-scope
# host is the local VM. This script never targets gitlab.com or any third party.
set -euo pipefail

# ── Resolve paths (script lives at .sixth/skills/gitlab-autopilot/scripts/) ───
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../.." >/dev/null 2>&1 && pwd)"

# ── Load .env (non-fatal) ─────────────────────────────────────────────────────
if [ -f "${REPO_ROOT}/.env" ]; then set -a; . "${REPO_ROOT}/.env"; set +a; fi

# ── Config ────────────────────────────────────────────────────────────────────
PROGRAM="local-lab"
VM_IP="${VM_IP:-192.168.122.7}"
TARGET_URL="http://${VM_IP}"
KALI_VM="${KALI_VM:-kali-og-testing}"
CONN="qemu:///system"

SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"
GDK_HELPER="${REPO_ROOT}/.sixth/skills/gitlab-test-vm/scripts/gdk-vm.sh"
THOROUGH_HELPER="${REPO_ROOT}/.sixth/skills/gitlab-thorough-audit/scripts/subagent-audit.sh"
SRC="${SRC:-${REPO_ROOT}/findings/gitlab/source/gitlab}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_BASE="${REPO_ROOT}/findings/${PROGRAM}"
OUT="${OUT_BASE}/${TS}"

log()  { printf '\033[1;34m[autopilot]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[autopilot]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[autopilot] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# ── Scope gate: parse in/out lists from scope.yaml and ask the guard ──────────
# Minimal YAML reader: collects "- value" items under in_scope:/out_of_scope:.
scope_list() {
  local section="$1"
  awk -v sec="$section" '
    $0 ~ "^"sec":" { inblk=1; next }
    inblk && /^[a-z_]+:/ && $0 !~ /^[[:space:]]/ { inblk=0 }
    inblk {
      line=$0
      sub(/#.*/, "", line)                 # strip comments
      if (line ~ /^[[:space:]]*-[[:space:]]*/) {
        sub(/^[[:space:]]*-[[:space:]]*/, "", line)
        gsub(/[" ]/, "", line)
        if (line != "") print line
      }
    }
  ' "$SCOPE_FILE"
}

guard() {
  # guard <target> — abort the whole run if the target is not in scope.
  local target="$1" inlist outlist verdict
  [ -f "$SCOPE_FILE" ] || die "scope file missing: $SCOPE_FILE"
  inlist="$(scope_list in_scope  | paste -sd, -)"
  outlist="$(scope_list out_of_scope | paste -sd, -)"
  [ -n "$inlist" ] || die "refusing to run: in_scope is empty in $SCOPE_FILE"
  log "Scope check: ${target}"
  if node "$GUARD" --target "$target" --in "$inlist" --out "$outlist"; then
    return 0
  else
    die "scope guard BLOCKED ${target} — aborting (this protects gitlab.com)."
  fi
}

mkout() { mkdir -p "$OUT/$1"; }

vm_up() {
  virsh -c "$CONN" domstate debian13 2>/dev/null | grep -q running || return 1
  curl -s -o /dev/null --max-time 5 "$TARGET_URL/users/sign_in"
}

# ── Phases ───────────────────────────────────────────────────────────────────
cmd_preflight() {
  need node; need nmap; need nuclei; need podman; need curl
  log "Verifying lab VM is up at ${TARGET_URL}…"
  vm_up || die "GitLab VM not reachable. Start it: .sixth/skills/gitlab-test-vm/scripts/gitlab-vm.sh up"
  log "VM OK (sign_in reachable)."
  guard "$VM_IP"
  if [ -f "${SRC}/Gemfile" ]; then
    log "GitLab source present: ${SRC}"
  else
    warn "GitLab source not found at ${SRC} (SAST will be skipped). Clone log: findings/gitlab/source/clone.log"
  fi
  log "Ensuring SAST container images are available (pull if missing)…"
  for img in docker.io/semgrep/semgrep:latest docker.io/presidentbeef/brakeman:latest docker.io/zricethezav/gitleaks:latest; do
    podman image exists "$img" 2>/dev/null || { log "pulling $img"; podman pull -q "$img" || warn "could not pull $img"; }
  done
  log "Preflight complete."
}

cmd_recon() {
  need nmap
  guard "$VM_IP"
  mkout recon
  log "nmap service/version scan of ${VM_IP} (top ports)…"
  # -Pn: VM may not answer ICMP; -sV: versions; no aggressive OS/script flood.
  nmap -Pn -sV --version-light -oN "$OUT/recon/nmap.txt" "$VM_IP" || warn "nmap returned non-zero"
  log "Recon written to $OUT/recon/nmap.txt"
}

# Run a SAST container over the read-only source, writing its report into the
# run's rw output dir (mounted at /out). All containers run --network=none:
# rootless podman's pasta backend is blocked by SELinux on /dev/ptmx, and an
# air-gapped scan is the correct posture for a security tool anyway. Optional
# extra read-only mounts can be appended after the marker "::".
sast_run() {
  local name="$1"; shift
  local -a extra=()
  while [ "$1" = "-v" ]; do extra+=("-v" "$2"); shift 2; done
  log "SAST: ${name}…"
  podman run --rm --network=none --security-opt label=disable \
    -v "${SRC}:/src:ro" -v "${OUT}/sast:/out:rw" "${extra[@]}" "$@" \
    || warn "${name} returned non-zero (may still have findings)"
}

# semgrep rule packs are fetched ONCE on the host (curl) and cached, so the
# scan container needs no network. Registry packs resolve to a combined YAML
# at https://semgrep.dev/c/p/<name>. Cache lives under findings/ (git-ignored).
RULES_CACHE="${REPO_ROOT}/findings/.semgrep-rules"
fetch_semgrep_rules() {
  need curl
  mkdir -p "$RULES_CACHE"
  local pack
  for pack in ruby secrets security-audit; do
    local dst="${RULES_CACHE}/${pack}.yml"
    if [ -s "$dst" ]; then continue; fi
    log "Fetching semgrep pack p/${pack}…"
    if ! curl -fsSL "https://semgrep.dev/c/p/${pack}" -o "$dst"; then
      warn "Could not fetch p/${pack}; semgrep will skip it."
      rm -f "$dst"
    fi
  done
}

cmd_sast() {
  need podman
  [ -f "${SRC}/Gemfile" ] || die "GitLab source not found at ${SRC} (clone or extract the version-matched tarball first)."
  mkout sast
  # semgrep — Ruby + security rulesets, run fully offline against cached packs.
  fetch_semgrep_rules
  local -a cfg=()
  local p
  for p in ruby secrets security-audit; do
    [ -s "${RULES_CACHE}/${p}.yml" ] && cfg+=(--config "/rules/${p}.yml")
  done
  if [ "${#cfg[@]}" -gt 0 ]; then
    sast_run semgrep -v "${RULES_CACHE}:/rules:ro" docker.io/semgrep/semgrep:latest \
      semgrep --quiet --metrics=off "${cfg[@]}" \
        --json --output /out/semgrep.json /src 2>"$OUT/sast/semgrep.err" || true
  else
    warn "No semgrep rule packs available; skipping semgrep."
  fi
  # brakeman — Rails static analysis, fully offline.
  sast_run brakeman docker.io/presidentbeef/brakeman:latest \
    brakeman --no-progress --no-exit-on-warn -f json -o /out/brakeman.json -p /src \
      2>"$OUT/sast/brakeman.err" || true
  # gitleaks — secret scan; --no-git for a tarball (no history). Offline.
  sast_run gitleaks docker.io/zricethezav/gitleaks:latest \
    detect --source=/src --no-git --report-format=json --report-path=/out/gitleaks.json --redact \
      2>"$OUT/sast/gitleaks.err" || true
  log "SAST written to $OUT/sast/ (semgrep.json, brakeman.json, gitleaks.json)"
}

cmd_dast() {
  need nuclei
  guard "$VM_IP"
  mkout dast
  log "nuclei against ${TARGET_URL} (IP-pinned, no off-host follow)…"
  # -duc: don't auto-update; rate-limit to stay courteous.
  # Interactsh (out-of-band) is OFF by default so no callback leaves the host to
  # an external collaborator (oast.fun). Set NUCLEI_OOB=1 to enable blind/OOB checks.
  local oob="-no-interactsh"
  [ "${NUCLEI_OOB:-0}" = "1" ] && oob=""
  nuclei -target "$TARGET_URL" \
    -rate-limit 50 -concurrency 25 -timeout 10 \
    -severity low,medium,high,critical \
    $oob \
    -jsonl -output "$OUT/dast/nuclei.jsonl" \
    ${NUCLEI_TEMPLATES:+-templates "$NUCLEI_TEMPLATES"} \
    -duc 2>"$OUT/dast/nuclei.err" || warn "nuclei returned non-zero"
  log "DAST written to $OUT/dast/nuclei.jsonl"
}

cmd_burp() {
  log "Booting Kali station '${KALI_VM}' for interactive Burp Suite…"
  virsh -c "$CONN" domstate "$KALI_VM" 2>/dev/null | grep -q running \
    || virsh -c "$CONN" start "$KALI_VM"
  cat <<EOF

  Kali VM '${KALI_VM}' is starting. It shares the libvirt 'default' NAT, so it
  can reach the GitLab VM directly.

  In Kali, point Burp Suite at:   ${TARGET_URL}
  Scope (Burp Target > Scope):    include  ${VM_IP}  ONLY — exclude everything else.
  Reminder: keep Burp pinned to ${VM_IP}. Never let intruder/scanner touch gitlab.com.
EOF
}

cmd_gdk_status() { bash "$GDK_HELPER" status; }
cmd_gdk_verify() { bash "$GDK_HELPER" verify; }

cmd_thorough() {
  bash "$THOROUGH_HELPER" all
}

# Find the most recent run dir under OUT_BASE that contains a given relative path.
# Phases are often run separately (recon, sast, dast each make their own ts dir),
# so triage resolves each phase independently and aggregates the latest of each.
latest_with() {
  local rel="$1" d
  for d in $(ls -dt "${OUT_BASE}"/*/ 2>/dev/null); do
    d="${d%/}"
    [ -e "$d/$rel" ] && { echo "$d"; return 0; }
  done
  return 1
}

cmd_triage() {
  local recon_dir sast_dir dast_dir
  recon_dir="$(latest_with 'recon/nmap.txt' || true)"
  sast_dir="$(latest_with 'sast/semgrep.json' || true)"
  dast_dir="$(latest_with 'dast/nuclei.jsonl' || true)"
  # Write the summary into the most recent run dir overall.
  OUT="$(ls -dt "${OUT_BASE}"/*/ 2>/dev/null | head -1)"; OUT="${OUT%/}"
  [ -n "${OUT:-}" ] && [ -d "$OUT" ] || die "no run directory found under ${OUT_BASE}"
  local sum="$OUT/SUMMARY.md"
  log "Summarising → $sum"
  local rb sb db
  rb="${recon_dir:+$(basename "$recon_dir")}"; rb="${rb:-—}"
  sb="${sast_dir:+$(basename "$sast_dir")}";   sb="${sb:-—}"
  db="${dast_dir:+$(basename "$dast_dir")}";   db="${db:-—}"
  {
    echo "# Autopilot run — ${PROGRAM} — $(basename "$OUT")"
    echo
    echo "Target VM: ${TARGET_URL}  (operator-owned; aggressive testing authorized)"
    echo
    echo "Sources: recon=${rb}, sast=${sb}, dast=${db}"
    echo
    echo "## Recon (nmap)"
    if [ -n "$recon_dir" ] && [ -f "$recon_dir/recon/nmap.txt" ]; then
      grep -E '^[0-9]+/tcp' "$recon_dir/recon/nmap.txt"
    else echo "_no recon output_"; fi
    echo
    echo "## SAST"
    echo
    echo "Heuristics down-rank (never drop) low-signal noise: severity/confidence"
    echo "breakdowns, and secrets in test/fixture/doc paths. Everything is still"
    echo "counted; the operator triages the \"review\" buckets first."
    echo
    # --- semgrep: break out by severity (ERROR > WARNING > INFO) ---
    if [ -n "$sast_dir" ] && [ -f "$sast_dir/sast/semgrep.json" ]; then
      local sg_total sg_err sg_warn sg_info
      sg_total=$(jq '.results | length' "$sast_dir/sast/semgrep.json" 2>/dev/null || echo '?')
      sg_err=$(jq '[.results[]?|select(.extra.severity=="ERROR")]|length' "$sast_dir/sast/semgrep.json" 2>/dev/null || echo 0)
      sg_warn=$(jq '[.results[]?|select(.extra.severity=="WARNING")]|length' "$sast_dir/sast/semgrep.json" 2>/dev/null || echo 0)
      sg_info=$(jq '[.results[]?|select(.extra.severity=="INFO")]|length' "$sast_dir/sast/semgrep.json" 2>/dev/null || echo 0)
      echo "- semgrep findings: ${sg_total} total — review ${sg_err} ERROR / ${sg_warn} WARNING, ${sg_info} INFO"
    fi
    # --- brakeman: break out by confidence (High > Medium > Weak) ---
    if [ -n "$sast_dir" ] && [ -f "$sast_dir/sast/brakeman.json" ]; then
      local bm_total bm_high bm_med bm_weak
      bm_total=$(jq '.warnings | length' "$sast_dir/sast/brakeman.json" 2>/dev/null || echo '?')
      bm_high=$(jq '[.warnings[]?|select(.confidence=="High")]|length' "$sast_dir/sast/brakeman.json" 2>/dev/null || echo 0)
      bm_med=$(jq '[.warnings[]?|select(.confidence=="Medium")]|length' "$sast_dir/sast/brakeman.json" 2>/dev/null || echo 0)
      bm_weak=$(jq '[.warnings[]?|select(.confidence=="Weak")]|length' "$sast_dir/sast/brakeman.json" 2>/dev/null || echo 0)
      echo "- brakeman warnings: ${bm_total} total — review ${bm_high} High / ${bm_med} Medium, ${bm_weak} Weak"
    fi
    # --- gitleaks: down-rank secrets in test/fixture/doc paths (runs --redact, so classify by File+RuleID) ---
    if [ -n "$sast_dir" ] && [ -f "$sast_dir/sast/gitleaks.json" ]; then
      local gl_re gl_total gl_low gl_review
      # Down-rank (keep, don't drop) known-noisy paths: test/fixture/doc dirs,
      # *.example templates, workhorse/testdata, and gitleaks' OWN ruleset config
      # (config/gitleaks-local.toml is full of sample tokens by design).
      gl_re='(^|/)(spec|test|tests|qa|fixtures?|factories|examples?|mocks?|dummy|samples?|doc|docs|vendor|node_modules|testdata)/|\.(md|txt|example)$|changelog|seed|gitleaks'
      gl_total=$(jq 'if type=="array" then length else 0 end' "$sast_dir/sast/gitleaks.json" 2>/dev/null || echo 0)
      gl_low=$(jq --arg re "$gl_re" 'if type=="array" then [.[]|select((.File // "")|test($re;"i"))]|length else 0 end' "$sast_dir/sast/gitleaks.json" 2>/dev/null || echo 0)
      gl_review=$(( gl_total - gl_low ))
      echo "- gitleaks secrets: ${gl_total} total — ${gl_review} to review, ${gl_low} down-ranked (test/fixture/doc paths)"
      echo
      echo "### gitleaks — review bucket (secrets outside fixture/test/doc paths)"
      jq -r --arg re "$gl_re" '
        if type=="array" then
          [.[]|select((.File // "")|test($re;"i")|not)]
          | sort_by(.File)[] | "- [" + (.RuleID // "?") + "] " + (.File // "?") + ":" + ((.StartLine // 0)|tostring)
        else empty end' "$sast_dir/sast/gitleaks.json" 2>/dev/null | head -40 || echo "_none — all secrets fell into down-ranked paths_"
    fi
    echo
    echo "## DAST (nuclei)"
    if [ -n "$dast_dir" ] && [ -f "$dast_dir/dast/nuclei.jsonl" ]; then
      echo "- nuclei matches: $(wc -l < "$dast_dir/dast/nuclei.jsonl" | tr -d ' ')"
      echo
      jq -r '"- [" + (."info".severity // "?") + "] " + (."info".name // ."template-id")' \
        "$dast_dir/dast/nuclei.jsonl" 2>/dev/null | sort -u | head -50 || true
    else
      echo "_no DAST output_"
    fi
    echo
    echo "## Next steps"
    echo "1. Operator triages each item above; the operator decides what is a real finding."
    echo "2. Manually reproduce + capture artifacts for confirmed issues."
    echo "3. Draft via the hackerone-report skill (self-managed PoC; never re-run vs gitlab.com)."
  } > "$sum"
  log "Done. Review: $sum"
  echo; cat "$sum"
}

cmd_all() {
  cmd_preflight
  cmd_recon
  if [ -f "${SRC}/Gemfile" ]; then cmd_sast; else warn "skipping SAST (no source yet)"; fi
  cmd_dast
  cmd_triage
}

usage() {
  cat <<EOF
autopilot.sh — scope-gated SAST + DAST for the local GitLab lab (${PROGRAM})

Usage: $0 <phase>

  preflight  Verify VM up, clone present, scope ALLOWs VM, pull SAST images
  recon      nmap service/version scan of ${VM_IP}
  sast       semgrep + brakeman + gitleaks over the cloned source
  dast       nuclei against ${TARGET_URL} (IP-pinned)
  burp       Boot ${KALI_VM} and print Burp targeting instructions
  gdk-status Scope-gated full-GDK/toolchain/resource inventory inside the VM
  gdk-verify Fail unless a complete GDK root + GitLab source are present
  thorough   Create subagent tasking and run serial read-only audit lanes
  triage     Summarise latest run into SUMMARY.md
  all        preflight -> recon -> sast -> dast -> triage

Every networked phase calls scope-authorization-guard first; the only in-scope
host is ${VM_IP}. gitlab.com and the production estate are always blocked.
EOF
}

case "${1:-}" in
  preflight) cmd_preflight;;
  recon)     cmd_recon;;
  sast)      cmd_sast;;
  dast)      cmd_dast;;
  burp)      cmd_burp;;
  gdk-status) cmd_gdk_status;;
  gdk-verify) cmd_gdk_verify;;
  thorough)  cmd_thorough;;
  triage)    cmd_triage;;
  all)       cmd_all;;
  ""|-h|--help|help) usage;;
  *) usage; die "unknown phase: $1";;
esac
