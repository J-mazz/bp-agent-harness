#!/usr/bin/env bash
# subagent-audit.sh — generate subagent tasking and run thorough local-lab lanes.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SKILL_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SKILL_DIR}/../../.." >/dev/null 2>&1 && pwd)"

if [ -f "${REPO_ROOT}/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "${REPO_ROOT}/.env"
  set +a
fi

PROGRAM="local-lab"
VM_IP="${VM_IP:-192.168.122.7}"
TARGET_URL="http://${VM_IP}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
OUT_BASE="${REPO_ROOT}/findings/${PROGRAM}"
RUN_DIR="${RUN_DIR:-${OUT_BASE}/${TS}}"
SUBAGENTS="${RUN_DIR}/subagents"
AUTO_SCRIPTS="${REPO_ROOT}/.sixth/skills/gitlab-autopilot/scripts"
GDK_HELPER="${REPO_ROOT}/.sixth/skills/gitlab-test-vm/scripts/gdk-vm.sh"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"

log()  { printf '\033[1;34m[thorough-audit]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[thorough-audit]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[thorough-audit] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

scope_list() {
  local section="$1"
  awk -v sec="$section" '
    $0 ~ "^"sec":" { inblk=1; next }
    inblk && /^[a-z_]+:/ && $0 !~ /^[[:space:]]/ { inblk=0 }
    inblk { line=$0; sub(/#.*/, "", line);
      if (line ~ /^[[:space:]]*-[[:space:]]*/){ sub(/^[[:space:]]*-[[:space:]]*/, "", line); gsub(/[" ]/, "", line); if(line!="") print line } }
  ' "$SCOPE_FILE"
}

guard() {
  need node
  local inlist outlist
  [ -f "$SCOPE_FILE" ] || die "scope file missing: $SCOPE_FILE"
  inlist="$(scope_list in_scope | paste -sd, -)"
  outlist="$(scope_list out_of_scope | paste -sd, -)"
  [ -n "$inlist" ] || die "refusing to run: in_scope is empty in $SCOPE_FILE"
  node "$GUARD" --target "$VM_IP" --in "$inlist" --out "$outlist" >/dev/null \
    || die "scope guard BLOCKED ${VM_IP} — refusing to run audit lanes."
}

init_run() {
  mkdir -p "$RUN_DIR" "$SUBAGENTS"
}

write_task() {
  local file="$1" title="$2"
  shift 2
  {
    echo "# ${title}"
    echo
    echo "Target: ${TARGET_URL} (program: ${PROGRAM}; operator-owned local lab only)"
    echo "Scope: run scope-authorization-guard before any VM request; never touch gitlab.com."
    echo "Output: write concise findings, evidence paths, and blockers back to this run directory."
    echo
    printf '%s\n' "$@"
  } > "${SUBAGENTS}/${file}"
}

cmd_plan() {
  init_run
  guard
  write_task "01-gdk-runtime.md" "Subagent lane 01 — GDK and runtime readiness" \
    "Inspect the harness GDK status output and VM resource facts. Determine whether full GDK is present, what is missing, and whether blockers are resource, egress, or dependency related. Do not run networked package installation. Return exact remediation steps and commands for the operator." \
    "Focus files: .sixth/skills/gitlab-test-vm/scripts/gdk-vm.sh, programs/local-lab/scope.yaml, findings/local-lab/<ts>/gdk-status if present."
  write_task "02-authz-role-boundary.md" "Subagent lane 02 — Authz and role boundary" \
    "Audit role boundary assumptions for alice/shared-app and the fixture ladder. Review role-privesc results plus source authorization patterns for CI variables, triggers, protected branches, members, deploy tokens, and runner creation. Classify only authz bypass / CI-CD privesc / GraphQL-REST IDOR as candidate findings."
  write_task "03-idor-bola.md" "Subagent lane 03 — IDOR/BOLA" \
    "Review REST object-level authorization across projects, groups, snippets, issues, repository files, and confidential resources. Compare expected 401/403/404 boundaries to actual lane results. Identify additional safe GET-only cases to add if coverage is thin."
  write_task "04-graphql-rest-parity.md" "Subagent lane 04 — GraphQL/REST parity" \
    "Review GraphQL queries/mutations used by probes and source resolver authorization. Look for REST-denied objects exposed by GraphQL fields or nullable-field inconsistencies. Keep tests read-only unless the operator explicitly asks for kinetic validation."
  write_task "05-cicd-privesc-chain.md" "Subagent lane 05 — CI/CD privesc chain" \
    "Assess runners, pipeline execution prerequisites, protected branch rules, CI variables, trigger/deploy token access, and CI_JOB_TOKEN scope. Model the Developer -> pipeline poisoning -> secret exposure -> job-token lateral movement chain, but do not execute destructive steps. Note runner/GDK blockers separately."
  write_task "06-evidence-consolidation.md" "Subagent lane 06 — Evidence consolidation" \
    "Merge lane outputs into a triage narrative. De-duplicate expected-pass observations, highlight mismatches and findings, and list exact reproduction artifacts. Keep confidential data redacted; include paths under findings/local-lab/<ts>/ only."
  cat > "${RUN_DIR}/AUDIT-MANIFEST.json" <<EOF
{
  "timestamp": "${TS}",
  "program": "${PROGRAM}",
  "target": "${TARGET_URL}",
  "run_dir": "${RUN_DIR}",
  "scope_gated": true,
  "off_host_allowed": false,
  "subagent_task_pack": "${SUBAGENTS}",
  "lanes": []
}
EOF
  log "Subagent task pack written to ${SUBAGENTS}"
  echo "$RUN_DIR"
}

run_lane() {
  local lane="$1" script="$2"
  shift 2
  guard
  mkdir -p "${RUN_DIR}/${lane}"
  log "Running lane '${lane}' via ${script}"
  local start end status
  start="$(date -u +%FT%TZ)"
  if OUT="${RUN_DIR}/${lane}" TS="$TS" bash "$AUTO_SCRIPTS/$script" "$@" \
      >"${RUN_DIR}/${lane}/stdout.log" 2>"${RUN_DIR}/${lane}/stderr.log"; then
    status="complete"
  else
    status="failed"
    warn "lane '${lane}' failed; see ${RUN_DIR}/${lane}/stderr.log"
  fi
  end="$(date -u +%FT%TZ)"
  {
    echo "lane=${lane}"
    echo "script=${script}"
    echo "status=${status}"
    echo "started_at=${start}"
    echo "completed_at=${end}"
    if [ -f "${RUN_DIR}/${lane}/RESULTS.txt" ]; then
      echo "pass_count=$(grep -c 'PASS' "${RUN_DIR}/${lane}/RESULTS.txt" || true)"
      echo "mismatch_count=$(grep -c 'MISMATCH' "${RUN_DIR}/${lane}/RESULTS.txt" || true)"
      echo "finding_count=$(grep -c 'FINDING' "${RUN_DIR}/${lane}/RESULTS.txt" || true)"
    elif [ -f "${RUN_DIR}/${lane}/INDEX.txt" ]; then
      echo "indexed_requests=$(wc -l < "${RUN_DIR}/${lane}/INDEX.txt" | tr -d ' ')"
      echo "finding_count=0"
    else
      echo "finding_count=unknown"
    fi
  } > "${RUN_DIR}/${lane}/lane-status.env"
}

cmd_run_readonly() {
  init_run
  [ -f "${SUBAGENTS}/01-gdk-runtime.md" ] || cmd_plan >/dev/null
  run_lane "auth" "auth-api-probe.sh"
  run_lane "idor" "idor-probe.sh"
  run_lane "role-privesc" "role-privesc-probe.sh"
  run_lane "attack" "attack-emulation.sh"
  log "Read-only lanes complete under ${RUN_DIR}"
  echo "$RUN_DIR"
}

cmd_run_kinetic() {
  init_run
  [ -f "${SUBAGENTS}/01-gdk-runtime.md" ] || cmd_plan >/dev/null
  run_lane "kinetic-privesc" "kinetic-privesc-probe.sh"
  log "Kinetic lane complete under ${RUN_DIR}"
  echo "$RUN_DIR"
}

cmd_gdk_status() {
  init_run
  guard
  mkdir -p "${RUN_DIR}/gdk-status"
  bash "$GDK_HELPER" status | tee "${RUN_DIR}/gdk-status/STATUS.txt"
}

lane_summary_row() {
  local lane_dir="$1" lane status="unknown" finding_count="—" mismatch_count="—" pass_count="—" indexed_requests="—"
  lane="$(basename "$lane_dir")"
  if [ -f "${lane_dir}/lane-status.env" ]; then
    # shellcheck disable=SC1090
    . "${lane_dir}/lane-status.env"
    printf '| %s | %s | %s | %s | %s | %s |\n' "$lane" "${status:-unknown}" "${pass_count:-—}" "${mismatch_count:-—}" "${finding_count:-—}" "${indexed_requests:-—}"
  fi
}

cmd_consolidate() {
  init_run
  local report="${RUN_DIR}/CONSOLIDATED-FINDINGS.md"
  {
    echo "# Consolidated GitLab thorough audit — ${PROGRAM} — ${TS}"
    echo
    echo "Target: ${TARGET_URL} (operator-owned local lab)."
    echo
    echo "## Lane summary"
    echo
    echo "| Lane | Status | PASS | MISMATCH | FINDING lines | Indexed requests |"
    echo "|------|--------|------|----------|---------------|------------------|"
    for d in "${RUN_DIR}"/*/; do lane_summary_row "${d%/}"; done
    echo
    echo "## Subagent task packets"
    echo
    for p in "${SUBAGENTS}"/*.md; do [ -f "$p" ] && echo "- \`${p#${REPO_ROOT}/}\`"; done
    echo
    echo "## Review notes"
    echo
    echo "- Candidate findings are limited to authz bypass, GraphQL/REST IDOR, and CI/CD privilege escalation."
    echo "- Kinetic/write-side lanes are opt-in and require VM egress containment."
    echo "- The operator decides what is a real finding before any report is drafted."
  } > "$report"
  log "Consolidated report written to ${report}"
  echo "$report"
}

cmd_all() {
  cmd_plan >/dev/null
  cmd_gdk_status >/dev/null || warn "GDK status failed; continuing read-only audit lanes."
  cmd_run_readonly >/dev/null
  cmd_consolidate
}

usage() {
  cat <<EOF
subagent-audit.sh — thorough local-lab GitLab audit tasking

Usage: $0 <command>

  plan          Create subagent task prompts under findings/local-lab/<ts>/subagents
  gdk-status    Record full-GDK readiness/status in this run directory
  run-readonly  Run auth, IDOR, role-privesc, and read-only ATT&CK lanes serially
  run-kinetic   Run write-side kinetic lane (requires egress lockdown)
  consolidate   Write CONSOLIDATED-FINDINGS.md for this run
  all           plan -> gdk-status -> run-readonly -> consolidate (no kinetic)

Environment: TS RUN_DIR VM_IP SSH_USER SSH_KEY
EOF
}

case "${1:-}" in
  plan) cmd_plan ;;
  gdk-status) cmd_gdk_status ;;
  run-readonly) cmd_run_readonly ;;
  run-kinetic) cmd_run_kinetic ;;
  consolidate) cmd_consolidate ;;
  all) cmd_all ;;
  ""|-h|--help|help) usage ;;
  *) usage; die "unknown command: $1" ;;
esac
