#!/usr/bin/env bash
# gdk-vm.sh — verify/install GitLab Development Kit (GDK) on the local lab VM.
#
# Safety posture:
#   - Scope-gates the VM IP before every SSH interaction.
#   - Defaults to status/verification only.
#   - Refuses online installation unless GDK_ALLOW_NETWORK=1 is explicit, because
#     a full GDK bootstrap reaches package mirrors and gitlab.com from the VM.
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
VM_NAME="${VM_NAME:-debian13}"
VM_IP="${VM_IP:-192.168.122.7}"
SSH_USER="${SSH_USER:-debian}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
CONN="qemu:///system"
GDK_ROOT="${GDK_ROOT:-/home/${SSH_USER}/gdk}"
GDK_MIN_FREE_GB="${GDK_MIN_FREE_GB:-40}"
GDK_MIN_MEM_GB="${GDK_MIN_MEM_GB:-16}"
GDK_ALLOW_NETWORK="${GDK_ALLOW_NETWORK:-0}"
GDK_FORCE="${GDK_FORCE:-0}"
SCOPE_FILE="${REPO_ROOT}/programs/${PROGRAM}/scope.yaml"
GUARD="${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/check-scope.mjs"

VIRSH() { virsh -c "$CONN" "$@"; }
log()  { printf '\033[1;34m[gdk-vm]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[gdk-vm]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[gdk-vm] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# Scope parser + guard live in one sourced helper (no copy-paste drift).
# shellcheck source=/dev/null
. "${REPO_ROOT}/.sixth/skills/scope-authorization-guard/scripts/scope-lib.sh"

guard() {
  [ -f "$SCOPE_FILE" ] || die "scope file missing: $SCOPE_FILE"
  scope_guard "$VM_IP" "$SCOPE_FILE" "$GUARD" >/dev/null \
    || die "scope guard BLOCKED ${VM_IP} — refusing to touch the VM."
}

preflight() {
  need node; need ssh; need virsh
  VIRSH version >/dev/null 2>&1 || die "cannot reach libvirt at $CONN"
}

vm_ssh() {
  ssh -i "$SSH_KEY" \
      -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=10 \
      -o ServerAliveInterval=10 \
      -o ServerAliveCountMax=2 \
      -o LogLevel=ERROR \
      "${SSH_USER}@${VM_IP}" "$@"
}

vm_state() { VIRSH domstate "$VM_NAME" 2>/dev/null || echo "not found"; }

ensure_running() {
  local state
  state="$(vm_state)"
  case "$state" in
    running) return 0 ;;
    paused)
      log "VM '${VM_NAME}' is paused; resuming it."
      VIRSH resume "$VM_NAME" >/dev/null
      ;;
    'shut off')
      log "VM '${VM_NAME}' is shut off; starting it."
      VIRSH start "$VM_NAME" >/dev/null
      ;;
    *) die "VM '${VM_NAME}' is not runnable (state: ${state})." ;;
  esac
}

wait_ssh() {
  local i
  for i in $(seq 1 24); do
    if vm_ssh true 2>/dev/null; then return 0; fi
    sleep 5
  done
  die "timed out waiting for SSH on ${VM_IP}"
}

remote_status_script() {
  cat <<'REMOTE'
set -euo pipefail
GDK_ROOT="$1"
df_target="$GDK_ROOT"
if [ ! -e "$df_target" ]; then
  df_target="$(dirname "$GDK_ROOT")"
fi
if [ ! -e "$df_target" ]; then
  df_target="$HOME"
fi
printf 'host=%s\n' "$(hostname)"
printf 'user=%s\n' "$(id -un)"
printf 'gdk_root=%s\n' "$GDK_ROOT"
if [ -d "$GDK_ROOT" ]; then
  printf 'gdk_root_present=yes\n'
  if [ -d "$GDK_ROOT/.git" ]; then
    git -C "$GDK_ROOT" remote -v 2>/dev/null | sed 's/^/gdk_remote=/' | head -n 2 || true
    git -C "$GDK_ROOT" rev-parse --short HEAD 2>/dev/null | sed 's/^/gdk_rev=/' || true
  fi
else
  printf 'gdk_root_present=no\n'
fi
for c in gdk ruby bundle node yarn corepack go make cmake pkg-config git; do
  if command -v "$c" >/dev/null 2>&1; then printf 'cmd_%s=%s\n' "$c" "$(command -v "$c")"; else printf 'cmd_%s=missing\n' "$c"; fi
done
[ -d "$GDK_ROOT/gitlab" ] && printf 'gitlab_source_present=yes\n' || printf 'gitlab_source_present=no\n'
[ -f "$GDK_ROOT/gitlab/Gemfile" ] && printf 'gitlab_gemfile=yes\n' || printf 'gitlab_gemfile=no\n'
[ -f "$GDK_ROOT/gdk.yml" ] && printf 'gdk_config=yes\n' || printf 'gdk_config=no\n'
gdk_free_gb=$(df -BG "$df_target" | awk 'NR==2{gsub(/G/,"",$4); print $4}')
free_gb=$(df -BG "$HOME" | awk 'NR==2{gsub(/G/,"",$4); print $4}')
mem_gb=$(awk '/MemTotal/{printf "%d", ($2/1024/1024)+0.999}' /proc/meminfo)
printf 'gdk_df_target=%s\n' "$df_target"
printf 'gdk_free_gb=%s\n' "${gdk_free_gb:-unknown}"
printf 'home_free_gb=%s\n' "${free_gb:-unknown}"
printf 'mem_total_gb=%s\n' "${mem_gb:-unknown}"
REMOTE
}

cmd_status() {
  preflight
  guard
  echo "VM:        ${VM_NAME}"
  echo "State:     $(vm_state)"
  echo "IP:        ${VM_IP}"
  echo "GDK root:  ${GDK_ROOT}"
  if [ "$(vm_state)" != "running" ]; then
    warn "VM is not running; status is limited. Run '$0 install' or resume/start the VM to inspect inside it."
    return 0
  fi
  vm_ssh "bash -s -- '$GDK_ROOT'" <<<"$(remote_status_script)"
}

resource_gate() {
  local free_gb mem_gb
  free_gb="$(vm_ssh "GDK_ROOT='$GDK_ROOT' bash -s" <<'REMOTE'
set -euo pipefail
df_target="$GDK_ROOT"
if [ ! -e "$df_target" ]; then
  df_target="$(dirname "$GDK_ROOT")"
fi
if [ ! -e "$df_target" ]; then
  df_target="$HOME"
fi
df -BG "$df_target" | awk 'NR==2{gsub(/G/,"",$4); print $4}'
REMOTE
)"
  mem_gb="$(vm_ssh "awk '/MemTotal/{printf \"%d\", (\$2/1024/1024)+0.999}' /proc/meminfo")"
  log "VM resources: ${free_gb} GiB free for GDK root, ${mem_gb} GiB RAM."
  if { [ "${free_gb:-0}" -lt "$GDK_MIN_FREE_GB" ] || [ "${mem_gb:-0}" -lt "$GDK_MIN_MEM_GB" ]; } && [ "$GDK_FORCE" != "1" ]; then
    die "full GDK needs more headroom (min ${GDK_MIN_FREE_GB} GiB free, ${GDK_MIN_MEM_GB} GiB RAM). Resize VM or set GDK_FORCE=1 if you accept a likely slow/fragile install."
  fi
}

remote_verify_script() {
  cat <<'REMOTE'
set -euo pipefail
GDK_ROOT="$1"
test -d "$GDK_ROOT" || { echo "missing GDK root: $GDK_ROOT" >&2; exit 10; }
test -f "$GDK_ROOT/gdk.yml" || { echo "missing gdk.yml under $GDK_ROOT" >&2; exit 11; }
test -d "$GDK_ROOT/gitlab" || { echo "missing GitLab source under $GDK_ROOT/gitlab" >&2; exit 12; }
test -f "$GDK_ROOT/gitlab/Gemfile" || { echo "missing GitLab Gemfile under $GDK_ROOT/gitlab" >&2; exit 13; }
if command -v gdk >/dev/null 2>&1; then
  gdk version || true
elif [ -x "$GDK_ROOT/bin/gdk" ]; then
  "$GDK_ROOT/bin/gdk" version || true
else
  echo "missing gdk executable" >&2; exit 14
fi
if [ "${GDK_DEEP_VERIFY:-0}" = "1" ]; then
  cd "$GDK_ROOT"
  if command -v gdk >/dev/null 2>&1; then gdk doctor; else "$GDK_ROOT/bin/gdk" doctor; fi
fi
echo "GDK_VERIFY=ok"
REMOTE
}

cmd_verify() {
  preflight
  guard
  ensure_running
  wait_ssh
  vm_ssh "GDK_DEEP_VERIFY='${GDK_DEEP_VERIFY:-0}' bash -s -- '$GDK_ROOT'" <<<"$(remote_verify_script)"
}

remote_online_install_script() {
  cat <<'REMOTE'
set -euo pipefail
GDK_ROOT="$1"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y git make curl ca-certificates
if [ ! -d "$GDK_ROOT/.git" ]; then
  git clone https://gitlab.com/gitlab-org/gitlab-development-kit.git "$GDK_ROOT"
fi
cd "$GDK_ROOT"
git remote -v
cat > gdk.yml <<'YAML'
---
tool_version_manager:
  enabled: true
YAML
# Current GDK docs recommend letting mise/GDK manage the full dependency set.
make bootstrap
if command -v gdk >/dev/null 2>&1; then
  gdk install blobless_clone=true
  gdk doctor || true
else
  ./bin/gdk install blobless_clone=true
  ./bin/gdk doctor || true
fi
touch "$GDK_ROOT/.installed-by-security-testing-harness"
REMOTE
}

cmd_install() {
  preflight
  guard
  ensure_running
  wait_ssh
  if vm_ssh "test -f '$GDK_ROOT/gdk.yml' -a -f '$GDK_ROOT/gitlab/Gemfile'" 2>/dev/null; then
    log "GDK appears present; running verification."
    cmd_verify
    return 0
  fi
  resource_gate
  if [ -n "${GDK_BUNDLE:-}" ]; then
    [ -f "$GDK_BUNDLE" ] || die "GDK_BUNDLE does not exist: $GDK_BUNDLE"
    need scp
    log "Copying offline GDK bundle to VM: $GDK_BUNDLE"
    vm_ssh "mkdir -p '$GDK_ROOT' /tmp/gdk-bundle"
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR "$GDK_BUNDLE" "${SSH_USER}@${VM_IP}:/tmp/gdk-bundle/bundle.tar"
    vm_ssh "tar -xaf /tmp/gdk-bundle/bundle.tar -C '$GDK_ROOT' --strip-components=1 && rm -rf /tmp/gdk-bundle"
    cmd_verify
    return 0
  fi
  if [ "$GDK_ALLOW_NETWORK" != "1" ]; then
    die "GDK is missing and no offline bundle was supplied. Refusing online bootstrap by default. Provide GDK_BUNDLE=/path/to/prebuilt-gdk.tar.* or explicitly set GDK_ALLOW_NETWORK=1 after deciding to allow setup-time VM egress."
  fi
  warn "Online GDK bootstrap contacts package mirrors, GitLab, GitHub, RubyGems, Node/Yarn, Go/Rust, PostgreSQL, Redis, and MinIO endpoints listed by GDK docs. Keep this for setup only; re-apply egress lockdown before kinetic testing."
  vm_ssh "bash -s -- '$GDK_ROOT'" <<<"$(remote_online_install_script)"
  cmd_verify
}

usage() {
  cat <<EOF
gdk-vm.sh — verify/install GDK on the local GitLab lab VM

Usage: $0 <command>

  status     Scope-gated inventory: GDK paths, toolchain, disk/RAM
  verify     Fail unless a complete GDK root + GitLab source are present
  install    Install from GDK_BUNDLE, or online only with GDK_ALLOW_NETWORK=1

Config (env or .env): VM_NAME VM_IP SSH_USER SSH_KEY GDK_ROOT
Safety defaults: GDK_ALLOW_NETWORK=${GDK_ALLOW_NETWORK}; GDK_FORCE=${GDK_FORCE}
Resource gate:  ${GDK_MIN_FREE_GB} GiB free + ${GDK_MIN_MEM_GB} GiB RAM minimum

Examples:
  $0 status
  GDK_BUNDLE=/path/to/prebuilt-gdk.tar.zst $0 install
  GDK_ALLOW_NETWORK=1 $0 install   # setup-time only; re-apply egress lockdown before kinetic tests
EOF
}

case "${1:-}" in
  status) cmd_status ;;
  verify) cmd_verify ;;
  install) cmd_install ;;
  ""|-h|--help|help) usage ;;
  *) usage; die "unknown command: $1" ;;
esac
