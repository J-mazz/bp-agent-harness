#!/usr/bin/env bash
# gitlab-vm.sh — manage the local self-managed GitLab test VM (libvirt/KVM).
#
# This adopts an EXISTING, manually-created VM (the OS and GitLab are installed by
# hand). The script is a thin convenience wrapper: start/stop/status/ssh/console
# plus helpers to read the GitLab URL and initial root password.
#
# It ONLY ever talks to the local libvirt daemon and the VM over SSH. It performs
# no network action against any remote GitLab asset. The VM is YOUR own instance —
# the authorized place for disruptive/DoS/destructive GitLab research.
set -euo pipefail

# -- Resolve repo root (script lives at .sixth/skills/gitlab-test-vm/scripts/) --
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SKILL_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SKILL_DIR}/../../.." >/dev/null 2>&1 && pwd)"

# -- Load .env (VM_NAME / VM_IP / SSH_USER, etc.) -------------------------------
if [ -f "${REPO_ROOT}/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "${REPO_ROOT}/.env"
  set +a
fi

# -- Configuration (override via environment or .env) --------------------------
VM_NAME="${VM_NAME:-debian13}"
VM_IP="${VM_IP:-192.168.122.7}"
SSH_USER="${SSH_USER:-debian}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
LIBVIRT_NET="${LIBVIRT_NET:-default}"
CONN="qemu:///system"
EXTERNAL_URL="${EXTERNAL_URL:-http://${VM_IP}}"
GDK_HELPER="${SCRIPT_DIR}/gdk-vm.sh"

VIRSH() { virsh -c "$CONN" "$@"; }
log()  { printf '\033[1;34m[gitlab-vm]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[gitlab-vm]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[gitlab-vm] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

preflight() {
  for c in virsh ssh; do need "$c"; done
  if ! VIRSH version >/dev/null 2>&1; then
    die "cannot reach libvirt at $CONN. Ensure you are in the 'libvirt' group (re-login if just added)."
  fi
}

vm_exists()  { VIRSH dominfo "$VM_NAME" >/dev/null 2>&1; }
vm_running() { VIRSH domstate "$VM_NAME" 2>/dev/null | grep -q running; }

vm_ssh() {
  ssh -i "$SSH_KEY" \
      -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=8 \
      -o LogLevel=ERROR \
      "${SSH_USER}@${VM_IP}" "$@"
}

wait_ssh() {
  log "Waiting for SSH on ${VM_IP}..."
  local i
  for i in $(seq 1 30); do
    if vm_ssh true 2>/dev/null; then log "SSH is up."; return 0; fi
    sleep 5
  done
  die "timed out waiting for SSH. Try: $0 console"
}

gitlab_health() {
  vm_ssh "sudo gitlab-ctl status 2>/dev/null | head -n 20" 2>/dev/null \
    || echo "(GitLab not reachable yet / not installed)"
}

cmd_up() {
  preflight
  vm_exists || die "VM '${VM_NAME}' does not exist. Create it manually first, or set VM_NAME in .env."
  vm_running || { log "Starting '${VM_NAME}'..."; VIRSH start "$VM_NAME"; }
  wait_ssh
  echo
  cmd_status
}

cmd_status() {
  preflight
  if ! vm_exists; then echo "VM '${VM_NAME}': not found."; return; fi
  echo "VM:        ${VM_NAME}"
  echo "State:     $(VIRSH domstate "$VM_NAME" 2>/dev/null || echo unknown)"
  echo "IP:        ${VM_IP}"
  echo "URL:       ${EXTERNAL_URL}"
  if vm_running; then
    echo "-- gitlab-ctl status --"
    gitlab_health
  fi
}

cmd_url() { echo "$EXTERNAL_URL"; }

cmd_password() {
  preflight
  vm_running || die "VM is not running."
  vm_ssh "sudo cat /etc/gitlab/initial_root_password 2>/dev/null" \
    || die "initial password file not found (removed 24h after first reconfigure; reset with: $0 ssh then 'sudo gitlab-rake \"gitlab:password:reset[root]\"')."
}

cmd_ssh()     { preflight; exec ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "${SSH_USER}@${VM_IP}"; }
cmd_console() { preflight; exec VIRSH console "$VM_NAME"; }
cmd_start()   { preflight; VIRSH start "$VM_NAME"; }
cmd_stop()    { preflight; VIRSH shutdown "$VM_NAME"; log "Shutdown signal sent."; }
cmd_gdk_status()  { bash "$GDK_HELPER" status; }
cmd_gdk_verify()  { bash "$GDK_HELPER" verify; }
cmd_gdk_install() { bash "$GDK_HELPER" install; }

usage() {
  cat <<EOF
gitlab-vm.sh — manage the local self-managed GitLab test VM (libvirt/KVM)

Adopts an existing, manually-created VM (OS + GitLab installed by hand).

Usage: $0 <command>

  up         Boot the VM and wait for SSH (idempotent)
  status     Show VM state, IP, URL, and GitLab health
  url        Print the GitLab URL
  password   Print the initial root password
  ssh        SSH into the VM
  console    Attach to the serial console (Ctrl+] to exit)
  start      Boot the VM
  stop       Graceful shutdown
  gdk-status Scope-gated GDK/toolchain/resource inventory inside the VM
  gdk-verify Fail unless a complete GDK root + GitLab source are present
  gdk-install Install GDK from GDK_BUNDLE, or online only with GDK_ALLOW_NETWORK=1

Config (env or .env): VM_NAME VM_IP SSH_USER SSH_KEY EXTERNAL_URL
  Current: VM_NAME=${VM_NAME} VM_IP=${VM_IP} SSH_USER=${SSH_USER}
EOF
}

case "${1:-}" in
  up) cmd_up;;
  status) cmd_status;;
  url) cmd_url;;
  password) cmd_password;;
  ssh) cmd_ssh;;
  console) cmd_console;;
  start) cmd_start;;
  stop) cmd_stop;;
  gdk-status) cmd_gdk_status;;
  gdk-verify) cmd_gdk_verify;;
  gdk-install) cmd_gdk_install;;
  ""|-h|--help|help) usage;;
  *) usage; die "unknown command: $1";;
esac
