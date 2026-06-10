#!/usr/bin/env bash
# egress-verify.sh — FAIL-CLOSED proof that the lab VM cannot reach off-host.
#
# WHY: before any KINETIC (state-changing / active-exploitation) test we must be
# certain an SSRF/exploit callback can never escape to gitlab.com or anywhere
# else. The earlier inline check was fail-OPEN: a single SSH that exited non-zero
# for ANY reason (wrong key/user, host down, missing curl) was misread as
# "egress blocked". This script treats every uncertainty as NOT contained.
#
# Containment is proven by a behavioural test (authoritative) plus a best-effort
# structural test:
#   (behavioural) over SSH, the VM tries to reach several external endpoints —
#                 mix of raw IPs (no DNS) and hostnames. ANY success => OPEN.
#                 SSH/transport failure, missing curl, empty/!sentinel output,
#                 or an indeterminate result => abort (fail closed).
#   (structural)  the host nftables `labguard` table should be present. Checked
#                 without ever prompting for a sudo password; if it can be proven
#                 ABSENT we abort, otherwise we defer to the behavioural proof.
#
# Exit codes:  0 = contained (safe to proceed)
#              1 = egress is OPEN (run egress-lockdown.sh apply)
#              3 = cannot verify / containment table proven absent (fail closed)
set -euo pipefail

VM_IP="${VM_IP:-192.168.122.7}"
SSH_USER="${SSH_USER:-debian}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
TABLE="${LABGUARD_TABLE:-labguard}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LOCKDOWN="${SCRIPT_DIR}/egress-lockdown.sh"

log(){ printf '\033[1;34m[egress-verify]\033[0m %s\n' "$*" >&2; }
err(){ printf '\033[1;31m[egress-verify]\033[0m %s\n' "$*" >&2; }

# --- (structural) best-effort nftables table check — never prompts for sudo ----
structural="unknown"
if command -v nft >/dev/null 2>&1; then
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    structural="present"
  else
    nft_out="$(sudo -n nft list table inet "$TABLE" 2>&1)" && structural="present" || {
      case "$nft_out" in
        *password*|*"terminal is required"*|*"sudo:"*) structural="unknown" ;;  # can't tell w/o password
        *) structural="absent" ;;                                              # nft ran, no such table
      esac
    }
  fi
fi
if [ "$structural" = "absent" ]; then
  err "host nftables '${TABLE}' containment table is ABSENT."
  err "apply it first:  .sixth/skills/gitlab-test-vm/scripts/egress-lockdown.sh apply"
  exit 3
fi

# --- (behavioural) authoritative: prove the VM cannot open outbound flows ------
# Honour SSH_USER/SSH_KEY exactly like every other script. The remote prints a
# definitive sentinel; anything else is treated as "cannot verify".
remote_check='
command -v curl >/dev/null 2>&1 || { echo NOCURL; exit 0; }
open=0
for u in https://1.1.1.1/ https://8.8.8.8/ http://93.184.216.34/ https://gitlab.com/; do
  if curl -s -o /dev/null -m 6 "$u" 2>/dev/null; then echo "REACHED $u"; open=1; fi
done
if [ "$open" -eq 0 ]; then echo EGRESS_BLOCKED; else echo EGRESS_OPEN; fi
'

verdict="$(ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=8 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
    -o LogLevel=ERROR \
    "${SSH_USER}@${VM_IP}" "$remote_check" 2>/dev/null)" || {
  err "cannot verify egress: SSH to ${SSH_USER}@${VM_IP} failed (key/user/host?)."
  err "refusing to proceed — containment is UNPROVEN (fail closed)."
  exit 3
}

if [ -z "$verdict" ]; then
  err "empty result from VM egress probe — refusing (fail closed)."; exit 3
fi
if printf '%s\n' "$verdict" | grep -q '^NOCURL$'; then
  err "curl is missing on the VM — cannot run the behavioural egress test; refusing."; exit 3
fi
if printf '%s\n' "$verdict" | grep -q '^EGRESS_OPEN$'; then
  err "VM egress is OPEN — it reached an external host:"
  printf '%s\n' "$verdict" | grep '^REACHED ' | sed 's/^/    /' >&2
  err "run egress-lockdown.sh apply before kinetic testing."
  exit 1
fi
if ! printf '%s\n' "$verdict" | grep -q '^EGRESS_BLOCKED$'; then
  err "indeterminate egress verdict — refusing (fail closed):"
  printf '%s\n' "$verdict" | sed 's/^/    /' >&2
  exit 3
fi

if [ "$structural" = "present" ]; then
  log "Containment verified: host '${TABLE}' table present AND VM cannot reach off-host."
else
  log "Containment verified behaviourally: VM cannot reach off-host (nft table state: ${structural})."
fi
exit 0
