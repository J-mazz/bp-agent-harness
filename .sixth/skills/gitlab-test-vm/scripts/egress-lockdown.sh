#!/usr/bin/env bash
# egress-lockdown.sh — host-side containment for the local-lab GitLab VM.
#
# WHY: the libvirt NAT default lets the VM reach the whole internet. Before any
# KINETIC (state-changing / active-exploitation) testing we must guarantee the
# VM cannot open connections off-host — so an SSRF/exploit callback can never
# escape to gitlab.com or anywhere else. Containment is enforced on the HOST
# (the VM is the target; we never trust the target's own firewall to contain it).
#
# MECHANISM: a dedicated nftables table `inet labguard` with a forward-hook chain
# at priority -150 (before firewalld's filter_FORWARD at +10). It DROPS every
# forwarded packet whose source is the VM. Management traffic is unaffected:
#   host <-> VM (SSH:22, HTTP:80) and VM -> host (DNS/DHCP on 192.168.122.1)
#   traverse the host INPUT/OUTPUT chains, NOT FORWARD.
#
# Reversible: `remove` deletes the table. Re-run `apply` after any libvirt/
# firewalld restart (those do not touch this table, but a host reboot clears it).
set -euo pipefail

VM_IP="${VM_IP:-192.168.122.7}"
HOST_BR_IP="${HOST_BR_IP:-192.168.122.1}"
TABLE="labguard"
cmd="${1:-apply}"

need_root(){ if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi; }
need_root

apply(){
  $SUDO nft "list table inet ${TABLE}" >/dev/null 2>&1 && $SUDO nft delete table inet "${TABLE}"
  $SUDO nft -f - <<EOF
table inet ${TABLE} {
  chain forward {
    type filter hook forward priority -150; policy accept;
    # allow only return traffic for already-established flows TO the VM
    ip daddr ${VM_IP} ct state established,related accept
    # VM -> host bridge (DNS/DHCP/HTTP-callback-to-host) stays allowed for lab use
    ip saddr ${VM_IP} ip daddr ${HOST_BR_IP} accept
    # everything else sourced from the VM (WAN, other subnets, inter-VM) is DROPPED
    ip saddr ${VM_IP} counter drop
  }
}
EOF
  echo "[egress-lockdown] applied: forwarded egress from ${VM_IP} DROPPED (host-only allowed)."
}

remove(){
  if $SUDO nft "list table inet ${TABLE}" >/dev/null 2>&1; then
    $SUDO nft delete table inet "${TABLE}"; echo "[egress-lockdown] removed."
  else echo "[egress-lockdown] not present."; fi
}

status(){
  if $SUDO nft "list table inet ${TABLE}" >/dev/null 2>&1; then
    $SUDO nft list table inet "${TABLE}"
  else echo "[egress-lockdown] table inet ${TABLE} not present."; fi
}

case "$cmd" in
  apply)  apply ;;
  remove) remove ;;
  status) status ;;
  *) echo "usage: $0 {apply|remove|status}" >&2; exit 2 ;;
esac
