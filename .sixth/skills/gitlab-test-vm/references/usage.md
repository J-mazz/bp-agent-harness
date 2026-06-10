# gitlab-test-vm — usage & troubleshooting

A local self-managed **GitLab CE** instance in a libvirt/KVM VM, for authorized GitLab
research that must not run against `gitlab.com` (DoS, destructive, high-volume, etc.).

## Quick reference

```bash
S=.sixth/skills/gitlab-test-vm/scripts/gitlab-vm.sh
$S up         # boot the EXISTING VM and wait for SSH (idempotent)
$S status     # VM state, IP, URL, gitlab-ctl health, root login line
$S url        # -> http://192.168.122.7
$S password   # initial root password (valid 24h after first reconfigure)
$S ssh        # shell into the VM (user: debian, passwordless sudo)
$S console    # serial console (exit with Ctrl+])
$S stop       # graceful shutdown
$S start      # boot again
$S gdk-status # scope-gated GDK/toolchain/resource inventory inside the VM
```

## What `up` does (rootless, via the libvirt daemon)
This script **adopts an existing, manually-created VM** — it does not provision one.

1. Preflight: confirms `virsh` + `ssh` exist and `qemu:///system` is reachable (you are in
   the `libvirt` group).
2. Confirms the domain named by `VM_NAME` (default `debian13`) exists; if not, it stops with
   "create it manually first".
3. Starts the domain if it is not already running.
4. Waits for key-based SSH on `VM_IP` (default `192.168.122.7`), then prints `status`.

There is no image download, cloud-init rendering, or `virt-install` step. Create the VM by
hand (any method you like) with Debian + GitLab Omnibus, key-based SSH for `SSH_USER`, and
passwordless `sudo`. An example `scripts/cloud-init.user-data.tmpl` is provided purely as a
reference for that manual build; no script reads it.

## Configuration (environment variables or `.env`)
The wrapper only *adopts* a VM, so it reads identity/connection settings — it does not size
or create hardware. Set these in the repo `.env` or the environment.

| Var | Default | Notes |
|-----|---------|-------|
| `VM_NAME` | `debian13` | libvirt domain name of the pre-created VM. |
| `VM_IP` | `192.168.122.7` | VM address on the libvirt `default` subnet (must match scope). |
| `SSH_USER` | `debian` | SSH login with passwordless `sudo` in the VM. |
| `SSH_KEY` | `~/.ssh/id_ed25519` | Private key used for SSH. |
| `EXTERNAL_URL` | `http://<VM_IP>` | GitLab external URL. |

Example: `VM_NAME=debian13 VM_IP=192.168.122.7 $S status`

> Sizing (RAM/vCPU/disk) is a property of the VM you built by hand, not of this script.

## State & secrets
- SSH key material and any captured VM runtime state live in `findings/gitlab/vm/`
  (git-ignored, confidential). Treat them as secrets.
- The initial root password file inside the VM is auto-removed 24h after the first
  reconfigure. Reset it later with:
  ```bash
  $S ssh
  sudo gitlab-rake "gitlab:password:reset[root]"
  ```

## Accessing GitLab
- Browse to `http://192.168.122.7` from the host (the libvirt NAT network is host-reachable).
- The host firewall normally permits traffic to `virbr0`; if the page does not load, confirm
  the VM is `running` via `$S status`.

## Troubleshooting
- **`cannot reach libvirt at qemu:///system`** — you were just added to the `libvirt` group;
  log out/in (or `exec su -l "$USER"`) and retry. Confirm with `virsh -c qemu:///system version`.
- **SSH never comes up** — watch the boot via `$S console`; confirm the VM got `VM_IP` and
  that your `SSH_KEY` is authorized for `SSH_USER`.
- **GitLab slow to come up** — `$S ssh` then `sudo gitlab-ctl tail` to follow logs;
  `sudo gitlab-ctl status` to list services.
- **Wrong VM adopted** — set `VM_NAME`/`VM_IP` (env or `.env`) to match the domain you built.

## Scope note
This VM is your own lab. Do not run the `passive-recon`, `security-headers-audit`,
`tls-config-check`, or `exposed-files-misconfig` skills against it as if it were the remote
`gitlab` program. Keep disruptive testing here; never against `gitlab.com`.
