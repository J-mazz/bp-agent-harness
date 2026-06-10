---
name: gitlab-test-vm
description: Manage a local self-managed GitLab instance running in a pre-created libvirt/KVM virtual machine for authorized GitLab bug bounty research. Use whenever the operator wants to "start the test VM", "boot the GitLab lab", SSH into it, check its status/URL, or needs a safe target for disruptive/DoS/destructive testing that must never be run against gitlab.com. Adopts an existing, manually-created VM (Debian 13 + GitLab Omnibus) over the libvirt daemon and SSH; it does not provision, download, or virt-install anything.
---

# GitLab Test VM

Manages an existing, self-managed **GitLab** instance inside a local **libvirt/KVM**
VM. This is *your own instance* — the right place for the testing GitLab's policy says must
**never** happen on `gitlab.com`: denial-of-service, destructive actions, abuse-style flows,
and anything disruptive.

> **This script adopts a VM you created by hand.** It does not download images, render
> cloud-init, or run `virt-install`. If the domain named by `VM_NAME` does not exist, the
> script stops and tells you to create it first.

> This VM is your lab, not a HackerOne in-scope remote asset. Do **not** point the recon /
> audit skills at it as if it were the `gitlab` program, and never aim disruptive tests at
> `gitlab.com`. See `programs/gitlab/scope.yaml` and `context/rules-of-engagement.md`.

## When to use
- "Install / launch / start the GitLab VM", "spin up GitLab", "boot the lab".
- You need a safe target for DoS, destructive, or high-volume research.
- You want to reproduce a vulnerability against a real Omnibus install before reporting.

For *source-code* research GitLab also recommends the **GDK** (GitLab Development Kit). This
skill keeps the **self-managed Omnibus** route for shipped-product validation and now also
exposes scope-gated GDK readiness/install helpers for the same local VM.

## Prerequisites
- A **manually-created** libvirt/KVM domain (default name `debian13`) running Debian +
  GitLab Omnibus, reachable at `VM_IP` (default `192.168.122.7`) with key-based SSH for
  `SSH_USER` (default `debian`) and passwordless `sudo` inside the VM.
- libvirt/KVM with the user in the `libvirt` group (rootless `qemu:///system`).
- For comfortable GitLab + GDK work: ≥ 16 GB RAM and ≥ 50 GB free disk in the VM.
- An example `scripts/cloud-init.user-data.tmpl` is included **only** as a reference if you
  choose to build the VM with cloud-init by hand; no script consumes it.

## Control script
All actions go through one idempotent script:

```bash
.sixth/skills/gitlab-test-vm/scripts/gitlab-vm.sh <command>
```

| Command | Action |
|---------|--------|
| `up` | Boot the **existing** VM and wait for SSH (idempotent; fails if it doesn't exist). |
| `status` | VM state, IP, GitLab health, and URL. |
| `url` | Print the GitLab URL. |
| `password` | Print the initial `root` password (from inside the VM). |
| `ssh` | Open an SSH shell into the VM. |
| `console` | Attach to the serial console (`Ctrl+]` to exit). |
| `stop` / `start` | Graceful shutdown / boot of the existing VM. |
| `gdk-status` | Scope-gated inventory of GDK presence, toolchain, RAM, and disk. |
| `gdk-verify` | Fail unless a complete GDK root and GitLab source are present. |
| `gdk-install` | Install GDK from `GDK_BUNDLE`, or online only with `GDK_ALLOW_NETWORK=1`. |

See `references/usage.md` for details, tuning (`VM_MEM_MB`, `VM_VCPUS`, `VM_DISK_GB`), and
troubleshooting.

## Typical flow
1. `gitlab-vm.sh up` — boots the existing VM and waits for SSH. (It does **not** provision;
   create the VM by hand first if it doesn't exist.)
2. `gitlab-vm.sh status` until GitLab reports healthy, then open the printed URL
   (default `http://192.168.122.7`).
3. `gitlab-vm.sh password` for the initial `root` login (valid 24h after the first reconfigure).
4. Research freely **on this VM**. Capture the reproduction artifacts (video/logs) GitLab
   requires, then draft with `hackerone-report`.
5. Optional GDK path: `gitlab-vm.sh gdk-status`, then `GDK_BUNDLE=/path/to/prebuilt-gdk.tar.zst gitlab-vm.sh gdk-install` or an explicitly authorized setup-time online bootstrap with `GDK_ALLOW_NETWORK=1`.
6. `gitlab-vm.sh stop` to suspend when done.

## Guardrails
- Runtime state (SSH keys, IP) lives under `findings/gitlab/vm/` (git-ignored, confidential).
  Never commit it.
- This skill only ever touches the **local** VM via the libvirt daemon. It performs no
  action against any remote GitLab asset.
- Keep DoS/destructive testing inside this VM. If you must size for production-like DoS
  testing, raise `VM_MEM_MB`/`VM_VCPUS` per GitLab's self-managed requirements.
