---
name: gitlab-test-vm
description: Launch and manage a local self-managed GitLab CE instance in a libvirt/KVM virtual machine for authorized GitLab bug bounty research. Use whenever the operator wants to "spin up GitLab", "start the test VM", "launch the GitLab lab", install a standalone GitLab instance, or needs a safe target for disruptive/DoS/destructive testing that must never be run against gitlab.com. Provisions Debian 12 + GitLab Omnibus via cloud-init, rootless through the libvirt daemon.
---

# GitLab Test VM

Brings up a throwaway, self-managed **GitLab CE** instance inside a local **libvirt/KVM**
VM. This is *your own instance* — the right place for the testing GitLab's policy says must
**never** happen on `gitlab.com`: denial-of-service, destructive actions, abuse-style flows,
and anything disruptive.

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

## Prerequisites (already verified on this host)
- libvirt/KVM + `virt-install`, `qemu-img`; user in the `libvirt` group (rootless).
- ~50 GB free disk, ≥ 4 GB RAM free (defaults: 4 vCPU / 8 GB / 50 GB).

## Control script
All actions go through one idempotent script:

```bash
.sixth/skills/gitlab-test-vm/scripts/gitlab-vm.sh <command>
```

| Command | Action |
|---------|--------|
| `up` | Create + boot the VM and provision GitLab (safe to re-run). |
| `status` | VM state, IP, GitLab health, and URL. |
| `url` | Print the GitLab URL. |
| `password` | Print the initial `root` password (from inside the VM). |
| `ssh` | Open an SSH shell into the VM. |
| `console` | Attach to the serial console (`Ctrl+]` to exit). |
| `stop` / `start` | Graceful shutdown / boot of an existing VM. |
| `gdk-status` | Scope-gated inventory of GDK presence, toolchain, RAM, and disk. |
| `gdk-verify` | Fail unless a complete GDK root and GitLab source are present. |
| `gdk-install` | Install GDK from `GDK_BUNDLE`, or online only with `GDK_ALLOW_NETWORK=1`. |
| `destroy` | Delete the VM and its disk (asks for confirmation). |

See `references/usage.md` for details, tuning (`VM_MEM_MB`, `VM_VCPUS`, `VM_DISK_GB`), and
troubleshooting.

## Typical flow
1. `gitlab-vm.sh up` — first run downloads a Debian cloud image and installs GitLab Omnibus
   (one-time, several minutes). Re-running is a no-op once it is healthy.
2. `gitlab-vm.sh status` until GitLab reports healthy, then open the printed URL
   (default `http://192.168.122.60`).
3. `gitlab-vm.sh password` for the initial `root` login (valid 24h after provisioning).
4. Research freely **on this VM**. Capture the reproduction artifacts (video/logs) GitLab
   requires, then draft with `hackerone-report`.
5. Optional GDK path: `gitlab-vm.sh gdk-status`, then `GDK_BUNDLE=/path/to/prebuilt-gdk.tar.zst gitlab-vm.sh gdk-install` or an explicitly authorized setup-time online bootstrap with `GDK_ALLOW_NETWORK=1`.
6. `gitlab-vm.sh destroy` when done, or `stop` to suspend.

## Guardrails
- Runtime state (SSH keys, IP, rendered cloud-init) is written under `findings/gitlab/vm/`
  (git-ignored, confidential). Never commit it.
- This skill only ever touches the **local** VM via the libvirt daemon. It performs no
  action against any remote GitLab asset.
- Keep DoS/destructive testing inside this VM. If you must size for production-like DoS
  testing, raise `VM_MEM_MB`/`VM_VCPUS` per GitLab's self-managed requirements.
