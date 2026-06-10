# gitlab-test-vm — usage & troubleshooting

A local self-managed **GitLab CE** instance in a libvirt/KVM VM, for authorized GitLab
research that must not run against `gitlab.com` (DoS, destructive, high-volume, etc.).

## Quick reference

```bash
S=.sixth/skills/gitlab-test-vm/scripts/gitlab-vm.sh
$S up         # create + boot + provision GitLab (idempotent, safe to re-run)
$S status     # VM state, IP, URL, gitlab-ctl health, root login line
$S url        # -> http://192.168.122.60
$S password   # initial root password (valid 24h after first reconfigure)
$S ssh        # shell into the VM (user: debian, passwordless sudo)
$S console    # serial console (exit with Ctrl+])
$S stop       # graceful shutdown
$S start      # boot again
$S destroy    # delete VM + disk (asks to confirm)
```

## What `up` does (rootless, via the libvirt daemon)
1. Preflight: confirms `qemu:///system` is reachable (you are in the `libvirt` group).
2. Ensures the libvirt `default` NAT network + storage pool exist and are running, and pins
   a DHCP reservation so the VM always gets `192.168.122.60`.
3. Downloads the Debian 12 generic cloud image into `~/.cache/gitlab-test-vm/` and verifies
   it against the official `SHA512SUMS`.
4. Generates a dedicated SSH keypair and renders `cloud-init.user-data.tmpl`.
5. Creates a qcow2 volume in the `default` pool, uploads the base image, resizes to 50 GB.
6. `virt-install --import --cloud-init` boots the VM; cloud-init installs GitLab Omnibus and
   writes a completion marker at `/var/lib/gitlab-provision-done`.
7. Waits for SSH, then for the marker, then prints status.

First run takes several minutes (image download + ~1 GB GitLab package + `reconfigure`).
Subsequent `up` calls are no-ops once the VM is healthy.

## Tuning (environment variables)
| Var | Default | Notes |
|-----|---------|-------|
| `VM_MEM_MB` | `8192` | Raise for production-like DoS sizing. |
| `VM_VCPUS` | `4` | GitLab needs ≥ 4 for comfort. |
| `VM_DISK_GB` | `50` | Root disk size. |
| `VM_IP` | `192.168.122.60` | Must be on the libvirt `default` subnet. |
| `VM_MAC` | `52:54:00:6b:b0:60` | Tied to the DHCP reservation. |
| `VM_NAME` | `gitlab-test` | libvirt domain + volume name. |

Example: `VM_MEM_MB=16384 VM_VCPUS=8 $S up`

## State & secrets
- SSH key, `known_hosts`, and rendered `user-data.yaml` live in `findings/gitlab/vm/`
  (git-ignored, confidential). Treat them as secrets.
- The initial root password file inside the VM is auto-removed 24h after the first
  reconfigure. Reset it later with:
  ```bash
  $S ssh
  sudo gitlab-rake "gitlab:password:reset[root]"
  ```

## Accessing GitLab
- Browse to `http://192.168.122.60` from the host (the libvirt NAT network is host-reachable).
- The host firewall normally permits traffic to `virbr0`; if the page does not load, confirm
  the VM is `running` and provisioning is `yes` via `$S status`.

## Troubleshooting
- **`cannot reach libvirt at qemu:///system`** — you were just added to the `libvirt` group;
  log out/in (or `exec su -l "$USER"`) and retry. Confirm with `virsh -c qemu:///system version`.
- **SSH never comes up** — watch the boot via `$S console` (cloud-init logs to the console).
  cloud-init details are in the VM at `/var/log/cloud-init-output.log`.
- **GitLab slow to come up** — `$S ssh` then `sudo gitlab-ctl tail` to follow logs;
  `sudo gitlab-ctl status` to list services.
- **IP already in use / reservation conflict** — pick another with
  `VM_IP=192.168.122.61 VM_MAC=52:54:00:6b:b0:61 $S up` (after `destroy`).
- **Start fresh** — `$S destroy` then `$S up`.

## Scope note
This VM is your own lab. Do not run the `passive-recon`, `security-headers-audit`,
`tls-config-check`, or `exposed-files-misconfig` skills against it as if it were the remote
`gitlab` program. Keep disruptive testing here; never against `gitlab.com`.
