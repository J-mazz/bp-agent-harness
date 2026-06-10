---
name: gitlab-autopilot
description: >-
  Semi-automated static (SAST) and dynamic (DAST) analysis run against the
  operator-owned local GitLab VM (program local-lab, 192.168.122.7) and a full
  clone of the matching upstream source. Use to plan and drive a recon -> SAST ->
  DAST -> triage session. Every network action is gated by scope-authorization-guard;
  it ONLY ever targets the local VM, never gitlab.com. Aggressive techniques are
  permitted because the target is a private instance the operator fully owns.
---

# gitlab-autopilot

A collaborative autopilot for analysing the **local** GitLab lab. It pairs:

- **Static analysis (SAST)** of a full upstream source clone
  (`findings/gitlab/source/gitlab`, matched to the installed `gitlab-ee` version).
- **Dynamic analysis (DAST)** against the running VM at `http://192.168.122.7`
  (program `local-lab`), plus an optional interactive **Burp Suite** station on
  the existing `kali-og-testing` VM.

> The operator owns the hardware and the instance. This is the authorized place
> for scanning, fuzzing, and destructive/DoS experiments that the public `gitlab`
> HackerOne program forbids against gitlab.com. Findings here become manually
> verified, reproducible PoCs that are THEN reported per the `gitlab` program rules.

## Hard rules (inherited from AGENTS.md + local-lab/scope.yaml)

1. **Scope gate first.** Before any network action, the driver runs
   `scope-authorization-guard`. The ONLY in-scope host is `192.168.122.7`.
   `gitlab.com` and the whole production estate are explicitly out-of-scope; the
   guard is default-deny so the host gateway and every other VM are blocked too.
2. **No off-host wandering.** Tools must not follow redirects/links off the VM
   (no CDN, no update server, no gitlab.com). nuclei/nmap are pinned to the IP.
3. **Artifacts are confidential.** Everything lands under
   `findings/local-lab/<timestamp>/` (git-ignored).
4. **Collaborative.** Stop and check in with the operator on low-confidence or
   consequential decisions (e.g. anything destructive, credentialed mutation).

## Tooling (host)

| Phase | Tool | How it runs |
|-------|------|-------------|
| recon | `nmap` | native |
| DAST  | `nuclei` (+ `~/nuclei-templates`) | native, pinned to the VM IP |
| SAST  | `semgrep` | `podman run … semgrep/semgrep` (Ruby/Rails rules) |
| SAST  | `brakeman` | `podman run … presidentbeef/brakeman` (Rails) |
| SAST  | `gitleaks` | `podman run … zricethezav/gitleaks` (secrets) |
| DAST  | Burp Suite | interactive, on `kali-og-testing` VM |

`semgrep/brakeman/gitleaks/trivy/zaproxy` are **not** installed natively; the
driver runs them as `podman` containers on demand. `docker` is absent — use
`podman`.

## Workflow

Run the driver (it prints a scope verdict before every networked phase):

```bash
.sixth/skills/gitlab-autopilot/scripts/autopilot.sh <phase>
```

Phases:

- `preflight` — verify VM up, source clone present, scope guard ALLOWs the VM,
  required tools resolvable. Pulls SAST container images if missing.
- `recon` — `nmap` service/version scan of the VM (scope-gated).
- `sast` — `semgrep` + `brakeman` + `gitleaks` over the cloned source.
- `dast` — `nuclei` against `http://192.168.122.7` (scope-gated, IP-pinned).
- `burp` — boot `kali-og-testing` and print Burp targeting instructions.
- `gdk-status` — scope-gated full-GDK/toolchain/resource inventory inside the VM.
- `gdk-verify` — fail unless a complete GDK root and GitLab source are present.
- `thorough` — create subagent tasking, run serial read-only audit lanes, and consolidate evidence.
- `triage` — summarise findings into `findings/local-lab/<ts>/SUMMARY.md`.
- `all` — preflight → recon → sast → dast → triage (skips interactive burp).

Use `/gitlab-thorough-audit` when you want focused subagent lanes for GDK readiness,
authz boundary review, IDOR/BOLA, GraphQL/REST parity, CI/CD privilege escalation,
and evidence consolidation.

## After the run

1. Operator reviews `SUMMARY.md` and decides what is a real finding.
2. For each confirmed issue, manually reproduce and capture artifacts.
3. Use the `hackerone-report` skill to draft a report against the `gitlab`
   program (self-managed PoC; never re-run the exploit against gitlab.com).
