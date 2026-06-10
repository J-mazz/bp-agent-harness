---
name: gitlab-thorough-audit
description: "Use when: running a deep local-lab GitLab audit, adding subagent tasking, checking GDK readiness, auditing authz bypass, IDOR/BOLA, GraphQL/REST parity, CI/CD privilege escalation, or chained ATT&CK evidence consolidation. Creates subagent task packets and runs scope-gated local-only audit lanes."
---

# GitLab Thorough Audit

This skill coordinates a **thorough local-lab-only audit** of the GitLab VM at
`192.168.122.7`. It is intentionally built around independent audit lanes so an
agent can task subagents with focused reviews while networked probes remain
serial, scope-gated, and auditable.

## Hard rules

- Run `scope-authorization-guard` before any VM request. The only authorized
  runtime target is `192.168.122.7` under `programs/local-lab/scope.yaml`.
- Keep networked probes serial. Do not parallel-blast the VM.
- Default lanes are read-only or read-intent GraphQL POSTs. Kinetic/write probes
  are opt-in and must keep VM egress locked down.
- Artifacts stay under `findings/local-lab/<timestamp>/`.
- Do not use this against `gitlab.com` or any production GitLab asset.

## Subagent lanes

Create a task pack first:

```bash
.sixth/skills/gitlab-thorough-audit/scripts/subagent-audit.sh plan
```

The task pack writes focused prompts to `findings/local-lab/<ts>/subagents/`:

1. **GDK/runtime readiness** — verify full GDK state and blockers.
2. **Authz/role boundary** — role-based access and CI/CD secret authorization.
3. **IDOR/BOLA** — REST and object-level authorization boundaries.
4. **GraphQL** — field-level authorization and resolver parity with REST.
5. **CI/CD privilege escalation** — runners, variables, job-token scope, pipeline poisoning prerequisites.
6. **Evidence consolidation** — merge results into a reportable triage view.

For AI-driven work, launch read-only exploration subagents from those prompts.
For runtime validation, use the serial lane runner below.

## Commands

```bash
.sixth/skills/gitlab-thorough-audit/scripts/subagent-audit.sh run-readonly
.sixth/skills/gitlab-thorough-audit/scripts/subagent-audit.sh run-kinetic
.sixth/skills/gitlab-thorough-audit/scripts/subagent-audit.sh consolidate
.sixth/skills/gitlab-thorough-audit/scripts/subagent-audit.sh all
```

- `run-readonly` runs the existing `auth-api`, `idor`, `role-privesc`, and
  read-only ATT&CK emulation lanes under one timestamp.
- `run-kinetic` runs the write-side privesc/IDOR lane only after the existing
  egress-containment assertion passes.
- `all` means `plan -> gdk-status -> run-readonly -> consolidate`; it deliberately
  does not run kinetic tests.

## Output

Each run writes:

- `subagents/*.md` — subagent task packets.
- `<lane>/RESULTS.txt`, `<lane>/stdout.log`, `<lane>/stderr.log` — lane evidence.
- `AUDIT-MANIFEST.json` — scope/constraint/lane metadata.
- `CONSOLIDATED-FINDINGS.md` — operator triage summary.

The operator decides whether any observation is a real finding before report
drafting.
