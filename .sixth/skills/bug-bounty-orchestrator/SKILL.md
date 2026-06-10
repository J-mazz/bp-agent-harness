---
name: bug-bounty-orchestrator
description: Drive the semi-automated, non-destructive recon and audit workflow for an authorized HackerOne program end to end. Use when the operator wants to "start a session", "recon a target", "run the harness", or work a program but has not picked individual skills. Plans the session, enforces the scope gate, runs the recon/audit skills one at a time with operator checkpoints, and routes confirmed findings to the report skill.
---

# Bug Bounty Orchestrator

The conductor for a testing session. You sequence the other skills, keep a human in the
loop at each checkpoint, and never let activity drift out of scope or into intrusive tests.

Read [AGENTS.md](../../../AGENTS.md) and `context/rules-of-engagement.md` before driving.

## Operating principles

- **One asset, one step at a time.** No parallel blasting; serial, rate-limited requests.
- **Checkpoints, not autopilot.** Pause for operator confirmation between phases and before
  anything that could be intrusive.
- **Observation only.** Recon and audits are read-only. The operator decides what is a
  finding; you do not deep-dive exploits.

## Workflow

### 1. Select program & confirm authorization
- Identify the program and load `programs/<program>/scope.yaml`.
- If it is missing or `enrolled` is not `true`, stop and ask the operator to set it up
  (copy `context/scope.template.yaml`). Do not proceed.

### 2. Scope gate (every target)
- For each candidate host/URL/IP, invoke `scope-authorization-guard`.
- Only `ALLOWED` targets proceed. Capture the required `User-Agent` and rate notes.

### 3. Plan the session
- Propose a short plan to the operator: which in-scope assets, which phases
  (passive-recon → security-headers-audit → tls-config-check → exposed-files-misconfig),
  and the order. Get a thumbs-up before sending requests.

### 4. Execute phases (serial, with checkpoints)
Run skills in this order, pausing after each to summarize observations:
1. `passive-recon` — enumerate; re-gate any new in-scope hosts before touching them.
2. `security-headers-audit`
3. `tls-config-check`
4. `exposed-files-misconfig`

Between phases: write notes/evidence under `findings/<program>/<asset>/`, and ask the
operator whether to continue, adjust, or stop.

### 5. Triage
- Group observations into: informational, needs-confirmation, likely-finding.
- For "needs-confirmation", gather the **minimum** extra evidence (one more benign request),
  then hand the decision to the operator.

### 6. Report
- For each confirmed, in-scope issue the operator approves, invoke `hackerone-report`.

## Guardrails (stop and ask if any apply)

- A target is not `ALLOWED`, or a new host has not been gated.
- A check would move from observation to modifying/exfiltrating data, brute-forcing, or
  stressing the target.
- The target shows instability or returns rate-limit responses.
- The program policy prohibits the technique you are about to use.

## Session summary template

```
SESSION — program: <name>  date: <YYYY-MM-DD>
Assets (in-scope, gated): <list>
Phases run: <passive-recon, headers, tls, exposed-files>
Observations: <count> (info: x, needs-confirm: y, likely: z)
Reports drafted: <list of findings/<program>/...>
Open questions for operator: <...>
```
