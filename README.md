# Bug Bounty Testing Harness (Sixth)

A **semi-automated, scope-bound, non-destructive** harness for working authorized
**HackerOne** programs from inside the Sixth AI panel in VS Code.

It is a directory of agent **skills**, **MCP configuration**, and **context files** — not a
standalone scanner. The agent does focused recon and configuration auditing; **you** review
every observation and decide what becomes a report.

> ⚠️ Only use this against assets that are explicitly in scope for a program you are
> enrolled in. Read [AGENTS.md](AGENTS.md) first — it is the operating contract.

## Quick start

1. **Add a program scope.** Copy the template and fill in the real in/out-of-scope assets:
   ```bash
   mkdir -p programs/acme
   cp context/scope.template.yaml programs/acme/scope.yaml
   # edit programs/acme/scope.yaml — paste in-scope + out-of-scope from the H1 policy
   ```
2. **(Optional) Enable MCP.** Install the read-only fetch server config — see
   [mcp/README.md](mcp/README.md).
3. **Open the Sixth panel** and start a session, e.g.:
   > Use `/scope-authorization-guard` to confirm `app.acme.com` is in scope for the `acme`
   > program, then `/bug-bounty-orchestrator` for a passive recon pass.
4. **Review findings** in `findings/acme/`. Use `/hackerone-report` to draft submissions.

## Skills

- `scope-authorization-guard` — run first; verifies target ∈ scope.
- `bug-bounty-orchestrator` — drives the end-to-end semi-automated loop.
- `passive-recon` — DNS, cert-transparency subdomains, tech fingerprint.
- `security-headers-audit` — security headers + cookie flags.
- `tls-config-check` — TLS/SSL configuration hygiene.
- `exposed-files-misconfig` — safe misconfiguration checks (robots, security.txt, `.git`, CORS…).
- `gitlab-test-vm` — (GitLab) launch a local self-managed GitLab CE VM for disruptive/DoS testing you must never run against gitlab.com.
- `gitlab-autopilot` — (local-lab) scope-gated SAST + DAST run against your own local GitLab VM and a full upstream source clone.
- `gitlab-thorough-audit` — (local-lab) subagent tasking plus serial audit lanes for GDK readiness, authz, IDOR/BOLA, GraphQL/REST parity, and CI/CD privilege escalation.
- `hackerone-report` — HackerOne-ready Markdown report from confirmed findings.

## What this harness will NOT do

No DoS, brute-force, active exploitation, data exfiltration, mass scanning, or
out-of-scope testing. See [AGENTS.md](AGENTS.md) §2. Findings are disclosed only via
HackerOne, by you.

## Layout

```
AGENTS.md            operating contract (auto-loaded by Sixth)
context/             rules of engagement, methodology, scope template
programs/<name>/     per-program authorized scope (scope.yaml)
mcp/                 MCP server config + install notes
.sixth/skills/       the agent skills
findings/<name>/     evidence + draft reports (git-ignored)
```
