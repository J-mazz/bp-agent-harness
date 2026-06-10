---
name: scope-authorization-guard
description: Verify that a target host, URL, or IP is explicitly in scope and authorized before any network interaction in a bug bounty session. ALWAYS run this first, and re-run whenever a new host or subdomain appears. Use whenever the operator names a target, when another skill is about to make a request, or when scope is uncertain. Refuses out-of-scope and unenrolled targets.
---

# Scope Authorization Guard

The mandatory safety gate for this harness. No recon, request, or audit skill may touch a
target until this guard returns **ALLOWED**. When in doubt, this guard treats a target as
**out of scope** and stops.

## When to run

- Before the first request of any session.
- Every time a new host/subdomain/IP is discovered (e.g., from `passive-recon`).
- Whenever the operator pastes a URL or asks to "check" something.

## Inputs

- The program: `programs/<program>/scope.yaml` (created from `context/scope.template.yaml`).
- The candidate target: a host, URL, or IP.

## Procedure

1. **Load scope.** Read `programs/<program>/scope.yaml`. If it is missing, or
   `program.enrolled` is not `true`, **STOP** and tell the operator to confirm enrollment
   and add the official scope. Never proceed on an unconfirmed program.
2. **Note program rules.** Capture `rules.required_user_agent`, `rules.rate_limit_note`, and
   `rules.prohibited`. Pass these along to downstream skills.
3. **Match deterministically.** Run the matcher with the target and the in/out-of-scope
   lists you read from the YAML:
   ```bash
   node .sixth/skills/scope-authorization-guard/scripts/check-scope.mjs \
     --target "app.example.com" \
     --in "example.com,*.example.com,203.0.113.0/24" \
     --out "blog.example.com,*.dev.example.com"
   ```
   The script prints `ALLOWED` or `BLOCKED` with the reason and exits non-zero when blocked.
   `out_of_scope` always wins over `in_scope`.
4. **Decide.**
   - `BLOCKED` → do not make any request. Explain why and ask the operator for an in-scope
     target. Suggest the closest in-scope asset if obvious.
   - `ALLOWED` → restate the target, the program, the required `User-Agent` (if any), and the
     non-destructive constraints, then hand off to the requested skill.
5. **Re-affirm constraints.** Remind that all downstream activity must be read-only, serial,
   rate-limited, and that findings stay in `findings/<program>/` (git-ignored).

## Refusal rules

- No `scope.yaml`, `enrolled: false`, or ambiguous match → **refuse and ask**.
- A target matching `out_of_scope` → **refuse**, even if it also matches `in_scope`.
- A wildcard in scope only authorizes what the program actually published. Do not infer
  apex from `*.example.com` or vice-versa unless both are listed.

## Output format

```
SCOPE CHECK — program: <name>
Target:    <normalized target>
Verdict:   ALLOWED | BLOCKED
Reason:    <which pattern matched / why blocked>
Rules:     UA=<...> | rate=<...> | prohibited=<...>
Next:      <skill to run, or what the operator must clarify>
```
