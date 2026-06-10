---
name: hackerone-report
description: Turn a confirmed, in-scope finding into a polished HackerOne-ready Markdown report with title, CVSS severity, asset, clear reproduction steps, impact, remediation, and redacted evidence. Use when the operator has confirmed a real issue and wants to draft a submission, or asks to "write this up" / "make a report". Does not submit anything — the operator submits via HackerOne. Confirm the finding is in scope before writing.
---

# HackerOne Report Writer

Produce a clean, triage-friendly report for a single confirmed finding. You draft; the
**operator submits** through the program's HackerOne page. Never auto-submit or contact
anyone.

**Pre-req:** the issue is confirmed, the asset passed `scope-authorization-guard`, and the
operator approved writing it up.

## Gather before writing
- Affected asset (exact in-scope host/URL/endpoint).
- Vulnerability type (map to CWE where possible).
- The minimal, **redacted** evidence already captured in `findings/<program>/<asset>/`.
- Reproduction steps that a triager can follow with the least privilege/effort.
- Real-world impact, scoped to what was actually demonstrated (no speculation).

## Severity
- Compute a **CVSS 3.1** vector and base score; show the vector string.
- Align the qualitative rating with the program's severity guidance. When uncertain, rate
  **conservatively** and say why.

## Writing rules
- Be precise and reproducible; a triager should reproduce it in minutes.
- Redact secrets, tokens, and any PII. Include only evidence needed to prove the issue.
- Claim only what you demonstrated non-destructively. No "this could lead to RCE" unless shown.
- Professional, neutral tone. No marketing, no exaggeration.

## Procedure
1. Read the template at `references/report-template.md`.
2. Fill every section from the gathered evidence; drop sections that genuinely do not apply.
3. Save the draft to `findings/<program>/<asset>/report-<slug>.md`.
4. Present the draft to the operator for review and HackerOne submission. Remind them this
   is the only authorized disclosure channel.

## Output
A complete Markdown report following the template, plus a one-line summary:
```
REPORT DRAFTED — <title> | severity <CVSS score/rating> | asset <target>
Saved: findings/<program>/<asset>/report-<slug>.md  (operator to submit via HackerOne)
```
