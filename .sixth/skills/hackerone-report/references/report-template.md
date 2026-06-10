# [Title] — concise, specific (e.g., "Session cookie missing HttpOnly on app.example.com")

> Draft for operator review. Submit only via the program's HackerOne page. Redact all
> secrets and PII before sharing.

## Summary
One or two sentences: what the issue is and why it matters, in plain language.

## Affected asset
- **Target:** `https://app.example.com/...` (confirmed in-scope for program `<name>`)
- **Component / endpoint:** `...`
- **Weakness:** `CWE-XXX: <name>`

## Severity
- **CVSS 3.1:** `<base score>` (`<rating>`)
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Rationale:** brief justification, scoped to demonstrated impact.

## Steps to reproduce
1. ...
2. ...
3. Observe: `<exact observable result>`

Include the minimal request/response needed (redacted):
```http
GET /path HTTP/1.1
Host: app.example.com
User-Agent: <program-required UA>

HTTP/1.1 200 OK
<relevant headers / minimal body proving the issue>
```

## Impact
What a malicious actor could realistically do, limited to what was demonstrated
non-destructively. No speculation beyond the evidence.

## Evidence
- `findings/<program>/<asset>/...` (redacted snippet/screenshot reference)
- Keep only what proves the issue; remove tokens, cookies, and PII.

## Remediation
- Concrete, actionable fix (e.g., "Set `HttpOnly`, `Secure`, and `SameSite=Lax` on the
  session cookie"). Link to the relevant standard/best practice where useful.

## References
- OWASP / CWE / vendor docs as applicable.

---
**Disclosure:** Reported privately via HackerOne to `<program>`. Not disclosed elsewhere.
