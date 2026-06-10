---
name: security-headers-audit
description: Audit HTTP security response headers and cookie flags for an authorized in-scope URL using a couple of read-only requests. Use when the operator wants to check HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, or cookie Secure/HttpOnly/SameSite flags. Gate the target through scope-authorization-guard first; observation only.
---

# Security Headers & Cookie Audit

Evaluate the defensive HTTP headers and cookie attributes of one in-scope URL. This is a
read-only observation — a single HEAD plus, if needed, one GET.

**Pre-req:** target passed `scope-authorization-guard`. Use the program `User-Agent`; one
request at a time.

## Collect
```bash
curl -sSIL -A "$USER_AGENT" "https://$TARGET/" -o /dev/null -D -
# If a GET is needed to observe Set-Cookie on a real response:
curl -sS  -A "$USER_AGENT" "https://$TARGET/" -o /dev/null -D - -c /dev/null
```

## Review checklist
- **HSTS** — `Strict-Transport-Security`: present, `max-age` ≥ 6 months, `includeSubDomains`,
  ideally `preload`.
- **CSP** — `Content-Security-Policy`: present, not just `Report-Only`; flag `unsafe-inline`,
  `unsafe-eval`, wildcard `*`, or missing `frame-ancestors`/`object-src`.
- **Framing** — `X-Frame-Options` or CSP `frame-ancestors` to prevent clickjacking.
- **MIME** — `X-Content-Type-Options: nosniff`.
- **Referrer-Policy** — present and not leaking full URLs cross-origin.
- **Permissions-Policy** — restricts powerful features.
- **Cross-origin isolation** — `Cross-Origin-Opener-Policy`, `-Embedder-Policy`, `-Resource-Policy`.
- **Info leakage** — verbose `Server`, `X-Powered-By`, internal IPs/hostnames in headers.
- **Cookies** (`Set-Cookie`) — `Secure`, `HttpOnly`, `SameSite` (Lax/Strict), reasonable
  scope/expiry. Session cookies missing `HttpOnly`/`Secure` are the common finding.

## Severity guidance
Most header gaps are **Low / informational** on their own. Rate impact in context (e.g.,
missing framing on a sensitive authenticated action is higher than on a static page). Use
CVSS 3.1 and the program's severity rules; rate conservatively.

## Do NOT
- Send authenticated requests unless a test account is permitted by policy.
- Hammer the endpoint; one or two requests is enough.

## Output
Write to `findings/<program>/<asset>/headers.md`:
```
HEADERS — <target>
Present: <good headers>
Missing/weak: <header: why it matters>
Cookies: <name: flags, gaps>
Candidate finding(s): <header/cookie issue + provisional severity>
```
