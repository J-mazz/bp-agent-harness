# Recon & Audit Methodology (non-destructive)

A repeatable, low-noise checklist the `bug-bounty-orchestrator` follows. Every step is
read-only/observational and gated by `scope-authorization-guard`. Work one in-scope asset
at a time; record evidence under `findings/<program>/<asset>/`.

## 0. Pre-flight (always)
- [ ] Program selected; `programs/<program>/scope.yaml` present and reviewed.
- [ ] Target host/URL confirmed in scope via `scope-authorization-guard`.
- [ ] Program policy noted: rate limits, prohibited tests, required identification.

## 1. Passive recon  (`passive-recon`)
- [ ] DNS records (A/AAAA/CNAME/MX/TXT/NS) for the in-scope apex & host.
- [ ] Certificate-transparency subdomains (crt.sh) — **filter to in-scope only**.
- [ ] WHOIS / registration basics (ownership sanity check, not for contacting).
- [ ] Lightweight tech fingerprint from one homepage GET (server, framework, headers).
- [ ] Record candidate in-scope hosts for the operator to approve before active checks.

## 2. Security headers & cookies  (`security-headers-audit`)
- [ ] HSTS, CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy,
      Permissions-Policy, COOP/COEP/CORP.
- [ ] Cookie flags: `Secure`, `HttpOnly`, `SameSite`; scope/expiry sanity.
- [ ] Cache-control on authenticated/sensitive responses (if a test account is in policy).

## 3. TLS/SSL hygiene  (`tls-config-check`)
- [ ] Supported protocols (flag SSLv3/TLS1.0/1.1), cipher strength, forward secrecy.
- [ ] Certificate validity, chain, hostname match, expiry, weak signature.
- [ ] HSTS alignment with TLS posture.

## 4. Exposed files & misconfig  (`exposed-files-misconfig`)
- [ ] `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`.
- [ ] Accidental exposure: `/.git/HEAD`, `/.env`, `/.DS_Store`, backup files (single GET each).
- [ ] Directory listing enabled on common paths.
- [ ] CORS: does an arbitrary `Origin` get reflected with credentials allowed? (one request)
- [ ] Verbose errors / stack traces / debug endpoints visible.

## 5. Triage with the operator
- [ ] Classify each observation: informational vs. potential finding.
- [ ] For potential findings, confirm impact with the **minimum** additional evidence.
- [ ] The operator decides what is reportable. No deep-diving exploits.

## 6. Report  (`hackerone-report`)
- [ ] Draft a HackerOne-ready report per confirmed, in-scope issue.
- [ ] Include CVSS, clear repro steps, impact, remediation, and redacted evidence.

### Severity reference
Use CVSS 3.1 and the program's own severity guidance. When in doubt, rate conservatively
and let the program's triage adjust.
