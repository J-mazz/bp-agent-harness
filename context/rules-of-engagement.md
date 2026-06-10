# Rules of Engagement (RoE)

These rules are enforced by every skill in this harness. They mirror, and never relax,
the policy of the specific HackerOne program being tested. Where a program is stricter
than this document, **the program wins**.

## Authorization

- Test **only** assets listed as in-scope in `programs/<program>/scope.yaml`, which must be
  copied verbatim from the program's official HackerOne scope.
- Confirm enrollment in the program before the first request of a session.
- Out-of-scope assets are off-limits even when reachable, tempting, or "obviously related."
- When scope is ambiguous, treat it as **out of scope** and ask the operator.

## Allowed activity (non-destructive)

- Passive DNS/WHOIS, certificate transparency lookups.
- A small number of read-only HTTP requests (GET/HEAD) to in-scope hosts.
- Observing response headers, status codes, TLS handshakes, and publicly served files.
- Detecting misconfigurations by observation (e.g., a directory listing renders, a CORS
  header reflects an arbitrary origin) — using a single benign request per check.

## Prohibited activity

- Denial of service, load/stress testing, amplification, or anything degrading availability.
- Brute-force / password spraying / high-volume credential or token guessing.
- Active exploitation: writing, modifying, deleting, or exfiltrating data; uploading shells;
  achieving code execution; establishing persistence; lateral movement.
- Automated mass scanning or aggressive fuzzing that ignores rate limits.
- Testing third-party services, shared SaaS, or other tenants.
- Retrieving or storing real user data / PII. Prove exposure with the minimum evidence,
  then stop.
- Social engineering, phishing, malware, or physical intrusion.

## Rate & courtesy limits

- Default: **serial requests with a delay between them** (≥ 1–2s); never parallel floods.
- Honor any program-specified request caps and identifying `User-Agent`.
- Back off and notify the operator at the first sign of target instability or rate limiting.

## Evidence handling

- Store evidence only under `findings/<program>/` (git-ignored).
- Redact secrets and PII in notes and reports; keep only what proves the issue.
- Never commit, publish, or share target data. Disclose findings solely via HackerOne.

## Escalation

- If a check would cross from observation into intrusive testing, **pause and ask**.
- If you find something high-impact, stop further probing of that issue and write it up;
  do not "see how far it goes."
