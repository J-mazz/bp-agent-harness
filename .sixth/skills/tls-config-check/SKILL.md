---
name: tls-config-check
description: Check TLS/SSL configuration hygiene for an authorized in-scope host using a single handshake — supported protocol versions, cipher strength, forward secrecy, and certificate validity/expiry/hostname match. Use when the operator wants to review SSL/TLS posture, find weak/legacy protocols (SSLv3, TLS 1.0/1.1), or certificate problems. Gate the host through scope-authorization-guard first; one connection, non-destructive.
---

# TLS / SSL Configuration Check

Assess the transport security of one in-scope host. A TLS handshake is read-only and
non-destructive; keep connections to a minimum.

**Pre-req:** host passed `scope-authorization-guard`. Default port 443 unless the program
lists another in-scope service.

## Quick inspection (always available)
```bash
# Certificate, chain, negotiated protocol/cipher:
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# Probe individual protocol versions (expect failure on legacy = good):
for p in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo -n "$p: "; echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" -$p \
    2>/dev/null | grep -q "BEGIN CERTIFICATE" && echo "ENABLED" || echo "disabled/failed"
done
```

## Deeper enumeration (use only if installed; still one host)
Prefer a passive, well-behaved tool if present — do not install scanners just to run them:
```bash
command -v testssl.sh >/dev/null && testssl.sh --quiet --color 0 "$TARGET:443"
command -v sslscan   >/dev/null && sslscan "$TARGET:443"
command -v nmap      >/dev/null && nmap --script ssl-enum-ciphers -p 443 "$TARGET"
```

## Review checklist
- **Protocols** — SSLv2/SSLv3/TLS1.0/TLS1.1 enabled = finding; prefer TLS1.2+ and TLS1.3.
- **Ciphers** — flag RC4, 3DES, NULL, EXPORT, anon; prefer AEAD (GCM/ChaCha20).
- **Forward secrecy** — ECDHE/DHE key exchange present.
- **Certificate** — not expired/near-expiry, hostname matches SAN, trusted chain complete,
  no weak signature (SHA-1) or small RSA keys (<2048).
- **HSTS alignment** — strong TLS but missing HSTS is worth noting (see headers skill).

## Severity guidance
Legacy protocol/cipher support and cert hostname/expiry issues are typically **Low–Medium**
unless the program states otherwise. Rate with CVSS 3.1, conservatively.

## Do NOT
- Run repeated/looping handshakes or load-style probing.
- Test hosts/ports not in scope.

## Output
Write to `findings/<program>/<asset>/tls.md`:
```
TLS — <target>:443
Protocols: <enabled/disabled>
Ciphers: <weak ones, if any>
Certificate: <subject/issuer/expiry/SAN match>
Candidate finding(s): <issue + provisional severity>
```
