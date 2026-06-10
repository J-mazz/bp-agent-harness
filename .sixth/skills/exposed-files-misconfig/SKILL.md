---
name: exposed-files-misconfig
description: Safely check an authorized in-scope host for common misconfigurations and accidental exposures — robots.txt, security.txt, exposed .git/.env/backup files, directory listing, permissive CORS reflection, and verbose error pages — using one benign GET per check. Use when the operator wants a non-destructive misconfiguration pass. Gate the host through scope-authorization-guard first; never download user data or escalate.
---

# Exposed Files & Misconfiguration Check

Look for low-hanging, observable misconfigurations with **one benign request per check**.
This is detection by observation, not exploitation.

**Pre-req:** host passed `scope-authorization-guard`. Use the program `User-Agent`, keep
requests serial with a short delay, and stop at the first sign of trouble.

## Discovery files (benign)
```bash
for path in robots.txt sitemap.xml .well-known/security.txt humans.txt; do
  echo "== /$path =="; curl -sS -A "$USER_AGENT" -o /dev/null -w "%{http_code}\n" "https://$TARGET/$path"
done
```
Read `robots.txt`/`security.txt` for disclosed paths and the program's preferred contact.

## Accidental exposure (single GET, do not crawl)
Check whether sensitive artifacts are *served*; confirm with the response, then stop.
```bash
for path in .git/HEAD .git/config .env .env.bak config.php.bak .DS_Store backup.zip; do
  code=$(curl -sS -A "$USER_AGENT" -o /tmp/probe.out -w "%{http_code}" "https://$TARGET/$path")
  echo "/$path -> $code"; sleep 1
done
```
- A `200` with real content (e.g., `.git/HEAD` returns `ref: refs/heads/...`, or `.env`
  shows `KEY=VALUE`) is a likely finding.
- **Do not** dump the whole repo, download databases, or read beyond the few bytes needed to
  prove exposure. Capture a minimal, redacted snippet only.

## Directory listing
```bash
for path in / uploads/ images/ backup/ .git/; do
  curl -sS -A "$USER_AGENT" "https://$TARGET/$path" | grep -qi "Index of /" && echo "LISTING: /$path"
done
```

## CORS reflection (one request)
Check whether an arbitrary origin is reflected with credentials allowed:
```bash
curl -sSI -A "$USER_AGENT" -H "Origin: https://evil.example" "https://$TARGET/" \
  | grep -i "access-control-allow-"
```
`Access-Control-Allow-Origin: https://evil.example` together with
`Access-Control-Allow-Credentials: true` is a misconfiguration worth reporting.

## Verbose errors / debug
Request a clearly invalid path and observe whether stack traces, framework debug pages, or
internal paths leak:
```bash
curl -sS -A "$USER_AGENT" "https://$TARGET/this-should-not-exist-$(date +%s)" | head -c 600
```

## Do NOT
- Brute-force directories/files with wordlists, or fuzz parameters.
- Retrieve, store, or exfiltrate real user data / PII / secrets beyond minimal proof.
- Use any exposure to gain access, write data, or escalate. Report and stop.

## Output
Write to `findings/<program>/<asset>/misconfig.md`:
```
MISCONFIG — <target>
Discovery files: <robots/security.txt notes>
Exposures: <path -> status, minimal redacted evidence>
Directory listing: <paths>
CORS: <reflected? credentials?>
Errors: <verbose? what leaked>
Candidate finding(s): <issue + provisional severity>
```
