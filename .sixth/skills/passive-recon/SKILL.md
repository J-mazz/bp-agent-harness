---
name: passive-recon
description: Perform passive, read-only reconnaissance on an authorized in-scope asset — DNS records, certificate-transparency subdomains, WHOIS basics, and a lightweight tech fingerprint from a single homepage request. Use when the operator wants to map an in-scope target or enumerate subdomains without active/aggressive scanning. Always gate every host through scope-authorization-guard first; never brute-force.
---

# Passive Recon

Map an in-scope asset using mostly passive sources and at most one or two benign HTTP
requests. The goal is a clean inventory the operator can approve before any auditing.

**Pre-req:** the target passed `scope-authorization-guard`. Re-gate every newly discovered
host before touching it. Honor the program's `User-Agent` and serial/rate limits.

## Steps

### 1. DNS records (passive)
```bash
for t in A AAAA CNAME MX TXT NS SOA; do echo "== $t =="; dig +short "$TARGET" "$t"; done
```
Note hosting providers, mail, SPF/DMARC TXT, and CNAMEs (possible take-over leads — only
report, never claim/register anything).

### 2. Certificate-transparency subdomains (passive)
crt.sh reads public CT logs — it does not touch the target.
```bash
curl -s "https://crt.sh/?q=%25.${APEX}&output=json" \
  | python3 -c 'import sys,json;[print(n) for r in json.load(sys.stdin) for n in r["name_value"].split("\n")]' \
  | sed 's/^\*\.//' | sort -u
```
**Filter the results to in-scope only.** Run each candidate through
`scope-authorization-guard`; discard anything that is out-of-scope.

### 3. WHOIS / ownership sanity (passive)
```bash
whois "$APEX" | sed -n '1,40p'
```
Use only to sanity-check ownership; never use registrant data to contact anyone.

### 4. Lightweight tech fingerprint (one request)
A single HEAD/GET to the homepage to read server/framework hints:
```bash
curl -sSI -A "$USER_AGENT" "https://$TARGET/" 
```
Look at `Server`, `X-Powered-By`, `Via`, cookie names, and obvious framework markers. Do
**not** crawl, spider, or fetch many pages here.

## Do NOT
- Brute-force subdomains/DNS, run mass wordlist scans, or port-scan broadly.
- Fetch large numbers of URLs or follow every link.
- Touch any host that has not passed the scope guard.

## Output
```
RECON — <target>
DNS: <key records>
Subdomains (in-scope only): <list>
Tech hints: <server/framework/cookies>
New in-scope hosts to audit (operator approval needed): <list>
```
Write the inventory to `findings/<program>/<asset>/recon.md`.
