#!/usr/bin/env node
// Deterministic scope matcher for the bug bounty harness.
// Read-only, no network. Prints ALLOWED/BLOCKED and exits non-zero when blocked.
//
// Usage:
//   node check-scope.mjs --target <host|url|ip> \
//     --in "example.com,*.example.com,203.0.113.0/24" \
//     --out "blog.example.com,*.dev.example.com"
//
// Semantics:
//   - out patterns ALWAYS win over in patterns.
//   - apex "example.com" matches only the exact host.
//   - "*.example.com" matches any subdomain (a.example.com, a.b.example.com) but NOT the apex.
//   - IPv4 exact and CIDR (e.g. 203.0.113.0/24) are supported for IP targets.

function arg(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : "";
}

function normalizeTarget(raw) {
  let t = String(raw || "").trim().toLowerCase();
  if (!t) return "";
  // strip scheme
  t = t.replace(/^[a-z]+:\/\//, "");
  // strip path/query/fragment
  t = t.split(/[\/?#]/)[0];
  // strip userinfo
  t = t.split("@").pop();
  // strip port (but not for bare IPv6; we only handle IPv4/hostnames here)
  t = t.replace(/:\d+$/, "");
  // strip trailing dot
  t = t.replace(/\.$/, "");
  return t;
}

function splitList(s) {
  return String(s || "")
    .split(",")
    .map((x) => x.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
}

const isIPv4 = (s) =>
  /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) &&
  s.split(".").every((o) => Number(o) >= 0 && Number(o) <= 255);

function ipToInt(ip) {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function cidrMatch(ip, cidr) {
  const [base, bitsRaw] = cidr.split("/");
  if (!isIPv4(base)) return false;
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

function matchOne(target, pattern) {
  // IP target vs IP/CIDR pattern
  if (isIPv4(target)) {
    if (isIPv4(pattern)) return target === pattern;
    if (pattern.includes("/")) return cidrMatch(target, pattern);
    return false;
  }
  // hostname target
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return target.endsWith(suffix) && target.length > suffix.length;
  }
  return target === pattern;
}

const target = normalizeTarget(arg("--target"));
const inList = splitList(arg("--in"));
const outList = splitList(arg("--out"));

function fail(reason) {
  console.log(`Verdict: BLOCKED`);
  console.log(`Target:  ${target || "(empty)"}`);
  console.log(`Reason:  ${reason}`);
  process.exit(2);
}

if (!target) fail("no target provided");
if (inList.length === 0) fail("no in-scope patterns provided — refusing by default");

const hitOut = outList.find((p) => matchOne(target, p));
if (hitOut) fail(`matches out_of_scope pattern "${hitOut}" (out-of-scope always wins)`);

const hitIn = inList.find((p) => matchOne(target, p));
if (!hitIn) fail("does not match any in_scope pattern");

console.log(`Verdict: ALLOWED`);
console.log(`Target:  ${target}`);
console.log(`Reason:  matches in_scope pattern "${hitIn}"`);
process.exit(0);
