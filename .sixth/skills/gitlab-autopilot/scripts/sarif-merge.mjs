#!/usr/bin/env node
// sarif-merge.mjs — merge semgrep / brakeman / gitleaks JSON into one SARIF 2.1.0
// document with one run[] per tool. Read-only, no network.
//
// Usage: node sarif-merge.mjs <sast_dir> [out.sarif]
//
// Field maps verified against the harness' own outputs:
//   semgrep : .results[] {check_id, path(/src/..), start/end{line,col}, extra{severity,message}}
//   brakeman: .warnings[] {check_name, warning_type, file(rel), line, confidence, message, link, fingerprint}
//   gitleaks: [ {RuleID, Description, File(/src/..), StartLine, EndLine, Tags} ]  (secrets redacted upstream)
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const sastDir = process.argv[2];
if (!sastDir) { console.error('usage: sarif-merge.mjs <sast_dir> [out.sarif]'); process.exit(1); }
const outPath = process.argv[3] || join(sastDir, 'findings.sarif');

const stripSrc = (p) => String(p || '').replace(/^\/src\//, '').replace(/^\//, '');
const readJson = (f) => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return null; } };

// rule collector: dedups rules per run and returns a stable ruleIndex
function collector() {
  const idx = new Map(); const list = [];
  return {
    ref(id, make) { if (!idx.has(id)) { idx.set(id, list.length); list.push(make()); } return idx.get(id); },
    get list() { return list; },
  };
}
const loc = (uri, sl, sc, el, ec) => ([{
  physicalLocation: {
    artifactLocation: { uri },
    region: { startLine: sl || 1, ...(sc ? { startColumn: sc } : {}), endLine: el || sl || 1, ...(ec ? { endColumn: ec } : {}) },
  },
}]);

function semgrepRun() {
  const j = readJson(join(sastDir, 'semgrep.json'));
  if (!j || !Array.isArray(j.results)) return null;
  const lvl = (s) => ({ ERROR: 'error', WARNING: 'warning', INFO: 'note' }[String(s || '').toUpperCase()] || 'warning');
  const rc = collector();
  const results = j.results.map((r) => {
    const id = r.check_id || 'semgrep.unknown';
    const ri = rc.ref(id, () => ({ id, name: id.split('.').pop(), shortDescription: { text: (r.extra?.message || id).slice(0, 300) } }));
    return {
      ruleId: id, ruleIndex: ri, level: lvl(r.extra?.severity),
      message: { text: r.extra?.message || id },
      locations: loc(stripSrc(r.path), r.start?.line, r.start?.col, r.end?.line, r.end?.col),
      properties: { severity: r.extra?.severity || null },
    };
  });
  return { tool: { driver: { name: 'semgrep', informationUri: 'https://semgrep.dev', version: j.version || null, rules: rc.list } }, results };
}

function brakemanRun() {
  const j = readJson(join(sastDir, 'brakeman.json'));
  if (!j || !Array.isArray(j.warnings)) return null;
  const lvl = (c) => ({ High: 'error', Medium: 'warning', Weak: 'note' }[String(c || '')] || 'warning');
  const rc = collector();
  const results = j.warnings.map((w) => {
    const id = w.check_name || w.warning_type || 'brakeman';
    const ri = rc.ref(id, () => ({ id, name: id, shortDescription: { text: w.warning_type || id }, ...(w.link ? { helpUri: w.link } : {}) }));
    return {
      ruleId: id, ruleIndex: ri, level: lvl(w.confidence),
      message: { text: `${w.warning_type}: ${w.message}` },
      locations: loc(stripSrc(w.file), w.line, null, w.line, null),
      ...(w.fingerprint ? { partialFingerprints: { brakemanFingerprint: w.fingerprint } } : {}),
      properties: { confidence: w.confidence || null, ...(w.link ? { link: w.link } : {}) },
    };
  });
  return { tool: { driver: { name: 'brakeman', informationUri: 'https://brakemanscanner.org', version: j.scan_info?.brakeman_version || null, rules: rc.list } }, results };
}

function gitleaksRun() {
  const j = readJson(join(sastDir, 'gitleaks.json'));
  if (!Array.isArray(j)) return null;
  const rc = collector();
  const results = j.map((g) => {
    const id = g.RuleID || 'gitleaks';
    const ri = rc.ref(id, () => ({ id, name: id, shortDescription: { text: g.Description || id } }));
    return {
      ruleId: id, ruleIndex: ri, level: 'warning',
      message: { text: g.Description || id }, // secret value intentionally NOT included
      locations: loc(stripSrc(g.File), g.StartLine, null, g.EndLine || g.StartLine, null),
      properties: { tags: g.Tags || [] },
    };
  });
  return { tool: { driver: { name: 'gitleaks', informationUri: 'https://github.com/gitleaks/gitleaks', rules: rc.list } }, results };
}

const runs = [semgrepRun(), brakemanRun(), gitleaksRun()].filter(Boolean);
const sarif = { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs };
writeFileSync(outPath, JSON.stringify(sarif, null, 2));

for (const r of runs) {
  const lv = r.results.reduce((a, x) => (a[x.level] = (a[x.level] || 0) + 1, a), {});
  console.error(`[sarif] ${r.tool.driver.name.padEnd(9)} results=${String(r.results.length).padStart(4)} rules=${String(r.tool.driver.rules.length).padStart(3)}  ${JSON.stringify(lv)}`);
}
console.error(`[sarif] wrote ${outPath} (${runs.length} runs)`);
console.log(outPath);
