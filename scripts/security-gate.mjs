#!/usr/bin/env node
/**
 * Security gate: fails when audit findings lack a valid, non-expired exception.
 *
 * Usage: node scripts/security-gate.mjs audit.json security/vuln-policy.json
 */
import fs from "node:fs";

const [auditPath, policyPath] = process.argv.slice(2);
if (!auditPath || !policyPath) {
  console.error("Usage: node scripts/security-gate.mjs <audit.json> <vuln-policy.json>");
  process.exit(2);
}

const loadJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const audit = loadJson(auditPath);
const policy = loadJson(policyPath);
const exceptions = policy.exceptions ?? [];

const today = new Date();
today.setHours(0, 0, 0, 0);

const isExpired = (dateStr) => {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return true;
  d.setHours(0, 0, 0, 0);
  return d < today;
};

// Normalize pnpm audit JSON (fallback to npm advisories shape)
function normalizeFindings(a) {
  const findings = [];

  if (Array.isArray(a.vulnerabilities)) {
    for (const v of a.vulnerabilities) {
      findings.push({
        id: v.id ?? v.name ?? v.title ?? `${v.package}@${v.version}`,
        package: v.package ?? v.name,
        severity: (v.severity ?? v.severityLevel ?? "").toLowerCase(),
        path: v.path ?? (Array.isArray(v.via) ? v.via.join(" > ") : "") ?? "",
      });
    }
  } else if (a.advisories) {
    for (const key of Object.keys(a.advisories)) {
      const adv = a.advisories[key];
      findings.push({
        id: adv.id ?? key,
        package: adv.module_name,
        severity: (adv.severity ?? "").toLowerCase(),
        path: adv.findings?.[0]?.paths?.[0] ?? "",
      });
    }
  }

  return findings;
}

const findings = normalizeFindings(audit);

const normSeverity = (s) => {
  const val = (s ?? "").toLowerCase();
  return val === "medium" ? "moderate" : val;
};

function matchException(f) {
  return exceptions.find((ex) => {
    const severityMatch = normSeverity(ex.severity) === normSeverity(f.severity);
    const idMatch = ex.id ? ex.id === f.id : true;
    const pkgMatch = ex.package ? ex.package === f.package : true;
    return severityMatch && idMatch && pkgMatch;
  });
}

const blocking = [];
const matched = [];
const expired = [];

for (const f of findings) {
  const sev = normSeverity(f.severity);
  const ex = matchException(f);

  if (ex && isExpired(ex.expires_on)) {
    expired.push({ finding: f, exception: ex });
  }

  const hasValidEx =
    !!ex &&
    !isExpired(ex.expires_on) &&
    !!ex.reason &&
    normSeverity(ex.severity) === sev;

  if (hasValidEx) matched.push({ finding: f, exception: ex });

  const isHigh = sev === "high" || sev === "critical";
  const isMedium = sev === "moderate" || sev === "medium";

  if (isHigh) {
    blocking.push({ finding: f, exception: ex, reason: "high/critical vulnerability" });
  } else if (isMedium && !hasValidEx) {
    blocking.push({ finding: f, exception: ex, reason: "missing or invalid exception" });
  }
}

const fmt = (f) =>
  `${f.severity || "unknown"} | ${f.package || "?"} | id=${f.id || "?"} | path=${f.path || "-"}`;

console.log("== Security Gate ==");
console.log(`Findings: ${findings.length}`);
console.log(`Blocking: ${blocking.length}`);
console.log(`Matched exceptions: ${matched.length}`);
console.log(`Expired exceptions: ${expired.length}`);

if (blocking.length) {
  console.log("\nBlocking findings:");
  for (const b of blocking) console.log(` - ${fmt(b.finding)} (${b.reason})`);
}

if (expired.length) {
  console.log("\nExpired exceptions:");
  for (const e of expired) console.log(` - ${fmt(e.finding)} | exception expires_on=${e.exception.expires_on}`);
}

if (!exceptions.length) console.log("\nNo exceptions configured.");

const ok = blocking.length === 0 && expired.length === 0;
console.log(`\nResult: ${ok ? "PASS" : "FAIL"}`);
process.exit(ok ? 0 : 1);
