import { readFileSync } from 'node:fs';
import exception from './frontend-audit-exception.json' with { type: 'json' };

const advisoryURL = `https://github.com/advisories/${exception.advisory}`;
const severities = ['info', 'low', 'moderate', 'high', 'critical'];
const blocks = (severity) => severities.indexOf(severity) >= severities.indexOf('moderate');

// npm reports transitive effects as names in via, with advisory objects only
// at the roots. An unknown, cyclic, or unrelated cause cannot be waived.
function exceptedFindings(findings, lock, name, chain = new Set()) {
  const item = findings[name];
  if (!Object.hasOwn(findings, name) || chain.has(name) || !item.nodes.every((path) => lock.packages[path]?.dev === true)) {
    return false;
  }
  const trace = new Set([...chain, name]);
  return item.via.every((cause) => {
    if (typeof cause === 'string') {
      return exceptedFindings(findings, lock, cause, trace);
    }
    return name === exception.package && cause?.name === exception.package &&
      cause.dependency === exception.package && cause.url === advisoryURL &&
      cause.range === exception.advisoryRange && cause.severity === 'high' &&
      item.nodes.length === 1 && item.nodes[0] === `node_modules/${exception.package}` &&
      lock.packages[item.nodes[0]].version === exception.version;
  });
}

export function needsException(report, status, lock, now = Date.now()) {
  const findings = report?.vulnerabilities;
  const counts = report?.metadata?.vulnerabilities;
  if (report?.error || report?.auditReportVersion !== 2 || !findings ||
      typeof findings !== 'object' || Array.isArray(findings) || !counts || ![0, 1].includes(status)) {
    throw new Error('npm audit did not produce a complete result');
  }
  const entries = Object.entries(findings);
  for (const [name, item] of entries) {
    if (item?.name !== name || !severities.includes(item.severity) ||
        !Array.isArray(item.via) || item.via.length === 0 ||
        !Array.isArray(item.nodes) || item.nodes.length === 0 ||
        item.nodes.some((path) => typeof path !== 'string')) {
      throw new Error('npm audit returned an unrecognized finding');
    }
    for (const cause of item.via) {
      const severity = typeof cause === 'string'
        ? (Object.hasOwn(findings, cause) ? findings[cause]?.severity : undefined)
        : (typeof cause?.url === 'string' && cause.url.length > 0 ? cause.severity : undefined);
      if (!severities.includes(severity) || severities.indexOf(severity) > severities.indexOf(item.severity)) {
        throw new Error('npm audit returned an unrecognized or inconsistent cause');
      }
    }
  }
  const blocking = entries.filter(([, item]) => blocks(item.severity));
  if (counts.total !== entries.length || severities.some((severity) =>
    counts[severity] !== entries.filter(([, item]) => item.severity === severity).length) ||
    status !== Number(blocking.length > 0)) {
    throw new Error('npm audit status and findings disagree');
  }
  if (status === 0) return false;
  if (now >= Date.parse(exception.expiresAt)) {
    throw new Error(`Frontend audit failed. The exception for ${exception.advisory} expired`);
  }
  const other = blocking.filter(([name]) => !exceptedFindings(findings, lock, name));
  if (other.length !== 0) {
    throw new Error(`Frontend audit blocked by ${other.map(([name]) => name).join(', ')}`);
  }
  return true;
}

export function verifyNoCorrectedRelease(advisory, registry) {
  const affected = advisory?.vulnerabilities;
  if (advisory?.ghsa_id !== exception.advisory || !Array.isArray(affected) || affected.length !== 1 ||
      affected[0]?.package?.ecosystem !== 'npm' || affected[0].package.name !== exception.package ||
      affected[0].first_patched_version !== null ||
      affected[0].vulnerable_version_range?.replace(/\s/g, '') !== exception.advisoryRange) {
    throw new Error('Upstream advisory changed or lists a corrected version. Review is required');
  }
  if (registry?.name !== exception.package || !registry.versions || !registry.time ||
      !Object.hasOwn(registry.versions, exception.version)) {
    throw new Error('npm registry did not return the reviewed package version');
  }
  const ceiling = exception.version.split('.').map(Number);
  for (const version of Object.keys(registry.versions)) {
    const parsed = /^(\d+)\.(\d+)\.(\d+)(?:[-+][\w.+-]+)?$/.exec(version);
    const published = Date.parse(registry.time[version]);
    if (!parsed || !Number.isFinite(published)) throw new Error('npm registry returned incomplete release metadata');
    const parts = parsed.slice(1).map(Number);
    const firstDifference = parts.findIndex((part, index) => part !== ceiling[index]);
    if (published >= Date.parse(exception.approvedOn) ||
        (firstDifference !== -1 && parts[firstDifference] > ceiling[firstDifference])) {
      throw new Error('A newer picomatch version is available. Review the exception before proceeding');
    }
  }
}

async function fetchJSON(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`Upstream verification failed with HTTP ${response.status}`);
  return response.json();
}

if (import.meta.main) {
  const [path, code] = process.argv.slice(2);
  try {
    const report = JSON.parse(readFileSync(path, 'utf8'));
    const lock = JSON.parse(readFileSync(new URL('../frontend/package-lock.json', import.meta.url), 'utf8'));
    if (needsException(report, Number(code), lock)) {
      const [advisory, registry] = await Promise.all([
        fetchJSON(`https://api.github.com/advisories/${exception.advisory}`),
        fetchJSON('https://registry.npmjs.org/picomatch'),
      ]);
      verifyNoCorrectedRelease(advisory, registry);
      console.warn(`Temporary development-only exception applied for ${exception.advisory} until ${exception.expiresAt} or a corrected release`);
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
