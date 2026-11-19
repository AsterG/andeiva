import assert from 'node:assert/strict';
import test from 'node:test';
import { needsException, verifyNoCorrectedRelease } from './check-frontend-audit.mjs';
import exception from './frontend-audit-exception.json' with { type: 'json' };

const during = Date.parse('2026-11-19T00:00:00Z');
const auditFinding = (name, via, severity = 'high') => ({ name, via, severity, nodes: [`node_modules/${name}`] });
const approved = {
  name: 'picomatch', dependency: 'picomatch', severity: 'high',
  url: `https://github.com/advisories/${exception.advisory}`, range: exception.advisoryRange,
};
const different = { ...approved, url: 'https://github.com/advisories/GHSA-1111-2222-3333' };
const fixture = () => ({
  packages: {
    'node_modules/picomatch': { dev: true, version: '4.0.7' },
    'node_modules/vite': { dev: true },
  },
});
function report(...items) {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: items.length };
  for (const item of items) counts[item.severity]++;
  return { auditReportVersion: 2, metadata: { vulnerabilities: counts },
    vulnerabilities: Object.fromEntries(items.map((x) => [x.name, x])) };
}

test('only the exact advisory and its dev-only transitive effects may pass', () => {
  const lock = fixture();
  const permitted = report(auditFinding('vite', ['picomatch']), auditFinding('picomatch', [approved]));
  assert.equal(needsException(permitted, 1, lock, during), true);
  assert.throws(() => needsException(report(auditFinding('picomatch', [approved, different])), 1, lock, during), /blocked/);
  assert.throws(() => needsException(report(auditFinding('vite', ['picomatch', different]), auditFinding('picomatch', [approved])), 1, lock, during), /blocked/);
  assert.throws(() => needsException(report(auditFinding('vite', ['undeclared'])), 1, lock, during), /cause/);
  assert.throws(() => needsException(report(auditFinding('vite', ['vite'])), 1, lock, during), /blocked/);
  lock.packages['node_modules/picomatch'].dev = false;
  assert.throws(() => needsException(permitted, 1, lock, during), /blocked/);
});

test('clean audits keep the moderate threshold and failed audits require complete evidence', () => {
  assert.equal(needsException(report(), 0, fixture(), during), false);
  assert.equal(needsException(report(auditFinding('vite', [{ ...different, severity: 'low' }], 'low')), 0, fixture(), during), false);
  assert.throws(() => needsException({ ...report(), error: { code: 'E503' } }, 1, fixture(), during), /complete/);
  assert.throws(() => needsException(report(auditFinding('vite', [null], 'low'), auditFinding('picomatch', [approved])), 1, fixture(), during), /cause/);
  assert.throws(() => needsException(report(auditFinding('vite', [different], 'low'), auditFinding('picomatch', [approved])), 1, fixture(), during), /cause/);
  assert.throws(() => needsException(report(), 1, fixture(), during), /disagree/);
  assert.throws(() => needsException(report(auditFinding('picomatch', [approved])), 1, fixture(), Date.parse(exception.expiresAt)), /expired/);
});

test('an official correction, changed range, or newer publication ends the exception', () => {
  const affected = { package: { ecosystem: 'npm', name: 'picomatch' }, first_patched_version: null, vulnerable_version_range: '<= 4.0.7' };
  const advisory = { ghsa_id: exception.advisory, vulnerabilities: [affected] };
  const registry = { name: 'picomatch', versions: { '2.3.2': {}, '4.0.7': {} }, time: { '2.3.2': '2026-03-23', '4.0.7': '2026-08-24' } };
  verifyNoCorrectedRelease(advisory, registry);
  registry.versions['2.3.3'] = {};
  registry.time['2.3.3'] = '2026-11-19';
  assert.throws(() => verifyNoCorrectedRelease(advisory, registry), /newer/);
  delete registry.versions['2.3.3'];
  assert.throws(() => verifyNoCorrectedRelease(advisory, { ...registry, versions: { '2.3.2': {} } }), /reviewed package/);
  affected.first_patched_version = { identifier: '2.3.3' };
  assert.throws(() => verifyNoCorrectedRelease(advisory, registry), /corrected/);
});
