import { readFileSync } from 'node:fs';

const lock = JSON.parse(readFileSync('frontend/package-lock.json', 'utf8'));
const runtimeLicenses = new Set(['Apache-2.0', 'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD']);
const developmentLicenses = new Set([...runtimeLicenses, 'MPL-2.0', 'BlueOak-1.0.0']);
const inventory = [];
for (const [path, dependency] of Object.entries(lock.packages)) {
  const allowed = dependency.dev ? developmentLicenses : runtimeLicenses;
  if (!allowed.has(dependency.license)) {
    throw new Error(`${path || lock.name}: review license metadata before accepting this dependency`);
  }
  inventory.push({
    path: path || lock.name,
    version: dependency.version,
    license: dependency.license,
    scope: dependency.dev ? 'development' : 'runtime',
  });
}
console.log(JSON.stringify({
  notice: 'Dependency metadata inventory; redistribution review is required before release.',
  packages: inventory,
}, null, 2));
