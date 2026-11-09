import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';

// Include prospective source in a new checkout as well as tracked files in CI.
const paths = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
  encoding: 'utf8',
}).split('\0').filter(Boolean);
const allowed = /^(?:\.github|cmd|internal|frontend|scripts)\//;
const rootFiles = new Set([
  '.gitignore', '.gitattributes', '.dockerignore', 'README.md', 'CONTRIBUTING.md',
  'LICENSE', 'NOTICE', 'SECURITY.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md',
  'Makefile', 'go.mod', 'go.sum', 'Dockerfile', 'compose.yaml',
]);
const errors = [];
for (const path of new Set(paths)) {
  if (!allowed.test(path) && !rootFiles.has(path)) errors.push(`${path}: outside reviewed source roots`);
  if (lstatSync(path).isSymbolicLink()) errors.push(`${path}: symlinks require an explicit packaging review`);
  if (/\.(?:go|[cm]?[jt]sx?|json|ya?ml|md|css|html)$/.test(path)) {
    const content = readFileSync(path, 'utf8');
    if (/\r/.test(content)) errors.push(`${path}: use LF line endings`);
    if (/^(?:<{7}|={7}|>{7})(?: |$)/m.test(content)) errors.push(`${path}: unresolved merge marker`);
  }
  if (path.startsWith('.github/workflows/') && /\.ya?ml$/.test(path)) {
    const workflow = readFileSync(path, 'utf8');
    for (const match of workflow.matchAll(/uses:\s+([^\s#]+)/g)) {
      if (!/^[\w.-]+\/[\w./-]+@[a-f0-9]{40}$/.test(match[1])) {
        errors.push(`${path}: action must use a full commit SHA: ${match[1]}`);
      }
    }
    if (/pull_request_target|write-all|secrets: inherit/.test(workflow)) {
      errors.push(`${path}: unsafe bootstrap workflow permission or trigger`);
    }
  }
}
if (errors.length) {
  process.stderr.write(`${errors.join('\n')}\n`);
  process.exitCode = 1;
} else {
  console.log(`Repository policy passed (${new Set(paths).size} source files).`);
}
