// scripts/check-architecture.mjs passes on this tree and fails on each kind of boundary break (MF7).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '..');
const check = dir => spawnSync(process.execPath, [join(ROOT, 'scripts', 'check-architecture.mjs'), dir], { encoding: 'utf8' });
function mutated(file, edit) {
  const dir = mkdtempSync(join(tmpdir(), 'arch-'));
  cpSync(ROOT, dir, { recursive: true, filter: source => source !== join(ROOT, '.git') && !source.startsWith(`${join(ROOT, '.git')}/`) });
  if (file !== null) writeFileSync(join(dir, file), edit(existsSync(join(dir, file)) ? readFileSync(join(dir, file), 'utf8') : ''));
  return dir;
}
const swap = (from, to) => text => { assert.ok(text.includes(from), `fixture text missing: ${from}`); return text.replace(from, to); };

test('the check passes on this tree', () => {
  const result = check(ROOT);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /0 findings/u);
});

const breaks = [
  ['A', 'a package import in the client', 'app.js', text => `import pad from 'left-pad';\n${text}`],
  ['A', 'a package manifest', 'package.json', () => '{"dependencies":{"left-pad":"1.0.0"}}'],
  ['A', 'dynamic code in the verifier', 'verifier/run.mjs', text => `${text}\nawait import(process.env.X);\n`],
  ['A', 'a child process in the verifier', 'verifier/run.mjs', text => `import { execSync } from 'node:child_process';\n${text}`],
  ['scope', 'an unchecked code file', 'extra.js', () => 'console.log(1)'],
  ['B', 'an action step', '.github/workflows/verifier.yml', swap('    steps:\n', '    steps:\n      - uses: actions/checkout@v4\n')],
  ['B', 'a self-hosted runner', '.github/workflows/verifier.yml', swap('runs-on: ubuntu-24.04', 'runs-on: self-hosted')],
  ['B', 'an install step', '.github/workflows/verifier.yml', swap('run: node verifier/run.mjs', 'run: npm ci && node verifier/run.mjs')],
  ['B', 'fetching the PR head', '.github/workflows/verifier.yml', swap('BASE_SHA: ${{ github.sha }}', 'BASE_SHA: ${{ github.event.pull_request.head.sha }}')],
  ['B', 'a second trigger', '.github/workflows/verifier.yml', swap('on:\n', 'on:\n  pull_request:\n')],
  ['C', 'a write to main', 'verifier/run.mjs', text => `${text}\nawait api('PUT', \`contents/x\`, { branch: MAIN });\n`],
  ['C', 'a delete', 'verifier/run.mjs', text => `${text}\nawait api('DELETE', \`git/refs/heads/\${LEDGER}\`);\n`],
  ['D', 'reading a whole body in the client', 'app.js', text => `${text}\nconst whole = await (await fetch(location.href)).text();\n`],
  ['D', 'an unchecked authority file size', 'verifier/run.mjs', swap("check(file !== null && file.size <= LIMITS.maxBody, 'installation.json missing or too large');", "check(file !== null, 'installation.json missing');")],
  ['D', 'a third-party script', 'index.html', swap('<script type="module" src="app.js"></script>', '<script src="https://cdn.example/x.js"></script><script type="module" src="app.js"></script>')],
  ['D', 'an unsafe CSP', 'index.html', swap("script-src 'self';", "script-src 'self' 'unsafe-inline';")],
];
for (const [rule, what, file, edit] of breaks) {
  test(`the check fails on ${what} [${rule}]`, () => {
    const dir = mutated(file, edit);
    try {
      const result = check(dir);
      assert.equal(result.status, 1, result.stdout);
      assert.match(result.stdout, new RegExp(`\\[${rule}\\]`, 'u'));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
