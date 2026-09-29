// This repository's own boundary check (charter item 7), run as: node scripts/check-architecture.mjs [root]
// Scope: the shipped client (index.html, app.js, core.mjs), the verifier (verifier/*.mjs) and its workflow.
// tests/ and scripts/ are not shipped to the page or the runner and are out of scope. It enforces:
//   A. no executable dependency: no package manifest/lockfile/node_modules; imports are local files only
//      (the verifier may also use node: built-ins); no dynamic import, require, eval, Function, vm or
//      child processes in shipped code;
//   B. no fork code executed by the workflow: GitHub-hosted runner, no `uses:` actions, no install steps,
//      only the trusted base commit is fetched and only `node verifier/run.mjs` runs; the PR head is used
//      as data (HEAD_SHA) only; secrets appear only in the verify step;
//   C. the verifier writes only its ledger branch, its own comment, and the submission's close;
//   D. bounded inputs: the client reads untrusted feeds only through fetchBounded; the verifier size-checks
//      every file it parses except its own ledger; the page loads only its own scripts.
// Any other .js/.mjs file in the shipped area is itself a finding, so new code cannot escape the check.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const root = process.argv[2] ?? join(import.meta.dirname, '..');
const findings = [];
const finding = (file, line, rule, message) => findings.push(`${file}:${line} [${rule}] ${message}`);
const read = file => readFileSync(join(root, file), 'utf8');
const lines = file => read(file).split('\n');

const CLIENT = ['app.js', 'core.mjs'];
const VERIFIER = existsSync(join(root, 'verifier')) ? readdirSync(join(root, 'verifier')).filter(f => /\.m?js$/u.test(f)).map(f => `verifier/${f}`) : [];
const SHIPPED = [...CLIENT, ...VERIFIER];
const WORKFLOW = '.github/workflows/verifier.yml';

// ---------------------------------------------------------------- scope: nothing shipped escapes the check
for (const name of readdirSync(root)) if (/\.(m?js|cjs|ts)$/u.test(name) && !CLIENT.includes(name)) finding(name, 1, 'scope', 'unchecked code file in the shipped area');
if (!VERIFIER.includes('verifier/run.mjs')) finding('verifier/run.mjs', 1, 'scope', 'verifier entry point missing');
for (const file of [...CLIENT, 'index.html', WORKFLOW]) if (!existsSync(join(root, file))) finding(file, 1, 'scope', 'expected file missing');
const workflows = existsSync(join(root, '.github/workflows')) ? readdirSync(join(root, '.github/workflows')) : [];
for (const name of workflows) if (`.github/workflows/${name}` !== WORKFLOW) finding(`.github/workflows/${name}`, 1, 'B', 'only the verifier workflow may exist');
if (findings.some(f => f.includes('expected file missing') || f.includes('entry point missing'))) done();

// ---------------------------------------------------------------- A. no executable dependency, no dynamic code
for (const name of ['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'node_modules']) {
  if (existsSync(join(root, name))) finding(name, 1, 'A', 'no package manifest, lockfile or installed dependency may exist');
}
const DYNAMIC = [[/\bimport\s*\(/u, 'dynamic import'], [/\brequire\s*\(/u, 'require'], [/\beval\s*\(/u, 'eval'], [/\bnew\s+Function\b|\bFunction\s*\(/u, 'Function constructor'],
  [/['"]node:(child_process|vm|worker_threads|module)['"]/u, 'child process / vm / module loader'], [/\bsetTimeout\s*\(\s*['"`]/u, 'string timer']];
for (const file of SHIPPED) {
  lines(file).forEach((text, index) => {
    for (const [pattern, what] of DYNAMIC) if (pattern.test(text)) finding(file, index + 1, 'A', `${what} is not allowed in shipped code`);
    for (const match of text.matchAll(/\b(?:import|export)\b[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gu)) {
      const spec = match[1] ?? match[2];
      const local = /^\.\.?\//u.test(spec) && !spec.includes('node_modules');
      const builtin = file.startsWith('verifier/') && /^node:(fs|path|crypto|url|os|buffer)$/u.test(spec);
      if (!local && !builtin) finding(file, index + 1, 'A', `import of '${spec}': only local files${file.startsWith('verifier/') ? ' or node: built-ins' : ''}`);
      if (CLIENT.includes(file) && spec !== './core.mjs') finding(file, index + 1, 'A', `the client imports only ./core.mjs, not '${spec}'`);
    }
  });
}
if (/\bimport\b/u.test(read('core.mjs').replace(/\/\/.*$/gmu, '').replace(/import\.meta/gu, ''))) finding('core.mjs', 1, 'A', 'core.mjs imports nothing');

// ---------------------------------------------------------------- B. the workflow runs no fork code
{
  const text = lines(WORKFLOW);
  const body = text.map(l => l.replace(/\s+#.*$/u, '')).join('\n');
  const triggers = /\non:\s*\n((?:[ \t]+.*\n)+)/u.exec(body)?.[1] ?? '';
  const events = [...triggers.matchAll(/^ {2}([a-z_]+):/gmu)].map(m => m[1]);
  if (events.join(',') !== 'pull_request_target') finding(WORKFLOW, 1, 'B', `the only trigger is pull_request_target (found: ${events.join(',') || 'none'})`);
  if (!/paths:\s*\[\s*'inbox\/\*\*'\s*\]/u.test(triggers)) finding(WORKFLOW, 1, 'B', "the trigger is filtered to paths ['inbox/**']");
  let secretsSeen = 0;
  text.forEach((line, index) => {
    const n = index + 1, code = line.replace(/\s+#.*$/u, '');
    if (/^\s*-?\s*uses:/u.test(code)) finding(WORKFLOW, n, 'B', 'no actions (`uses:`) may run');
    const runsOn = /runs-on:\s*(.+)$/u.exec(code);
    if (runsOn && !/^ubuntu-\d{2}\.\d{2}$/u.test(runsOn[1].trim())) finding(WORKFLOW, n, 'B', 'runs-on must be a pinned GitHub-hosted ubuntu image');
    if (/\b(npm|npx|pnpm|yarn|pip3?|bun|deno)\b|curl\b|wget\b|\bsource\b|\beval\b/u.test(code)) finding(WORKFLOW, n, 'B', 'no install, download or eval steps');
    if (/github\.(head_ref|event\.pull_request\.head\.(ref|repo))/u.test(code)) finding(WORKFLOW, n, 'B', 'the PR head ref/repository is never fetched or used');
    if (/github\.event\.pull_request\.head\.sha/u.test(code) && !/^\s*HEAD_SHA:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}\s*$/u.test(code)) {
      finding(WORKFLOW, n, 'B', 'the PR head sha is passed only as HEAD_SHA (read as data through the API)');
    }
    if (/\$\{\{\s*github\.event\.(pull_request\.(title|body)|comment|issue)/u.test(code)) finding(WORKFLOW, n, 'B', 'no PR text is interpolated into the workflow');
    if (/secrets\./u.test(code)) {
      secretsSeen++;
      if (!/^\s*(GITHUB_TOKEN|VERIFIER_SIGNING_KEY):\s*\$\{\{\s*secrets\.(GITHUB_TOKEN|VERIFIER_SIGNING_KEY)\s*\}\}\s*$/u.test(code)) finding(WORKFLOW, n, 'B', 'secrets appear only as the verify step\'s two env values');
    }
    if (/^\s*(id-token|actions|packages|deployments|pages|security-events|attestations):\s*write/u.test(code) || /write-all/u.test(code)) finding(WORKFLOW, n, 'B', 'permissions are limited to contents, pull-requests and issues');
    if (/^\s*run:/u.test(code) || /^\s{10,}\S/u.test(code)) {
      if (/git\s+(fetch|clone|checkout|pull)\b/u.test(code) && !/git fetch -q --depth 1 "https:\/\/github\.com\/\$\{REPO\}\.git" "\$\{BASE_SHA\}"|git checkout -q FETCH_HEAD/u.test(code)) {
        finding(WORKFLOW, n, 'B', 'only the trusted base commit (github.sha) is fetched');
      }
    }
  });
  if (secretsSeen !== 2) finding(WORKFLOW, 1, 'B', `exactly two secret references expected, found ${secretsSeen}`);
  if (!/BASE_SHA:\s*\$\{\{\s*github\.sha\s*\}\}/u.test(body)) finding(WORKFLOW, 1, 'B', 'BASE_SHA must be github.sha (the base branch commit)');
  const runs = [...body.matchAll(/run:\s*(\|\n(?:\s{10,}.*\n?)+|.*)/gu)].map(m => m[1].replace(/^\|\n/u, '').trim());
  const verify = runs.filter(r => !/^git init/u.test(r));
  if (verify.length !== 1 || verify[0] !== 'node verifier/run.mjs') finding(WORKFLOW, 1, 'B', 'the only program run is `node verifier/run.mjs` from the base checkout');
}

// ---------------------------------------------------------------- C. the verifier writes only its ledger
{
  const WRITES = [/^`contents\/\$\{path\}`, \{ message: `verifier: \$\{path\}`, content, branch: LEDGER \}/u, /^'git\/trees'/u, /^'git\/commits'/u,
    /^'git\/refs', \{ ref: `refs\/heads\/\$\{LEDGER\}`/u, /^`issues\/\$\{PR\}\/comments`/u, /^`pulls\/\$\{PR\}`, \{ state: 'closed' \}/u];
  for (const file of VERIFIER) {
    lines(file).forEach((text, index) => {
      for (const match of text.matchAll(/\bapi\(\s*'(PUT|POST|PATCH|DELETE)',\s*(.*)$/gu)) {
        if (match[1] === 'DELETE' || !WRITES.some(pattern => pattern.test(match[2]))) finding(file, index + 1, 'C', `write '${match[1]} ${match[2].slice(0, 60)}' is not an allowed ledger/comment/close write`);
      }
      if (/\bfetch\s*\(/u.test(text) && !/fetch\(`\$\{API\}\//u.test(text)) finding(file, index + 1, 'C', 'the verifier talks only to the GitHub API');
      if (/\b(writeFileSync|appendFileSync|rmSync|unlinkSync|renameSync)\b/u.test(text)) finding(file, index + 1, 'C', 'the verifier writes no local files');
    });
  }
  if (!/const API = 'https:\/\/api\.github\.com'|API = 'https:\/\/api\.github\.com'/u.test(read('verifier/run.mjs'))) finding('verifier/run.mjs', 1, 'C', 'API must be https://api.github.com');
  if (!/LEDGER = 'ledger'/u.test(read('verifier/run.mjs'))) finding('verifier/run.mjs', 1, 'C', "LEDGER must be the 'ledger' branch");
}

// ---------------------------------------------------------------- D. bounded inputs
{
  for (const file of CLIENT) {
    lines(file).forEach((text, index) => {
      if (/\.(text|json|arrayBuffer|blob|formData)\s*\(\s*\)/u.test(text)) finding(file, index + 1, 'D', 'the client never reads a whole body; use fetchBounded');
      if (/\bfetch\s*\(/u.test(text) && !/fetchImpl\(target/u.test(text) && !/method: 'POST'.*signal: AbortSignal\.timeout\(/u.test(text)) {
        finding(file, index + 1, 'D', 'untrusted GETs go through fetchBounded; the one POST carries a timeout');
      }
    });
  }
  const core = read('core.mjs');
  if (!/export async function fetchBounded/u.test(core) || !/check\(total <= maxBytes/u.test(core) || !/reader\??\.cancel\(\)/u.test(core) || !/setTimeout\(/u.test(core)) {
    finding('core.mjs', 1, 'D', 'fetchBounded must enforce a byte ceiling while reading, cancel, and carry a deadline');
  }
  const run = lines('verifier/run.mjs');
  run.forEach((text, index) => {
    if (!/JSON\.parse\(decode\(/u.test(text) || /const readLedger/u.test(text)) return;
    const window = run.slice(Math.max(0, index - 3), index + 1).join('\n');
    if (!/\.size <= LIMITS\.maxBody/u.test(window)) finding('verifier/run.mjs', index + 1, 'D', 'every parsed file except the verifier\'s own ledger is size-checked first');
  });
  const verifier = read('verifier/run.mjs');
  if (!/files\.length === 1 && files\[0\]\.status === 'added' && SUBMISSION\.test/u.test(verifier)) finding('verifier/run.mjs', 1, 'D', 'a submission is exactly one added inbox file');
  if (!/listing\.length <= \d+/u.test(verifier)) finding('verifier/run.mjs', 1, 'D', 'the approvers listing is bounded');
  const html = read('index.html');
  for (const match of html.matchAll(/<script\b([^>]*)>/gu)) {
    const src = /\bsrc="([^"]+)"/u.exec(match[1])?.[1];
    if (src === undefined) finding('index.html', 1, 'D', 'no inline scripts');
    else if (/^(?:[a-z]+:|\/\/)/iu.test(src)) finding('index.html', 1, 'D', `script '${src}' is not from this origin`);
  }
  const csp = /Content-Security-Policy" content="([^"]+)"/u.exec(html)?.[1] ?? '';
  if (!/script-src 'self'(;|$)/u.test(csp) || /unsafe-/u.test(csp)) finding('index.html', 1, 'D', "the page's CSP is script-src 'self' with no unsafe- sources");
  if (!/frame-ancestors|window\.top !== window\.self/u.test(html + read('app.js'))) finding('app.js', 1, 'D', 'the page refuses to run inside a frame');
}

done();
function done() {
  if (findings.length > 0) { console.log(findings.join('\n')); console.log(`architecture check: ${findings.length} finding(s)`); process.exit(1); }
  console.log(`architecture check: ${SHIPPED.length + 2} files (${SHIPPED.join(', ')}, index.html, ${WORKFLOW}), 0 findings`);
  process.exit(0);
}
