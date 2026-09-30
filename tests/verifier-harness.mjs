// Runs the verifier's real entry point (verifier/run.mjs) against an in-memory GitHub, as the workflow would:
// a base checkout of the code in a temporary directory, environment variables, and the REST API via fetch.
// TREE=<dir> selects which tree's code runs (default: this repository), so a test can be run against old bytes.
import { cpSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const TREE = process.env.TREE ?? join(dirname(fileURLToPath(import.meta.url)), '..');
const b64 = text => Buffer.from(text).toString('base64');
let run = 0;

/** A repository (optional hooks: `onMain()` runs on each main-ref read; `beforeWrite(file)` runs before a ledger
 * create and may return a status to answer instead, modelling a concurrent ledger commit).
 * A repository: `main` is a list of states (each { sha, files: {path: text}, history: {path: [{sha, login, pulls}]} });
 * `mainAt` picks which state answers each successive `git/ref/heads/main` read (to model a concurrent change). */
export function repository({ name, main, ledger = new Map(), ledgerExists = true, rules = ['deletion', 'non_fast_forward'] }) {
  return { name, main, ledger, ledgerExists, rules, mainReads: 0, comments: [], logs: [], closed: false, failComments: 0, writes: [] };
}

export async function runVerifier(repo, { submission, pr = 1, now, secret, baseFiles }) {
  const inbox = `inbox/${submission.includes('InstarApprovalProposal') ? 'proposal' : 'act'}-aaaaaaaa.json`;
  const dir = mkdtempSync(join(tmpdir(), 'verifier-'));
  mkdirSync(join(dir, 'verifier'));
  cpSync(join(TREE, 'core.mjs'), join(dir, 'core.mjs'));
  cpSync(join(TREE, 'verifier'), join(dir, 'verifier'), { recursive: true });
  // The base checkout also carries the authority files as they were at the base commit.
  for (const [path, text] of Object.entries(baseFiles ?? repo.main[0].files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  const state = () => repo.main[Math.min(repo.mainReads, repo.main.length - 1)];
  const byRef = ref => repo.main.find(item => item.sha === ref) ?? repo.main[0];
  const answer = (status, json) => ({ status, ok: status >= 200 && status < 300, json: async () => json, text: async () => JSON.stringify(json) });
  let finished;
  const done = new Promise(resolve => { finished = resolve; });
  const realFetch = globalThis.fetch, realNow = Date.now, realLog = console.log, cwd = process.cwd();
  globalThis.fetch = async (url, options = {}) => {
    const u = new URL(url), method = options.method ?? 'GET';
    const path = decodeURIComponent(u.pathname.replace(`/repos/${repo.name}/`, '')), ref = u.searchParams.get('ref');
    if (path === `pulls/${pr}/files`) return answer(200, [{ status: 'added', filename: inbox }]);
    if (path === `contents/${inbox}`) return answer(200, { size: Buffer.byteLength(submission), content: b64(submission) });
    if (path === 'git/ref/heads/main') { repo.onMain?.(); const current = state(); repo.mainReads++; return answer(200, { object: { sha: current.sha } }); }
    if (path === 'git/ref/heads/ledger') return repo.ledgerExists ? answer(200, { object: { sha: 'ledger-head' } }) : answer(404, {});
    if (path === 'git/trees' || path === 'git/commits') return answer(201, { sha: `${path}-new` });
    if (path === 'git/refs' && method === 'POST') { repo.ledgerExists = true; return answer(201, {}); }
    if (path.startsWith('rules/branches/')) return answer(200, repo.rules.map(type => ({ type })));
    if (path === 'commits') {
      const history = byRef(u.searchParams.get('sha')).history[u.searchParams.get('path')] ?? [];
      return answer(200, history.slice(0, Number(u.searchParams.get('per_page') ?? 30)).map(c => ({ sha: c.sha, author: c.login ? { login: c.login } : null })));
    }
    const pulls = /^commits\/([^/]+)\/pulls$/u.exec(path);
    if (pulls) {
      const commit = repo.main.flatMap(s => Object.values(s.history).flat()).find(c => c.sha === pulls[1]);
      return answer(200, commit?.pulls ?? []);
    }
    if (path.startsWith('contents/')) {
      const file = path.slice('contents/'.length);
      if (ref === 'ledger' || (method === 'PUT' && JSON.parse(options.body).branch === 'ledger')) {
        if (!repo.ledgerExists) return answer(404, {});
        if (method === 'GET') return repo.ledger.has(file) ? answer(200, { content: b64(repo.ledger.get(file)) }) : answer(404, {});
        if (repo.beforeWrite) { const blocked = await repo.beforeWrite(file); if (blocked) return answer(blocked, {}); }
        if (repo.ledger.has(file)) return answer(422, {});
        repo.ledger.set(file, Buffer.from(JSON.parse(options.body).content, 'base64').toString('utf8'));
        repo.writes.push(file);
        return answer(201, {});
      }
      if (method !== 'GET') return answer(403, {}); // anything but the ledger is not writable by the workflow
      const files = byRef(ref).files;
      if (Object.hasOwn(files, file)) return answer(200, { type: 'file', size: Buffer.byteLength(files[file]), content: b64(files[file]) });
      const listing = Object.keys(files).filter(p => p.startsWith(`${file}/`)).map(p => ({ type: 'file', name: p.slice(file.length + 1), path: p }));
      return listing.length > 0 ? answer(200, listing) : answer(404, {});
    }
    if (path === `issues/${pr}/comments`) {
      if (repo.failComments > 0) { repo.failComments--; return answer(502, {}); }
      repo.comments.push(JSON.parse(options.body).body); return answer(201, {});
    }
    if (path === `pulls/${pr}`) { repo.closed = true; finished(); return answer(200, {}); }
    throw new Error(`unmocked ${method} ${path}`);
  };
  Date.now = () => now;
  console.log = (...args) => { repo.logs.push(args.join(' ')); };
  Object.assign(process.env, { REPO: repo.name, PR_NUMBER: String(pr), HEAD_SHA: 'submission-head', BASE_SHA: repo.main[0].sha,
    GITHUB_TOKEN: 'synthetic-token', VERIFIER_SIGNING_KEY: secret });
  process.chdir(dir);
  try {
    await import(`${pathToFileURL(join(dir, 'verifier', 'run.mjs')).href}?run=${run++}`);
    await Promise.race([done, new Promise(resolve => setTimeout(resolve, 3000))]);
    await new Promise(resolve => setTimeout(resolve, 20));
  } finally {
    globalThis.fetch = realFetch; Date.now = realNow; console.log = realLog; process.chdir(cwd); process.exitCode = 0;
  }
  return repo;
}
