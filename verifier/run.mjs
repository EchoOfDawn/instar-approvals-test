// The external verifier's one entry point, run by .github/workflows/verifier.yml on a GitHub-hosted runner
// from the TRUSTED BASE BRANCH. It never checks out, imports or executes pull request code: it reads the
// one submitted file as data through the API, and writes only to the `ledger` branch, create-once.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { acceptAct, check, consumeKey, importSigningKey, issueChallenge, openChallenge, parseApprover,
  parseInstallation, signReceipt } from '../core.mjs';

const env = name => { const value = process.env[name]; check(typeof value === 'string' && value.length > 0, `${name} missing`); return value; };
const REPO = env('REPO'), PR = Number(env('PR_NUMBER')), HEAD = env('HEAD_SHA'), BASE = env('BASE_SHA'), TOKEN = env('GITHUB_TOKEN');
const LEDGER = 'ledger', API = 'https://api.github.com';
const SUBMISSION = /^inbox\/(proposal|act)-[a-z0-9-]{8,64}\.json$/u;

async function api(method, path, body, allow = []) {
  const response = await fetch(`${API}${path}`, { method, headers: { authorization: `Bearer ${TOKEN}`, accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28', 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (allow.includes(response.status)) return { status: response.status, json: null };
  if (!response.ok) throw new Error(`GitHub API ${method} ${path.split('?')[0]} answered ${response.status}`);
  return { status: response.status, json: response.status === 204 ? null : await response.json() };
}
const decode = content => Buffer.from(content, 'base64').toString('utf8');
async function readLedger(path) {
  const { status, json } = await api('GET', `/repos/${REPO}/contents/${path}?ref=${LEDGER}`, undefined, [404]);
  return status === 404 ? null : JSON.parse(decode(json.content));
}
/** Create-once on the ledger branch: GitHub refuses a create when the path exists (the durable claim). */
async function createOnce(path, value) {
  const content = Buffer.from(`${JSON.stringify(value, null, 2)}\n`).toString('base64');
  for (let attempt = 0; attempt < 6; attempt++) {
    const { status } = await api('PUT', `/repos/${REPO}/contents/${path}`, { message: `verifier: ${path}`, content, branch: LEDGER }, [409, 422]);
    if (status === 200 || status === 201) return true;
    if (status === 422 && (await readLedger(path)) !== null) return false; // already exists: the claim is someone else's
    await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1))); // a concurrent ledger commit; retry
  }
  throw new Error(`ledger write for ${path} did not settle`);
}

/** Authority comes from the base branch only, and only from the owner's own direct commits: an approver
 * or installation record that arrived through any pull request (including a merged agent PR) is refused. */
async function ownedByOwner(path) {
  const owner = REPO.split('/')[0].toLowerCase();
  const { json: commits } = await api('GET', `/repos/${REPO}/commits?path=${encodeURIComponent(path)}&sha=${BASE}&per_page=20`);
  check(commits.length > 0 && commits.length < 20, `${path} history unreadable`);
  for (const commit of commits) {
    check(commit.author?.login?.toLowerCase() === owner, `${path} was changed by someone other than the owner`);
    const { json: pulls } = await api('GET', `/repos/${REPO}/commits/${commit.sha}/pulls`);
    check(pulls.length === 0, `${path} arrived through a pull request`);
  }
}
async function loadAuthority() {
  const installation = parseInstallation(JSON.parse(readFileSync('installation.json', 'utf8')));
  check(installation.repository.toLowerCase() === REPO.toLowerCase(), 'installation names another repository');
  await ownedByOwner('installation.json');
  const approvers = [];
  for (const name of (existsSync('approvers') ? readdirSync('approvers') : []).filter(file => /^[a-f0-9]{16}\.json$/u.test(file)).sort()) {
    const path = `approvers/${name}`;
    try { await ownedByOwner(path); approvers.push(await parseApprover(JSON.parse(readFileSync(join('approvers', name), 'utf8')), installation)); }
    catch (error) { console.log(`approver ${name} ignored: ${error.message}`); }
  }
  check(approvers.length <= 8, 'too many approvers');
  return { installation, approvers };
}

async function settle(outcome) {
  // Public logs and comments carry only opaque references and the refusal reason, never request content.
  console.log(`outcome: ${outcome}`);
  await api('POST', `/repos/${REPO}/issues/${PR}/comments`, { body: `verifier: ${outcome}` });
  await api('PATCH', `/repos/${REPO}/pulls/${PR}`, { state: 'closed' });
}

async function main() {
  const { json: files } = await api('GET', `/repos/${REPO}/pulls/${PR}/files?per_page=10`);
  check(files.length === 1 && files[0].status === 'added' && SUBMISSION.test(files[0].filename), 'a submission adds exactly one inbox file and nothing else');
  const { json: blob } = await api('GET', `/repos/${REPO}/contents/${files[0].filename}?ref=${HEAD}`);
  check(blob.size <= 16384, 'submission too large');
  const submission = JSON.parse(decode(blob.content)); // data only
  const { installation, approvers } = await loadAuthority();
  const now = Date.now();
  if (files[0].filename.startsWith('inbox/proposal-')) {
    const signingKey = await importSigningKey(env('VERIFIER_SIGNING_KEY'));
    const keyVersion = Math.max(...installation.verifierKeys.map(key => key.version));
    const envelope = await issueChallenge({ proposal: submission, installation, now, random: crypto.getRandomValues(new Uint8Array(32)), signingKey, keyVersion });
    const key = await consumeKey(envelope.challenge);
    check((await readLedger(`consumed/${key}.json`)) === null, 'this request was already decided');
    const name = envelope.challenge.id.slice('challenge:'.length);
    check(await createOnce(`challenges/${name}.json`, envelope), 'challenge id collision');
    return settle(`issued ${name}`);
  }
  const name = String(submission?.challengeId ?? '').slice('challenge:'.length);
  check(/^[a-f0-9]{64}$/u.test(name), 'act names no challenge');
  const envelope = await readLedger(`challenges/${name}.json`); // the verifier's own record, never the submitter's copy
  check(envelope !== null, 'unknown challenge');
  const challenge = await openChallenge(envelope, installation);
  const receipt = await acceptAct({ envelope, act: submission, approvers, installation, now, approversRef: BASE });
  const key = await consumeKey(challenge);
  const claim = { challengeId: challenge.id, decision: receipt.decision, actDigest: receipt.actDigest, consumedAt: now };
  if (!(await createOnce(`consumed/${key}.json`, claim))) {
    const prior = await readLedger(`consumed/${key}.json`);
    // Crash recovery: the same act re-submitted re-emits its receipt; any other act for this request is a replay.
    check(prior.actDigest === receipt.actDigest, 'this request was already decided (replay refused)');
    const existing = await readLedger(`receipts/${key}.json`);
    if (existing !== null) return settle(`receipt ${key} already recorded`);
    receipt.verifiedAt = prior.consumedAt;
  }
  await createOnce(`receipts/${key}.json`, await signReceipt(receipt, await importSigningKey(env('VERIFIER_SIGNING_KEY'))));
  return settle(`${receipt.decision} recorded as receipt ${key}`);
}

main().catch(async error => {
  const reason = error instanceof Error ? error.message.slice(0, 200) : 'refused';
  try { await settle(`refused: ${reason}`); } catch { console.log(`refused: ${reason}`); }
  process.exitCode = 1;
});
