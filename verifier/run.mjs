// The external verifier's one entry point, run by .github/workflows/verifier.yml on a GitHub-hosted runner
// from the TRUSTED BASE BRANCH. It never checks out, imports or executes pull request code: it reads the
// one submitted file as data through the API, and writes only to the `ledger` branch, create-once.
// Authority (installation.json, approvers/) is read from CURRENT main at acceptance, never from the job's
// base commit, so a job queued before a revocation cannot use the revoked key.
import { LIMITS, Refusal, acceptAct, check, consumeKey, digest, importSigningKey, issueChallenge, openChallenge, parseApprover,
  parseInstallation, safeReason, signReceipt, signingVersion } from '../core.mjs';

const env = name => { const value = process.env[name]; check(typeof value === 'string' && value.length > 0, 'verifier environment incomplete'); return value; };
const REPO = env('REPO'), PR = Number(env('PR_NUMBER')), HEAD = env('HEAD_SHA'), TOKEN = env('GITHUB_TOKEN');
const MAIN = 'main', LEDGER = 'ledger', API = 'https://api.github.com';
const SUBMISSION = /^inbox\/(proposal|act)-[a-z0-9-]{8,64}\.json$/u, APPROVER_FILE = /^[a-f0-9]{16}\.json$/u;

async function api(method, path, body, allow = []) {
  const response = await fetch(`${API}/repos/${REPO}/${path}`, { method, headers: { authorization: `Bearer ${TOKEN}`, accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28', 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (allow.includes(response.status)) return { status: response.status, json: null };
  if (!response.ok) throw new Refusal(`GitHub API ${method} answered ${response.status}`);
  return { status: response.status, json: response.status === 204 ? null : await response.json() };
}
const decode = content => Buffer.from(content, 'base64').toString('utf8');
const readFile = async (path, ref) => {
  const { status, json } = await api('GET', `contents/${path}?ref=${ref}`, undefined, [404]);
  return status === 404 ? null : json;
};
const readLedger = async path => { const file = await readFile(path, LEDGER); return file === null ? null : JSON.parse(decode(file.content)); };
const mainHead = async () => (await api('GET', `git/ref/heads/${MAIN}`)).json.object.sha;

/** The ledger branch is created by the verifier on first use, as an orphan commit (no copy of main). */
async function ensureLedger() {
  if ((await api('GET', `git/ref/heads/${LEDGER}`, undefined, [404])).status !== 404) return;
  const tree = await api('POST', 'git/trees', { tree: [{ path: 'README.md', mode: '100644', type: 'blob', content: 'Verifier ledger: challenges and signed receipts, create-once.\n' }] });
  const commit = await api('POST', 'git/commits', { message: 'verifier: create ledger', tree: tree.json.sha, parents: [] });
  await api('POST', 'git/refs', { ref: `refs/heads/${LEDGER}`, sha: commit.json.sha }, [422]); // 422: a concurrent job created it
}
/** Both branches must carry the protection ruleset (no deletion, no force-push): the ledger is append-only. */
async function checkProtection() {
  for (const branch of [MAIN, LEDGER]) {
    const types = new Set((await api('GET', `rules/branches/${branch}`)).json.map(rule => rule.type));
    check(types.has('deletion') && types.has('non_fast_forward'), 'the protection ruleset is not active; import it once (see the setup page)');
  }
}
const ATTEMPTS = 6;
const pause = attempt => new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
/** One create-once attempt on the ledger branch. GitHub refuses a create when the path exists (the durable
 * claim): 'created', 'exists' (the claim is someone else's), or 'retry' (a concurrent ledger commit; nothing
 * was written). */
async function putOnce(path, value) {
  const content = Buffer.from(`${JSON.stringify(value, null, 2)}\n`).toString('base64');
  const { status } = await api('PUT', `contents/${path}`, { message: `verifier: ${path}`, content, branch: LEDGER }, [409, 422]);
  if (status === 200 || status === 201) return 'created';
  if (status === 422 && (await readLedger(path)) !== null) return 'exists';
  return 'retry';
}
async function createOnce(path, value) {
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    const result = await putOnce(path, value);
    if (result !== 'retry') return result === 'created';
    await pause(attempt);
  }
  throw new Refusal('ledger write did not settle');
}

/** The current version of an authority file must come from the custodian's own direct commit on main (the
 * principal named in installation.json, not the repository namespace, so an organization works). Only the
 * latest change counts: an owner correction supersedes an earlier bad record, and history length is irrelevant. */
async function fromCustodian(path, ref, custodian) {
  const { json: commits } = await api('GET', `commits?path=${encodeURIComponent(path)}&sha=${ref}&per_page=1`);
  check(commits.length === 1, 'authority history unreadable');
  check(commits[0].author?.login?.toLowerCase() === custodian, 'authority file last changed by someone other than the custodian');
  const { json: pulls } = await api('GET', `commits/${commits[0].sha}/pulls`);
  check(pulls.length === 0, 'authority file last changed through a pull request');
}
async function loadAuthority(ref) {
  const file = await readFile('installation.json', ref);
  check(file !== null && file.size <= LIMITS.maxBody, 'installation.json missing or too large');
  const installation = parseInstallation(JSON.parse(decode(file.content)));
  check(installation.repository.toLowerCase() === REPO.toLowerCase(), 'installation names another repository');
  check(/^github:[a-z0-9-]{1,39}$/u.test(installation.principal), 'installation principal must be github:<login>');
  const custodian = installation.principal.slice('github:'.length);
  await fromCustodian('installation.json', ref, custodian);
  const listing = (await readFile('approvers', ref)) ?? [];
  check(Array.isArray(listing) && listing.length <= 32, 'approvers directory unreadable or too large');
  const approvers = [];
  for (const entry of listing.filter(item => item.type === 'file' && APPROVER_FILE.test(item.name)).sort((a, b) => a.name.localeCompare(b.name))) {
    try {
      await fromCustodian(`approvers/${entry.name}`, ref, custodian);
      const record = await readFile(`approvers/${entry.name}`, ref);
      check(record !== null && record.size <= LIMITS.maxBody, 'approver record missing or too large');
      approvers.push(await parseApprover(JSON.parse(decode(record.content)), installation));
    } catch (error) { console.log(`approver ${entry.name} ignored: ${safeReason(error)}`); }
  }
  check(approvers.length <= LIMITS.maxKeys, 'too many approvers');
  return { installation, approvers };
}

async function settle(outcome) {
  // Public logs and comments carry only opaque references and fixed refusal sentences, never input.
  console.log(`outcome: ${outcome}`);
  await api('POST', `issues/${PR}/comments`, { body: `verifier: ${outcome}` });
  await api('PATCH', `pulls/${PR}`, { state: 'closed' });
}

async function main() {
  const { json: files } = await api('GET', `pulls/${PR}/files?per_page=10`);
  check(files.length === 1 && files[0].status === 'added' && SUBMISSION.test(files[0].filename), 'a submission adds exactly one inbox file and nothing else');
  const blob = await readFile(files[0].filename, HEAD);
  check(blob !== null && blob.size <= LIMITS.maxBody, 'submission too large');
  const submission = JSON.parse(decode(blob.content)); // data only
  await checkProtection();
  await ensureLedger();
  const signingKey = await importSigningKey(env('VERIFIER_SIGNING_KEY'));
  if (files[0].filename.startsWith('inbox/proposal-')) {
    const { installation } = await loadAuthority(await mainHead());
    const envelope = await issueChallenge({ proposal: submission, installation, now: Date.now(), random: crypto.getRandomValues(new Uint8Array(32)),
      signingKey, keyVersion: await signingVersion(signingKey, installation) });
    check((await readLedger(`receipts/${await consumeKey(envelope.challenge)}.json`)) === null, 'this request was already decided');
    const name = envelope.challenge.id.slice('challenge:'.length);
    check(await createOnce(`challenges/${name}.json`, envelope), 'challenge id collision');
    return settle(`issued ${name}`);
  }
  const name = String(submission?.challengeId ?? '').slice('challenge:'.length);
  check(/^[a-f0-9]{64}$/u.test(name), 'act names no challenge');
  const envelope = await readLedger(`challenges/${name}.json`); // the verifier's own record, never the submitter's copy
  check(envelope !== null, 'unknown challenge');
  const key = await consumeKey(envelope.challenge);
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    if (attempt > 0) await pause(attempt - 1);
    // Recovery comes first, before any fresh-admission check: an acceptance already on the ledger is the
    // decision. Re-announcing it grants nothing new and rewrites nothing, whatever expiry or authority say now.
    const prior = await readLedger(`receipts/${key}.json`);
    if (prior !== null) {
      check(prior.receipt?.actDigest === await digest(submission), 'this request was already decided (replay refused)');
      return settle(`receipt ${key} already recorded`);
    }
    // Fresh admission on EVERY write attempt: a failed write recorded nothing, so a retry is a new acceptance
    // and must see current main and the current clock, never the authority or time of an earlier attempt.
    const ref = await mainHead();
    const { installation, approvers } = await loadAuthority(ref);
    await openChallenge(envelope, installation);
    const now = Date.now(); // sampled after the authority load: a slow load cannot carry an earlier time past expiry
    const receipt = await acceptAct({ envelope, act: submission, approvers, installation, now, approversRef: ref });
    const signedReceipt = await signReceipt(receipt, signingKey, await signingVersion(signingKey, installation));
    // The last admission check before the write: main unchanged since the authority read, challenge unexpired.
    // A revocation landing after this point, during the one write, is ordered after the acceptance; the receipt
    // names the authority commit it checked, and the effect owner rechecks current authority at use.
    check((await mainHead()) === ref, 'authority changed during acceptance; submit the decision again');
    check(Date.now() < envelope.challenge.expiresAt, 'challenge expired');
    if ((await putOnce(`receipts/${key}.json`, signedReceipt)) === 'created') return settle(`${receipt.decision} recorded as receipt ${key}`);
    // 'exists' (a concurrent job accepted first) is recovered, and 'retry' re-admitted, by the next pass.
  }
  throw new Refusal('ledger write did not settle');
}

main().catch(async error => {
  const reason = safeReason(error);
  try { await settle(`refused: ${reason}`); } catch { console.log(`refused: ${reason}`); }
  process.exitCode = 1;
});
