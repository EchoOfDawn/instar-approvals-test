// The verifier entry point end to end, against an in-memory GitHub (tests/verifier-harness.mjs).
// Round-2/3 must-fixes: current authority, re-admitted on every write attempt (MF1, R2-MF1), recoverable
// acceptance and key versions (MF2), custodian identity and history (MF3), no input echoed into public output
// (MF6), and the ledger/ruleset bootstrap.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { repository, runVerifier } from './verifier-harness.mjs';
import { softAuthenticator } from './soft-authenticator.mjs';

const TREE = process.env.TREE ?? join(import.meta.dirname, '..');
const C = await import(pathToFileURL(join(TREE, 'core.mjs')).href);
const pair = () => { const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { secret: C.b64u(privateKey.export({ format: 'der', type: 'pkcs8' })), spki: C.b64u(publicKey.export({ format: 'der', type: 'spki' })) }; };
const V1 = pair(), V2 = pair();
const T0 = 1_790_000_000_000;
const json = value => `${JSON.stringify(value, null, 2)}\n`;

function installationFor({ repo = 'Human/approvals', keys = [{ version: 1, publicKey: V1.spki }] } = {}) {
  return C.parseInstallation({ type: 'InstarApprovalInstallation', v: 1, installation: 'approvals', origin: 'https://human.github.io',
    rpId: 'human.github.io', repository: repo, principal: 'github:human', verifierKeys: keys });
}
const owner = (sha, login = 'Human') => ({ sha, login, pulls: [] });
const viaPr = (sha, login = 'Human') => ({ sha, login, pulls: [{ number: 7 }] });

async function scenario({ repo = 'Human/approvals', keys, lifetimeMs = 60_000, issueKey = V1, issueVersion = 1 } = {}) {
  const installation = installationFor({ repo, keys });
  const phone = softAuthenticator({ rpId: installation.rpId, origin: installation.origin });
  const approverPath = 'approvers/aaaaaaaaaaaaaaaa.json';
  const files = { 'installation.json': json(installation), [approverPath]: json(phone.register({ installation })) };
  const history = { 'installation.json': [owner('c-install')], [approverPath]: [owner('c-approver')] };
  const proposal = { type: 'InstarApprovalProposal', v: 1, installation: 'approvals', action: 'raise-caps', subject: { kind: 'model-calls', from: 1, to: 2 },
    base: await C.digest('base'), artifact: await C.digest('artifact'), request: `request:${'a'.repeat(64)}`, requestedBy: 'agent:echo',
    noteDigest: await C.digest(''), lifetimeMs };
  const envelope = await C.issueChallenge({ proposal, installation, now: T0, random: new Uint8Array(32), signingKey: await C.importSigningKey(issueKey.secret), keyVersion: issueVersion });
  const nonce = C.b64u(new Uint8Array(32).fill(3));
  const act = { type: 'InstarApprovalAct', v: 1, challengeId: envelope.challenge.id, decision: 'approve', nonce,
    assertion: phone.assert(await C.actChallenge(envelope.challenge, 'approve', nonce)) };
  const key = await C.consumeKey(envelope.challenge);
  const ledger = new Map([[`challenges/${envelope.challenge.id.slice('challenge:'.length)}.json`, json(envelope)]]);
  return { installation, files, history, approverPath, envelope, act, key, ledger, repoName: repo };
}
const outcome = repo => repo.comments.at(-1) ?? '(no verdict)';

test('MF1: a key revoked on current main refuses, even though the job\'s base commit still lists it', async () => {
  const s = await scenario();
  const revoked = { ...s.files }; delete revoked[s.approverPath];
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [
    { sha: 'OLD-BASE', files: s.files, history: s.history },
    { sha: 'CURRENT', files: revoked, history: { 'installation.json': s.history['installation.json'] } }] });
  repo.mainReads = 1; // every read of main answers the current (revoked) state
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret, baseFiles: s.files });
  assert.match(outcome(repo), /refused: passkey not enrolled/u);
  assert.equal(repo.writes.length, 0, 'nothing is consumed');
});

test('MF1: a still-authorized key succeeds and the receipt binds the current authority commit', async () => {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'OLD-BASE', files: s.files, history: s.history },
    { sha: 'CURRENT', files: s.files, history: s.history }] });
  repo.mainReads = 1;
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret, baseFiles: s.files });
  assert.match(outcome(repo), /approve recorded as receipt/u);
  const receipt = await C.openReceipt(JSON.parse(repo.ledger.get(`receipts/${s.key}.json`)), s.installation);
  assert.equal(receipt.approversRef, 'CURRENT');
});

test('MF1: main changing between the authority read and the acceptance write refuses without consuming', async () => {
  const s = await scenario();
  const revoked = { ...s.files }; delete revoked[s.approverPath];
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'A', files: s.files, history: s.history },
    { sha: 'B', files: revoked, history: { 'installation.json': s.history['installation.json'] } }] });
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /refused: authority changed/u);
  assert.equal(repo.writes.length, 0);
});

// R2-MF1: a failed ledger write recorded nothing, so every new write attempt is admitted afresh against
// current main and the current clock; the clock is sampled after the authority load, not before it.
async function retried(change) {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'AUTHORIZED', files: s.files, history: s.history }] });
  let attempts = 0;
  repo.beforeWrite = file => { if (!file.startsWith('receipts/')) return 0; attempts++; if (attempts === 1) { change(s, repo); return 409; } return 0; };
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  return { s, repo, attempts };
}

test('R2-MF1: a revocation completed after a failed receipt write refuses the retry', async () => {
  const { s, repo, attempts } = await retried((s, repo) => {
    const revoked = { ...s.files }; delete revoked[s.approverPath];
    repo.main = [{ sha: 'REVOKED', files: revoked, history: { 'installation.json': s.history['installation.json'] } }];
  });
  assert.equal(attempts, 1, 'no second write under the revoked authority');
  assert.match(outcome(repo), /refused: passkey not enrolled/u);
  assert.equal(repo.ledger.has(`receipts/${s.key}.json`), false, 'nothing is accepted');
});

test('R2-MF1: expiry reached after a failed receipt write refuses the retry', async () => {
  const { s, repo, attempts } = await retried(() => { Date.now = () => T0 + 120_000; });
  assert.equal(attempts, 1);
  assert.match(outcome(repo), /refused: challenge expired/u);
  assert.equal(repo.ledger.has(`receipts/${s.key}.json`), false);
});

test('R2-MF1: a failed write with authority and clock unchanged is retried and accepted, binding current main', async () => {
  const { s, repo, attempts } = await retried(() => {});
  assert.equal(attempts, 2);
  assert.match(outcome(repo), /approve recorded as receipt/u);
  const receipt = await C.openReceipt(JSON.parse(repo.ledger.get(`receipts/${s.key}.json`)), s.installation);
  assert.equal(receipt.approversRef, 'AUTHORIZED');
  assert.equal(receipt.verifiedAt, T0 + 1000);
});

test('R2-MF1: expiry reached while authority loads refuses; the clock is sampled after the load', async () => {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'AUTHORIZED', files: s.files, history: s.history }] });
  repo.onMain = () => { Date.now = () => T0 + 120_000; };
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /refused: challenge expired/u);
  assert.equal(repo.writes.length, 0);
});

test('R2-MF1: the receipt records the time sampled after the authority load, not before it', async () => {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'AUTHORIZED', files: s.files, history: s.history }] });
  repo.onMain = () => { if (repo.mainReads === 0) Date.now = () => T0 + 30_000; }; // the load takes 29 s, within the lifetime
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /approve recorded/u);
  const receipt = await C.openReceipt(JSON.parse(repo.ledger.get(`receipts/${s.key}.json`)), s.installation);
  assert.equal(receipt.verifiedAt, T0 + 30_000);
});

test('R2-MF1: expiry reached during the final authority recheck refuses before the write', async () => {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'AUTHORIZED', files: s.files, history: s.history }] });
  repo.onMain = () => { if (repo.mainReads === 1) Date.now = () => T0 + 120_000; }; // the second read is the recheck
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /refused: challenge expired/u);
  assert.equal(repo.writes.length, 0);
});

test('R2-MF1: a concurrent job that accepts during the retry wait is recovered on re-admission, not overwritten', async () => {
  const s = await scenario();
  const other = repository({ name: s.repoName, ledger: new Map(s.ledger), main: [{ sha: 'AUTHORIZED', files: s.files, history: s.history }] });
  await runVerifier(other, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  const winner = other.ledger.get(`receipts/${s.key}.json`); // the concurrent job's receipt
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'AUTHORIZED', files: s.files, history: s.history }] });
  let attempts = 0;
  repo.beforeWrite = file => { if (!file.startsWith('receipts/')) return 0; attempts++; repo.ledger.set(file, winner); return 409; };
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.equal(attempts, 1);
  assert.match(outcome(repo), /already recorded/u);
  assert.equal(repo.ledger.get(`receipts/${s.key}.json`), winner);
});

test('MF2: acceptance durable but not announced, retried after expiry and an authority change, recovers the same receipt', async () => {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'FIRST', files: s.files, history: s.history }] });
  repo.failComments = 2; // the job "crashes" after the durable write: announcing fails
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  const stored = repo.ledger.get(`receipts/${s.key}.json`);
  assert.ok(stored, 'the acceptance is durable');
  // Retry: the challenge has expired and main has moved on (the approver was since revoked).
  const revoked = { ...s.files }; delete revoked[s.approverPath];
  repo.main = [{ sha: 'LATER', files: revoked, history: { 'installation.json': s.history['installation.json'] } }]; repo.mainReads = 0;
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 3_600_000, secret: V1.secret });
  assert.match(outcome(repo), /already recorded/u);
  assert.equal(repo.ledger.get(`receipts/${s.key}.json`), stored, 'recovery rewrites nothing');
  assert.equal((await C.openReceipt(JSON.parse(stored), s.installation)).approversRef, 'FIRST', 'the original authority is kept');
  // A different act for the decided request is still a replay.
  const other = { ...s.act, nonce: C.b64u(new Uint8Array(32).fill(4)) };
  await runVerifier(repo, { submission: JSON.stringify(other), now: T0 + 3_600_000, secret: V1.secret });
  assert.match(outcome(repo), /already decided/u);
});

test('MF2: a challenge signed with key v1 accepted after rotating the secret to v2 yields a receipt labelled v2 that opens', async () => {
  const keys = [{ version: 1, publicKey: V1.spki }, { version: 2, publicKey: V2.spki }];
  const s = await scenario({ keys });
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'M', files: s.files, history: s.history }] });
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V2.secret });
  assert.match(outcome(repo), /approve recorded/u);
  const receipt = await C.openReceipt(JSON.parse(repo.ledger.get(`receipts/${s.key}.json`)), s.installation);
  assert.equal(receipt.keyVersion, 2);
  assert.equal(receipt.challengeKeyVersion, 1);
});

test('MF3: an organization repository with the owner\'s own commits loads (custodian is the principal, not the namespace)', async () => {
  const s = await scenario({ repo: 'owner-only-org/approvals' });
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'M', files: s.files, history: s.history }] });
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /approve recorded/u);
});

test('MF3: an owner correction supersedes an earlier pull-request record, and long owner histories still load', async () => {
  const s = await scenario();
  const long = Array.from({ length: 40 }, (_, i) => owner(`c-install-${i}`));
  const history = { 'installation.json': long, [s.approverPath]: [owner('c-fix'), viaPr('c-bad', 'EchoOfDawn')] };
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'M', files: s.files, history }] });
  await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /approve recorded/u);
});

test('MF3: a record whose current version came through a pull request, or from another author, is ignored', async () => {
  for (const latest of [viaPr('c-pr'), owner('c-other', 'EchoOfDawn')]) {
    const s = await scenario();
    const history = { ...s.history, [s.approverPath]: [latest, owner('c-old')] };
    const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'M', files: s.files, history }] });
    await runVerifier(repo, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
    assert.match(outcome(repo), /refused: passkey not enrolled/u);
  }
});

test('MF6: malformed input is never echoed into the public comment or log', async () => {
  const s = await scenario();
  const repo = repository({ name: s.repoName, ledger: s.ledger, main: [{ sha: 'M', files: s.files, history: s.history }] });
  await runVerifier(repo, { submission: 'PRIVATE_REQUEST_MARKER', now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(repo), /^verifier: refused: /u);
  const everything = [...repo.comments, ...repo.logs].join('\n');
  assert.doesNotMatch(everything, /PRIVATE_RE/u);
  // A well-formed but malicious field value is not echoed either.
  const odd = { ...s.act, decision: 'PRIVATE_DECISION_MARKER' };
  await runVerifier(repo, { submission: JSON.stringify(odd), now: T0 + 1000, secret: V1.secret });
  assert.doesNotMatch([...repo.comments, ...repo.logs].join('\n'), /PRIVATE_DECISION/u);
});

test('setup: the verifier creates its ledger branch on first use, and refuses without the protection ruleset', async () => {
  const s = await scenario();
  const fresh = repository({ name: s.repoName, ledgerExists: false, main: [{ sha: 'M', files: s.files, history: s.history }] });
  const proposal = JSON.parse(JSON.stringify({ type: 'InstarApprovalProposal', v: 1, installation: 'approvals', action: 'raise-caps',
    subject: { kind: 'model-calls', from: 1, to: 2 }, base: s.envelope.challenge.base, artifact: s.envelope.challenge.artifact,
    request: `request:${'c'.repeat(64)}`, requestedBy: 'agent:echo', noteDigest: s.envelope.challenge.noteDigest, lifetimeMs: 60_000 }));
  await runVerifier(fresh, { submission: JSON.stringify(proposal), now: T0, secret: V1.secret });
  assert.match(outcome(fresh), /issued [a-f0-9]{64}/u);
  assert.equal(fresh.ledgerExists, true);
  const bare = repository({ name: s.repoName, ledger: s.ledger, rules: [], main: [{ sha: 'M', files: s.files, history: s.history }] });
  await runVerifier(bare, { submission: JSON.stringify(s.act), now: T0 + 1000, secret: V1.secret });
  assert.match(outcome(bare), /refused: .*protection ruleset/u);
  assert.equal(bare.writes.length, 0);
});
