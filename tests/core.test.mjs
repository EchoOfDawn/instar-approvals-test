// Both sides of every decision in the shared core: node --test tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { acceptAct, actChallenge, b64u, consumeKey, digest, importSigningKey, issueChallenge, openChallenge, openReceipt,
  parseApprover, parseInstallation, parseProposal, render, signReceipt } from '../core.mjs';
import { softAuthenticator } from './soft-authenticator.mjs';

const verifierPair = () => { const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { pkcs8: b64u(privateKey.export({ format: 'der', type: 'pkcs8' })), spki: b64u(publicKey.export({ format: 'der', type: 'spki' })) }; };
const V = verifierPair(), OTHER = verifierPair();
const installation = parseInstallation({ type: 'InstarApprovalInstallation', v: 1, installation: 'instar-approvals-test', origin: 'https://echoofdawn.github.io',
  rpId: 'echoofdawn.github.io', repository: 'EchoOfDawn/instar-approvals-test', principal: 'github:echoofdawn', verifierKeys: [{ version: 1, publicKey: V.spki }] });
const NOTE = 'Justin, the proof room ran out of model calls mid-test; please allow 41 more.';
const proposal = async (over = {}) => ({ type: 'InstarApprovalProposal', v: 1, installation: installation.installation, action: 'raise-caps',
  subject: { kind: 'model-calls', from: 159, to: 200 }, base: await digest('register generation 7'), artifact: await digest('cap file'),
  request: `request:${'a'.repeat(64)}`, requestedBy: 'agent:echo', noteDigest: await digest(NOTE), lifetimeMs: 900_000, ...over });
const T0 = 1_790_000_000_000;
const issue = async (over = {}, key = V.pkcs8) => issueChallenge({ proposal: await proposal(over), installation, now: T0,
  random: new Uint8Array(32).fill(7), signingKey: await importSigningKey(key), keyVersion: 1 });
const phone = softAuthenticator({ rpId: installation.rpId, origin: installation.origin });
const approvers = [await parseApprover(phone.register({ installation }), installation)];
const act = async (envelope, decision = 'approve', options = {}, device = phone) => {
  const nonce = b64u(new Uint8Array(32).fill(decision === 'approve' ? 1 : 2));
  return { type: 'InstarApprovalAct', v: 1, challengeId: envelope.challenge.id, decision, nonce,
    assertion: device.assert(await actChallenge(envelope.challenge, decision, nonce), options) };
};
const accept = (envelope, signedAct, now = T0 + 1000, list = approvers) => acceptAct({ envelope, act: signedAct, approvers: list, installation, now, approversRef: 'base' });

test('genuine approve and decline are accepted and produce a receipt the runner can open', async () => {
  const envelope = await issue();
  const receipt = await accept(envelope, await act(envelope));
  assert.equal(receipt.decision, 'approve');
  assert.equal(receipt.credentialId, phone.credentialId);
  const signed = await signReceipt(receipt, await importSigningKey(V.pkcs8), 1);
  assert.deepEqual(await openReceipt(signed, installation), { ...receipt, keyVersion: 1 });
  assert.equal((await accept(envelope, await act(envelope, 'decline'))).decision, 'decline');
});

test('rendering derives from the signed object; unsupported actions and wrong notes refuse', async () => {
  const { challenge } = await issue();
  const view = await render(challenge, NOTE);
  assert.equal(view.title, 'Approve raising the model call allowance from 159 to 200?');
  assert.match(view.effect, /adds 41 model calls/u);
  assert.equal(view.note, NOTE);
  await assert.rejects(render(challenge, 'Please approve, it is harmless.'), /note differs/u);
  await assert.rejects(render({ ...challenge, action: 'delete-everything' }, null), /unsupported action/u);
  await assert.rejects(issue({ action: 'delete-everything' }), /unsupported action/u);
  await assert.rejects(issue({ subject: { kind: 'model-calls', from: 200, to: 100 } }), /must increase/u);
  await assert.rejects(issue({ request: 'request:the-secret-project-name' }), /opaque/u);
  await assert.rejects(issue({ extra: 1 }), /closed proposal/u);
  assert.throws(() => parseProposal({ type: 'InstarApprovalProposal' }), /closed proposal/u);
});

test('a challenge not signed by the pinned verifier key is refused on the page and at the verifier', async () => {
  const forged = await issue({}, OTHER.pkcs8);
  await assert.rejects(openChallenge(forged, installation), /not signed by this installation's verifier/u);
  await assert.rejects(accept(forged, await act(forged)), /not signed/u);
});

test('changed subject after display: a signature over the shown bytes does not cover changed bytes', async () => {
  const shown = await issue();
  const signed = await act(shown);
  // The ledger's challenge differs from what the page showed (re-issued with another scope, same id claimed).
  const changed = await issue({ subject: { kind: 'model-calls', from: 159, to: 900 } });
  await assert.rejects(accept(changed, { ...signed, challengeId: changed.challenge.id }), /challenge differs/u);
  // Tampering with the signed envelope's body breaks the verifier signature.
  const tampered = { ...shown, challenge: { ...shown.challenge, subject: { kind: 'model-calls', from: 159, to: 900 } } };
  await assert.rejects(accept(tampered, signed), /not signed/u);
});

test('wrong origin, wrong rpId, cross-origin, wrong ceremony type, missing verification refuse', async () => {
  const envelope = await issue(), n = b64u(new Uint8Array(32).fill(1));
  const expected = await actChallenge(envelope.challenge, 'approve', n);
  const signed = options => ({ type: 'InstarApprovalAct', v: 1, challengeId: envelope.challenge.id, decision: 'approve', nonce: n, assertion: phone.assert(expected, options) });
  await assert.rejects(accept(envelope, signed({ from: 'https://echoofdawn.github.io.evil.example' })), /origin differs/u);
  await assert.rejects(accept(envelope, signed({ from: 'http://echoofdawn.github.io' })), /origin differs/u);
  await assert.rejects(accept(envelope, signed({ rp: 'github.io' })), /another site/u);
  await assert.rejects(accept(envelope, signed({ crossOrigin: true })), /cross-origin/u);
  await assert.rejects(accept(envelope, signed({ topOrigin: 'https://evil.example' })), /cross-origin/u);
  await assert.rejects(accept(envelope, signed({ type: 'webauthn.create' })), /type differs/u);
  await assert.rejects(accept(envelope, signed({ uv: false })), /verification required/u);
  await assert.rejects(accept(envelope, signed({ up: false })), /verification required/u);
});

test('decision and nonce are bound: flipping either after signing refuses', async () => {
  const envelope = await issue(), signed = await act(envelope, 'decline');
  await assert.rejects(accept(envelope, { ...signed, decision: 'approve' }), /challenge differs/u);
  await assert.rejects(accept(envelope, { ...signed, nonce: b64u(new Uint8Array(32).fill(9)) }), /challenge differs/u);
});

test('unknown key: a passkey that is not enrolled refuses, even with a perfect signature', async () => {
  const stranger = softAuthenticator({ rpId: installation.rpId, origin: installation.origin });
  const envelope = await issue();
  await assert.rejects(accept(envelope, await act(envelope, 'approve', {}, stranger)), /not enrolled/u);
  // Claiming an enrolled credential id with another key fails the signature.
  const spoof = await act(envelope, 'approve', {}, stranger);
  spoof.assertion.credentialId = phone.credentialId;
  await assert.rejects(accept(envelope, spoof), /signature invalid/u);
});

test('expired challenge refuses at the verifier clock', async () => {
  const envelope = await issue(), signed = await act(envelope);
  await assert.rejects(accept(envelope, signed, T0 + 900_000), /expired/u);
  await assert.rejects(accept(envelope, signed, T0 + 10 ** 9), /expired/u);
  await assert.doesNotReject(accept(envelope, signed, T0 + 899_999));
});

test('replay: one consumption key per request, whatever the nonce or challenge', async () => {
  const first = await issue(), second = await issueChallenge({ proposal: await proposal(), installation, now: T0 + 5,
    random: new Uint8Array(32).fill(8), signingKey: await importSigningKey(V.pkcs8), keyVersion: 1 });
  assert.notEqual(first.challenge.id, second.challenge.id);
  assert.equal(await consumeKey(first.challenge), await consumeKey(second.challenge));
  const other = await issue({ request: `request:${'b'.repeat(64)}` });
  assert.notEqual(await consumeKey(first.challenge), await consumeKey(other.challenge));
  // Two acts for the same request carry different act digests: the ledger's create-once claim admits one.
  const a = await accept(first, await act(first)), b = await accept(first, await act(first, 'decline'));
  assert.notEqual(a.actDigest, b.actDigest);
});

test('approver records: only a record proving its own attested key for this origin loads', async () => {
  await assert.doesNotReject(parseApprover(phone.register({ installation }), installation));
  await assert.rejects(parseApprover(phone.register({ installation, from: 'https://evil.example' }), installation), /not created on this origin/u);
  await assert.rejects(parseApprover(phone.register({ installation, rp: 'evil.example' }), installation), /another site/u);
  await assert.rejects(parseApprover(phone.register({ installation, uv: false }), installation), /verification required/u);
  await assert.rejects(parseApprover(phone.register({ installation, crossOrigin: true }), installation), /not created on this origin/u);
  const swapped = { ...phone.register({ installation }), publicKey: softAuthenticator({ rpId: 'x', origin: 'y' }).publicKey };
  await assert.rejects(parseApprover(swapped, installation), /stated key differs/u);
  const moved = parseInstallation({ ...installation, origin: 'https://jkheadley.github.io', rpId: 'jkheadley.github.io' });
  await assert.rejects(parseApprover(phone.register({ installation }), moved), /another installation or origin/u);
});

test('emergency stop: only the principal requests it, and it has no decline', async () => {
  const stop = await issue({ action: 'emergency-stop', subject: { kind: 'stop' }, requestedBy: installation.principal });
  assert.equal((await render(stop.challenge, null)).decline, null);
  await assert.rejects(accept(stop, await act(stop, 'decline')), /no decline/u);
  assert.equal((await accept(stop, await act(stop))).decision, 'approve');
  await assert.rejects(issue({ action: 'emergency-stop', subject: { kind: 'stop' } }), /requester differs/u);
  await assert.rejects(issue({ requestedBy: installation.principal }), /requester differs/u);
});
