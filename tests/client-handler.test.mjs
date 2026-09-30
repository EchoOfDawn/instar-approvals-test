// R2-MF2: the page's real confirm handler (app.js), driven with a synthetic DOM and a software passkey.
// Signing, delivery and acceptance are separate states: "sent" only after the return address confirmed
// receipt, and acceptance is never claimed by the page (the verifier records it).
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { softAuthenticator } from './soft-authenticator.mjs';

const TREE = process.env.TREE ?? join(import.meta.dirname, '..');
const C = await import(pathToFileURL(join(TREE, 'core.mjs')).href);
const T0 = 1_790_000_000_000;
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const installation = C.parseInstallation({ type: 'InstarApprovalInstallation', v: 1, installation: 'approvals', origin: 'https://human.github.io',
  rpId: 'human.github.io', repository: 'Human/approvals', principal: 'github:human',
  verifierKeys: [{ version: 1, publicKey: C.b64u(publicKey.export({ format: 'der', type: 'spki' })) }] });
const proposal = { type: 'InstarApprovalProposal', v: 1, installation: 'approvals', action: 'raise-caps', subject: { kind: 'model-calls', from: 1, to: 2 },
  base: await C.digest('base'), artifact: await C.digest('artifact'), request: `request:${'a'.repeat(64)}`, requestedBy: 'agent:echo',
  noteDigest: await C.digest(''), lifetimeMs: 600_000 };
const envelope = await C.issueChallenge({ proposal, installation, now: T0, random: new Uint8Array(32),
  signingKey: await C.importSigningKey(C.b64u(privateKey.export({ format: 'der', type: 'pkcs8' }))), keyVersion: 1 });
let run = 0;

/** Loads app.js at a #c= link (optionally with &r=), taps Approve, and reports POSTs and what the page said. */
async function approveAt({ returnUrl, postStatus = 200 }) {
  const elements = new Map();
  const elem = id => { if (!elements.has(id)) elements.set(id, { hidden: true, textContent: '', value: '', disabled: false, replaceChildren() {} }); return elements.get(id); };
  const phone = softAuthenticator({ rpId: installation.rpId, origin: installation.origin });
  const seen = { posts: 0, sayingWhilePosting: null, sayingWhileSigning: null };
  const saved = { document: globalThis.document, window: globalThis.window, location: globalThis.location, fetch: globalThis.fetch, now: Date.now };
  globalThis.document = { getElementById: elem, querySelectorAll: () => [elem('approve'), elem('decline')], createElement: () => ({}) };
  globalThis.window = {}; globalThis.window.top = globalThis.window; globalThis.window.self = globalThis.window;
  const hash = `c=${encodeURIComponent('https://relay.example/challenge')}${returnUrl ? `&r=${encodeURIComponent(returnUrl)}` : ''}`;
  globalThis.location = new URL(`https://human.github.io/approvals/#${hash}`);
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: { get: async ({ publicKey: options }) => {
    seen.sayingWhileSigning = elem('result').textContent;
    const a = phone.assert(options.challenge);
    return { id: a.credentialId, response: { clientDataJSON: C.fromB64u(a.clientDataJSON), authenticatorData: C.fromB64u(a.authenticatorData), signature: C.fromB64u(a.signature) } };
  } } } });
  globalThis.fetch = async (url, init = {}) => {
    if (init.method === 'POST') { seen.posts++; seen.sayingWhilePosting = elem('result').textContent; return new Response('', { status: postStatus }); }
    return new Response(JSON.stringify(new URL(url).pathname.endsWith('installation.json') ? installation : envelope), { status: 200 });
  };
  Date.now = () => T0 + 1000;
  try {
    await import(`${pathToFileURL(join(TREE, 'app.js')).href}?run=${run++}`);
    for (let i = 0; !elem('approve').onclick && i < 200; i++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ok(elem('approve').onclick, `the page refused: ${elem('error-text').textContent}`);
    await elem('approve').onclick();
  } finally {
    Object.assign(globalThis, { document: saved.document, window: saved.window, location: saved.location, fetch: saved.fetch }); Date.now = saved.now;
  }
  return { ...seen, result: elem('result').textContent, copyBox: !elem('act-box').hidden, signed: elem('act-out').value };
}

test('R2-MF2: with no return address nothing is sent, and the page says so and shows the decision to copy', async () => {
  const page = await approveAt({});
  assert.equal(page.posts, 0);
  assert.doesNotMatch(page.result, /and sent|sent:/iu);
  assert.match(page.result, /^Signed: approved\. Not sent/u);
  assert.match(page.result, /copy/iu);
  assert.equal(page.copyBox, true);
  assert.match(page.signed, /InstarApprovalAct/u);
});

test('R2-MF2: "sent" only after the return address confirms receipt; signing and sending are shown as separate steps', async () => {
  const page = await approveAt({ returnUrl: 'https://relay.example/return' });
  assert.equal(page.posts, 1);
  assert.match(page.sayingWhileSigning, /passkey/iu);
  assert.doesNotMatch(page.sayingWhileSigning, /Signed/u);
  assert.match(page.sayingWhilePosting, /^Signed: approved\. Sending/u);
  assert.match(page.result, /^Signed and sent: approved\./u);
  assert.match(page.result, /not recorded yet/iu, 'acceptance is not claimed');
  assert.equal(page.copyBox, false);
});

test('R2-MF2: a refused delivery is reported as signed but not sent, with the decision to copy', async () => {
  const page = await approveAt({ returnUrl: 'https://relay.example/return', postStatus: 502 });
  assert.equal(page.posts, 1);
  assert.match(page.result, /^Signed, but not delivered \(the return address answered 502\)/u);
  assert.equal(page.copyBox, true);
});
