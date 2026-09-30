// Shared, dependency-free core of the phone approval client and its external verifier.
// The same bytes run in the operator's browser (loaded from this repository's own Pages origin) and in
// the verifier workflow on a GitHub-hosted runner (loaded from the trusted base branch). Web Crypto only.
// It ports the preview approval surface's approach (closed challenge, fixed rendering, the passkey signs
// SHA-256 of {whole challenge, decision, fresh nonce}) to an external, operator-owned verifier.

export const LIMITS = Object.freeze({ maxLifetimeMs: 86_400_000, minLifetimeMs: 60_000, maxBody: 16_384,
  maxNote: 2_000, maxField: 200, maxKeys: 8, maxInt: 1_000_000_000, skewMs: 120_000 });
export const SURFACE = 'instar-approvals';
/** A deliberate refusal. Its message is a fixed, safe sentence written here, never a copy of input, so it
 * may appear in public logs and comments. Any other error is reported only as a fixed code (safeReason). */
export class Refusal extends Error {}
export const check = (condition, detail) => { if (!condition) throw new Refusal(detail); };
export const safeReason = error => error instanceof Refusal ? error.message.slice(0, 200)
  : error instanceof SyntaxError ? 'malformed input' : 'unexpected error';

const subtle = globalThis.crypto.subtle;
const sorted = value => Array.isArray(value) ? value.map(sorted) : value !== null && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
/** Key-sorted JSON: browser and verifier hash exactly the same bytes for the same object. */
export const canonical = value => JSON.stringify(sorted(value));
export const utf8 = text => new TextEncoder().encode(text);
export const sha256 = async bytes => new Uint8Array(await subtle.digest('SHA-256', typeof bytes === 'string' ? utf8(bytes) : bytes));
export const toHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
export const digest = async value => `sha256:${toHex(await sha256(typeof value === 'string' ? value : canonical(value)))}`;
export const b64u = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
export const fromB64u = text => {
  check(typeof text === 'string' && text.length > 0 && text.length <= 8192 && /^[A-Za-z0-9_-]+$/u.test(text), 'base64url field required');
  const plain = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4));
  return Uint8Array.from(plain, c => c.charCodeAt(0));
};
const equalBytes = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);
const closed = (value, fields, what) => {
  check(value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(','), `closed ${what} required`);
  return value;
};
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const ID = /^[a-z][a-z0-9-]{0,62}(:[A-Za-z0-9._-]{1,128})?$/u;
const text = (value, what, max = LIMITS.maxField) => { check(typeof value === 'string' && value.length > 0 && value.length <= max, `${what} invalid`); return value; };
const int = (value, what) => { check(Number.isSafeInteger(value) && value >= 0 && value <= LIMITS.maxInt, `${what} invalid`); return value; };

// ---------------------------------------------------------------- installation (operator-owned record)
const INSTALLATION = ['type', 'v', 'installation', 'origin', 'rpId', 'repository', 'principal', 'verifierKeys'];
/** The operator's pinned installation: HTTPS origin, rpId, repository and the verifier's public keys. An
 * origin change means a new installation and a new enrolment. */
export function parseInstallation(value) {
  closed(value, INSTALLATION, 'installation');
  check(value.type === 'InstarApprovalInstallation' && value.v === 1, 'installation type invalid');
  check(ID.test(value.installation) && ID.test(value.principal), 'installation id or principal invalid');
  check(/^[a-z0-9.-]{1,253}$/u.test(value.rpId) && value.origin === `https://${value.rpId}`, 'origin must be https://<rpId>');
  check(/^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/u.test(value.repository), 'repository invalid');
  check(Array.isArray(value.verifierKeys) && value.verifierKeys.length >= 1 && value.verifierKeys.length <= 4, 'verifier keys invalid');
  for (const key of value.verifierKeys) {
    closed(key, ['version', 'publicKey'], 'verifier key');
    check(Number.isSafeInteger(key.version) && key.version > 0, 'verifier key version invalid');
    fromB64u(key.publicKey);
  }
  return value;
}

// ---------------------------------------------------------------- proposals and challenges
/** Actions this client can render. Anything else is refused, never shown as a generic prompt. */
const KINDS = { 'model-calls': ['model call', 'model calls I may spend'], replies: ['reply', 'replies I may send'], messages: ['message', 'messages I may take'] };
function checkSubject(action, subject) {
  if (action === 'raise-caps') {
    closed(subject, ['kind', 'from', 'to'], 'raise subject');
    check(Object.hasOwn(KINDS, subject.kind), 'raise kind unsupported');
    check(int(subject.to, 'to') > int(subject.from, 'from'), 'a raise must increase the allowance');
    return;
  }
  if (action === 'emergency-stop') { closed(subject, ['kind'], 'stop subject'); check(subject.kind === 'stop', 'stop kind invalid'); return; }
  throw new Refusal('unsupported action');
}
const PROPOSAL = ['type', 'v', 'installation', 'action', 'subject', 'base', 'artifact', 'request', 'requestedBy', 'noteDigest', 'lifetimeMs'];
/** The agent's bounded proposal. It carries no prose: requester prose travels privately and is bound by
 * its digest. */
export function parseProposal(value) {
  closed(value, PROPOSAL, 'proposal');
  check(value.type === 'InstarApprovalProposal' && value.v === 1, 'proposal type invalid');
  check(ID.test(value.installation), 'installation invalid');
  checkSubject(value.action, value.subject);
  for (const field of ['base', 'artifact', 'noteDigest']) check(DIGEST.test(value[field]), `${field} digest invalid`);
  check(/^request:[a-f0-9]{64}$/u.test(value.request), 'request id must be opaque');
  check(ID.test(value.requestedBy), 'requester invalid');
  check(Number.isSafeInteger(value.lifetimeMs) && value.lifetimeMs >= LIMITS.minLifetimeMs && value.lifetimeMs <= LIMITS.maxLifetimeMs, 'lifetime invalid');
  return value;
}
const CHALLENGE = ['type', 'v', 'id', 'surface', 'installation', 'origin', 'rpId', 'principal', 'action', 'subject', 'base', 'artifact',
  'request', 'requestedBy', 'noteDigest', 'issuedAt', 'expiresAt', 'singleUse', 'keyVersion'];
export function checkChallenge(challenge, installation) {
  closed(challenge, CHALLENGE, 'challenge');
  check(challenge.type === 'InstarApprovalChallenge' && challenge.v === 1 && challenge.surface === SURFACE && challenge.singleUse === true, 'challenge type invalid');
  check(/^challenge:[a-f0-9]{64}$/u.test(challenge.id), 'challenge id invalid');
  check(challenge.installation === installation.installation && challenge.origin === installation.origin && challenge.rpId === installation.rpId
    && challenge.principal === installation.principal, 'challenge names another installation, origin or principal');
  checkSubject(challenge.action, challenge.subject);
  // The emergency stop is the operator's own request; every other action is requested by someone else.
  check(challenge.action === 'emergency-stop' ? challenge.requestedBy === challenge.principal : challenge.requestedBy !== challenge.principal,
    'requester differs from the action rule');
  for (const field of ['base', 'artifact', 'noteDigest']) check(DIGEST.test(challenge[field]), `${field} digest invalid`);
  check(/^request:[a-f0-9]{64}$/u.test(challenge.request), 'request id invalid');
  check(Number.isSafeInteger(challenge.issuedAt) && Number.isSafeInteger(challenge.expiresAt) && challenge.expiresAt > challenge.issuedAt
    && challenge.expiresAt - challenge.issuedAt <= LIMITS.maxLifetimeMs, 'challenge lifetime invalid');
  check(Number.isSafeInteger(challenge.keyVersion), 'key version invalid');
  return challenge;
}

// ---------------------------------------------------------------- the verifier's own signatures
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }, SIGN = { name: 'ECDSA', hash: 'SHA-256' };
export const importSigningKey = pkcs8 => subtle.importKey('pkcs8', fromB64u(pkcs8), ECDSA, false, ['sign']);
const verifierKey = (installation, version) => {
  const key = installation.verifierKeys.find(item => item.version === version);
  check(key !== undefined, 'verifier key version unknown');
  return subtle.importKey('spki', fromB64u(key.publicKey), ECDSA, false, ['verify']);
};
/** The installation key version whose public half matches this secret (not the challenge's, not the highest). */
export async function signingVersion(signingKey, installation) {
  const probe = utf8('instar-approvals signing-key probe'), signature = await subtle.sign(SIGN, signingKey, probe);
  for (const { version } of installation.verifierKeys) if (await subtle.verify(SIGN, await verifierKey(installation, version), signature, probe)) return version;
  throw new Refusal('the verifier signing key is not listed in installation.json');
}
const signed = async (field, body, key) => ({ [field]: body, signature: b64u(await subtle.sign(SIGN, key, utf8(canonical(body)))) });
async function checkSigned(envelope, field, installation) {
  closed(envelope, [field, 'signature'], `signed ${field}`);
  const body = envelope[field];
  check(body !== null && typeof body === 'object' && Number.isSafeInteger(body.keyVersion), `${field} key version missing`);
  check(await subtle.verify(SIGN, await verifierKey(installation, body.keyVersion), fromB64u(envelope.signature), utf8(canonical(body))),
    `${field} is not signed by this installation's verifier`);
  return body;
}

/** Verifier: turn a bounded proposal into a signed, short-lived, single-use challenge (its own clock). */
export async function issueChallenge({ proposal, installation, now, random, signingKey, keyVersion }) {
  parseProposal(proposal);
  check(proposal.installation === installation.installation, 'proposal names another installation');
  check(proposal.action === 'emergency-stop' ? proposal.requestedBy === installation.principal : proposal.requestedBy !== installation.principal,
    'requester differs from the action rule');
  const id = `challenge:${toHex(await sha256(canonical({ proposal, now, random: b64u(random) })))}`;
  const challenge = { type: 'InstarApprovalChallenge', v: 1, id, surface: SURFACE, installation: installation.installation,
    origin: installation.origin, rpId: installation.rpId, principal: installation.principal, action: proposal.action,
    subject: proposal.subject, base: proposal.base, artifact: proposal.artifact, request: proposal.request,
    requestedBy: proposal.requestedBy, noteDigest: proposal.noteDigest, issuedAt: now, expiresAt: now + proposal.lifetimeMs,
    singleUse: true, keyVersion };
  checkChallenge(challenge, installation);
  return signed('challenge', challenge, signingKey);
}
/** Both sides: an envelope is trusted only if the pinned verifier key signed exactly this challenge. */
export async function openChallenge(envelope, installation) {
  return checkChallenge(await checkSigned(envelope, 'challenge', installation), installation);
}

// ---------------------------------------------------------------- rendering (derived, never requester prose)
/** What the operator sees, derived only from the signed challenge. The requester's note is returned
 * separately and must be shown as plain, untrusted text. */
export async function render(challenge, note) {
  let title, effect, approve = 'Approve', decline = 'Decline';
  if (challenge.action === 'raise-caps') {
    const [one, effectText] = KINDS[challenge.subject.kind], { from, to } = challenge.subject;
    title = `Approve raising the ${one} allowance from ${from} to ${to}?`;
    effect = `That adds ${to - from} ${effectText} in this trial. Your saved messages are then answered. You can still stop the trial at any time.`;
  } else if (challenge.action === 'emergency-stop') {
    title = 'Sign a request to stop this preview agent?';
    effect = 'This signs a stop request. The independent verifier records it within about a minute, and the stop takes effect when '
      + 'the agent next checks for it. To stop immediately, send "stop" in Telegram; that works without this page.';
    approve = 'Sign stop request'; decline = null;
  } else throw new Refusal('unsupported action');
  let shownNote = null;
  if (note !== undefined && note !== null) {
    check(typeof note === 'string' && note.length <= LIMITS.maxNote, 'requester note too long');
    check(await digest(note) === challenge.noteDigest, 'requester note differs from the signed request');
    shownNote = note;
  }
  return { title, effect, approve, decline, note: shownNote,
    facts: [['Installation', challenge.installation], ['Approver', challenge.principal], ['Requested by', challenge.requestedBy],
      ['Expires', new Date(challenge.expiresAt).toUTCString()]] };
}

/** The exact bytes the passkey signs: the whole challenge, the decision and a fresh nonce (the preview
 * surface's act formula, unchanged). */
export const actChallenge = async (challenge, decision, nonce) =>
  sha256(canonical({ type: 'PreviewApprovalAct', schemaVersion: 1, challenge, decision, nonce }));

// ---------------------------------------------------------------- WebAuthn checks
function readCbor(bytes, start) { // the subset a COSE EC2 key uses: unsigned/negative ints, byte strings, maps
  let at = start;
  const item = () => {
    check(at < bytes.length, 'truncated COSE key');
    const head = bytes[at++], major = head >> 5, info = head & 31;
    let n = info;
    if (info === 24) n = bytes[at++]; else if (info === 25) { n = (bytes[at] << 8) | bytes[at + 1]; at += 2; } else check(info < 24, 'unsupported COSE encoding');
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2) { const value = bytes.slice(at, at + n); check(value.length === n, 'truncated COSE key'); at += n; return value; }
    if (major === 5) { check(n <= 8, 'COSE key too large'); const map = new Map(); for (let i = 0; i < n; i++) { const key = item(); map.set(key, item()); } return map; }
    throw new Refusal('unsupported COSE item');
  };
  const value = item();
  return { value, end: at };
}
const authenticatorData = async (bytes, rpId, required) => {
  check(bytes.length >= 37 && equalBytes(bytes.slice(0, 32), await sha256(rpId)), 'authenticator data names another site');
  check((bytes[32] & required) === required, 'user presence and verification required');
  return bytes;
};
const clientData = (encoded, type, expected, origin) => {
  const bytes = fromB64u(encoded), data = JSON.parse(new TextDecoder().decode(bytes));
  check(data?.type === type, 'client data type differs');
  check(data.challenge === b64u(expected), 'client data challenge differs');
  check(data.origin === origin, 'client data origin differs');
  check(data.crossOrigin !== true && data.topOrigin === undefined, 'cross-origin ceremony refused');
  return bytes;
};
const spkiPoint = spki => { check(spki.length === 91, 'P-256 public key required'); return spki.slice(26); };
/** DER ECDSA signature -> raw r||s for Web Crypto. */
function derToRaw(der) {
  check(der.length >= 8 && der[0] === 0x30 && der[1] === der.length - 2 && der[2] === 0x02, 'signature encoding invalid');
  const out = new Uint8Array(64); let at = 2;
  for (const offset of [0, 32]) {
    check(der[at] === 0x02, 'signature encoding invalid');
    const length = der[at + 1]; let value = der.slice(at + 2, at + 2 + length); at += 2 + length;
    while (value.length > 32 && value[0] === 0) value = value.slice(1);
    check(value.length <= 32, 'signature encoding invalid');
    out.set(value, offset + 32 - value.length);
  }
  check(at === der.length, 'signature encoding invalid');
  return out;
}

const APPROVER = ['type', 'v', 'installation', 'principal', 'origin', 'rpId', 'credentialId', 'alg', 'publicKey', 'clientDataJSON', 'authenticatorData'];
/** Client: the approver record, constructed locally from the browser's own credential. */
export async function approverRecord(installation, credential) {
  const record = { type: 'InstarApprover', v: 1, installation: installation.installation, principal: installation.principal,
    origin: installation.origin, rpId: installation.rpId, credentialId: credential.id, alg: credential.response.getPublicKeyAlgorithm(),
    publicKey: b64u(credential.response.getPublicKey()), clientDataJSON: b64u(credential.response.clientDataJSON),
    authenticatorData: b64u(credential.response.getAuthenticatorData()) };
  return parseApprover(record, installation);
}
/** Both sides: an approver is valid only if its own attested data proves an ES256 passkey created with user
 * verification for this origin and rpId, and the stated key is exactly the attested key. */
export async function parseApprover(record, installation) {
  closed(record, APPROVER, 'approver');
  check(record.type === 'InstarApprover' && record.v === 1 && record.alg === -7, 'ES256 approver required');
  check(record.installation === installation.installation && record.principal === installation.principal
    && record.origin === installation.origin && record.rpId === installation.rpId, 'approver enrolled for another installation or origin');
  const data = JSON.parse(new TextDecoder().decode(fromB64u(record.clientDataJSON)));
  check(data?.type === 'webauthn.create' && data.origin === installation.origin && data.crossOrigin !== true, 'approver was not created on this origin');
  const auth = await authenticatorData(fromB64u(record.authenticatorData), installation.rpId, 0x45);
  check(auth.length >= 55, 'attested credential data missing');
  const length = (auth[53] << 8) | auth[54], id = auth.slice(55, 55 + length);
  check(length > 0 && length <= 1023 && id.length === length && b64u(id) === record.credentialId, 'credential id differs');
  const cose = readCbor(auth, 55 + length).value;
  check(cose instanceof Map && cose.get(1) === 2 && cose.get(3) === -7 && cose.get(-1) === 1, 'attested key is not ES256');
  const point = spkiPoint(fromB64u(record.publicKey));
  check(point[0] === 4 && equalBytes(point.slice(1, 33), cose.get(-2)) && equalBytes(point.slice(33), cose.get(-3)), 'stated key differs from the attested key');
  return record;
}

const ACT = ['type', 'v', 'challengeId', 'decision', 'nonce', 'assertion'];
const ASSERTION = ['credentialId', 'clientDataJSON', 'authenticatorData', 'signature'];
export function parseAct(value) {
  closed(value, ACT, 'act');
  check(value.type === 'InstarApprovalAct' && value.v === 1, 'act type invalid');
  check(/^challenge:[a-f0-9]{64}$/u.test(value.challengeId), 'challenge id invalid');
  check(value.decision === 'approve' || value.decision === 'decline', 'decision must be approve or decline');
  check(fromB64u(value.nonce).length >= 16 && fromB64u(value.nonce).length <= 64, 'fresh nonce required');
  closed(value.assertion, ASSERTION, 'assertion');
  for (const field of ASSERTION) fromB64u(value.assertion[field]);
  return value;
}
/** One enrolled passkey's WebAuthn assertion over exactly `expected`. Returns the approver. */
export async function verifyAssertion({ approvers, installation, expected, assertion }) {
  const approver = approvers.find(item => item.credentialId === assertion.credentialId);
  check(approver !== undefined, 'passkey not enrolled');
  const client = clientData(assertion.clientDataJSON, 'webauthn.get', expected, installation.origin);
  const auth = await authenticatorData(fromB64u(assertion.authenticatorData), installation.rpId, 0x05);
  const key = await subtle.importKey('spki', fromB64u(approver.publicKey), ECDSA, false, ['verify']);
  const message = new Uint8Array([...auth, ...await sha256(client)]);
  check(await subtle.verify(SIGN, key, derToRaw(fromB64u(assertion.signature)), message), 'passkey signature invalid');
  return approver;
}

/** Durable, semantic consumption key: one effect per (installation, request), whatever the nonce. */
export const consumeKey = async challenge => toHex(await sha256(`${challenge.installation}\n${challenge.request}`));

/** Verifier: check an act against the challenge the verifier itself issued (read from its own ledger,
 * never from the submission). Returns the receipt body to record, before consumption. */
export async function acceptAct({ envelope, act, approvers, installation, now, approversRef }) {
  parseAct(act);
  const challenge = await openChallenge(envelope, installation);
  check(act.challengeId === challenge.id, 'act names another challenge');
  check(now < challenge.expiresAt, 'challenge expired');
  check(challenge.issuedAt <= now + LIMITS.skewMs, 'challenge issued in the future');
  check(challenge.action !== 'emergency-stop' || act.decision === 'approve', 'a stop has no decline');
  const expected = await actChallenge(challenge, act.decision, act.nonce);
  const approver = await verifyAssertion({ approvers, installation, expected, assertion: act.assertion });
  return { type: 'InstarApprovalReceipt', v: 1, installation: installation.installation, challengeId: challenge.id,
    challengeDigest: await digest(challenge), request: challenge.request, decision: act.decision, credentialId: approver.credentialId,
    approverDigest: await digest(approver), approversRef, actDigest: await digest(act), verifiedAt: now, challengeKeyVersion: challenge.keyVersion };
}
/** The receipt names the key version that actually signs it; the challenge's own version is kept separately. */
export const signReceipt = (receipt, signingKey, keyVersion) => signed('receipt', { ...receipt, keyVersion }, signingKey);
/** Runner / effect owner: a receipt counts only if the pinned verifier key signed it. The effect owner
 * must still recheck current authority, scope and base against its own governing state. */
export const openReceipt = (envelope, installation) => checkSigned(envelope, 'receipt', installation);

// ---------------------------------------------------------------- bounded reads of untrusted feeds (client)
/** Fetch JSON from an untrusted HTTPS address: no credentials, no redirects, a byte ceiling enforced while
 * reading (the stream is cancelled the moment it is exceeded) and one deadline covering connect and read. */
export async function fetchBounded(url, what, { maxBytes = LIMITS.maxBody, timeoutMs = 15_000, fetchImpl = globalThis.fetch } = {}) {
  let target;
  try { target = new URL(url); } catch { throw new Refusal(`${what} address is invalid`); }
  check(target.protocol === 'https:', `${what} must be fetched over HTTPS`);
  const controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Refusal(`${what} took too long`)); }, timeoutMs); });
  let reader;
  try {
    const response = await Promise.race([fetchImpl(target, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal }), deadline]);
    check(response.ok, `${what} could not be fetched`);
    check(response.body, `${what} is empty`);
    reader = response.body.getReader();
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      total += value.byteLength;
      check(total <= maxBytes, `${what} is too large`);
      chunks.push(value);
    }
    const bytes = new Uint8Array(total); let at = 0;
    for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Refusal(`${what} is not valid JSON`); }
  } catch (error) {
    reader?.cancel().catch(() => {});
    controller.abort();
    throw error instanceof Refusal ? error : new Refusal(`${what} could not be fetched`);
  } finally { clearTimeout(timer); }
}

// ---------------------------------------------------------------- what the page says after a tap (client)
/** Not signed, signed (sending, sent, not delivered, or left for the owner to send), never merged. */
export function resultText({ decision, action, signed, delivery, error }) {
  // Three separate states: signed (on this device), sent (the return address confirmed receipt), recorded (the
  // verifier's acceptance, which this page never observes and so never claims).
  if (!signed) return `Not signed: ${error}`;
  const what = action === 'emergency-stop' ? 'stop request' : decision === 'approve' ? 'approved' : 'declined';
  const stopNow = action === 'emergency-stop' ? ' To stop immediately, send "stop" in Telegram.' : '';
  if (delivery === 'sending') return `Signed: ${what}. Sending...`;
  if (delivery === 'failed') return `Signed, but not delivered (${error}). Copy the signed decision below and send it back.${stopNow}`;
  if (delivery !== 'sent') return `Signed: ${what}. Not sent yet. Copy the signed decision below and send it back. Nothing is recorded until the verifier accepts it.${stopNow}`;
  if (decision === 'decline' && action !== 'emergency-stop') return 'Signed and sent: declined. Nothing will change.';
  return `Signed and sent: ${what}. The return address confirmed receipt; not recorded yet, the independent verifier records it next.${stopNow}`;
}
