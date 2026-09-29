// Craft acts with the ENROLLED test passkey (exported from the virtual authenticator) or a stranger key,
// under deliberately wrong conditions, to prove the live verifier refuses each one.
//   node tests/craft-act.mjs <state-dir> <challenge-id-hex> <case> > act.json
// cases: good | wrong-origin | wrong-rpid | cross-origin | no-uv | unknown-key
import { createHash, createPrivateKey, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { actChallenge, b64u } from '../core.mjs';
import { softAuthenticator } from './soft-authenticator.mjs';
const [state, id, which] = process.argv.slice(2);
const envelope = await (await fetch(`https://raw.githubusercontent.com/EchoOfDawn/instar-approvals-test/ledger/challenges/${id}.json`)).json();
const nonce = b64u(randomBytes(32)), expected = await actChallenge(envelope.challenge, 'approve', nonce);
const RP = 'echoofdawn.github.io', ORIGIN = 'https://echoofdawn.github.io';
let assertion;
if (which === 'unknown-key') assertion = softAuthenticator({ rpId: RP, origin: ORIGIN }).assert(expected);
else {
  const credential = JSON.parse(readFileSync(`${state}/credential.json`, 'utf8'));
  const key = createPrivateKey({ key: Buffer.from(credential.privateKey, 'base64'), format: 'der', type: 'pkcs8' });
  const sha = data => createHash('sha256').update(data).digest();
  const rp = which === 'wrong-rpid' ? 'localhost' : RP, flags = which === 'no-uv' ? 0x01 : 0x05;
  const data = { type: 'webauthn.get', challenge: b64u(expected), origin: which === 'wrong-origin' ? 'https://echoofdawn.github.io.attacker.example' : ORIGIN,
    crossOrigin: which === 'cross-origin' };
  const auth = Buffer.concat([sha(rp), Buffer.from([flags]), Buffer.from([0, 0, 0, 9])]), client = Buffer.from(JSON.stringify(data));
  assertion = { credentialId: b64u(Buffer.from(credential.credentialId, 'base64')), clientDataJSON: b64u(client), authenticatorData: b64u(auth),
    signature: b64u(sign('sha256', Buffer.concat([auth, sha(client)]), key)) };
}
console.log(JSON.stringify({ type: 'InstarApprovalAct', v: 1, challengeId: envelope.challenge.id, decision: 'approve', nonce, assertion }, null, 2));
