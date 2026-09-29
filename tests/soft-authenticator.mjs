// A software WebAuthn authenticator for tests: a P-256 key producing real registration and assertion bytes.
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { b64u } from '../core.mjs';

const sha = data => createHash('sha256').update(data).digest();
const cbor = { bytes: b => Buffer.concat([Buffer.from([0x58, b.length]), b]) };

export function softAuthenticator({ rpId, origin, privateKey: given }) {
  const { privateKey, publicKey } = given ? { privateKey: given, publicKey: createPublicKey(given) } : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ format: 'der', type: 'spki' }), point = spki.subarray(26);
  const id = Buffer.from(sha(spki).subarray(0, 16));
  const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]), cbor.bytes(point.subarray(1, 33)),
    Buffer.from([0x22]), cbor.bytes(point.subarray(33))]);
  const flags = (up, uv, at) => (up ? 1 : 0) | (uv ? 4 : 0) | (at ? 0x40 : 0);
  return {
    credentialId: b64u(id), publicKey: b64u(spki),
    register({ installation, rp = rpId, from = origin, uv = true, crossOrigin = false }) {
      const auth = Buffer.concat([sha(rp), Buffer.from([flags(true, uv, true)]), Buffer.alloc(4), Buffer.alloc(16),
        Buffer.from([0, id.length]), id, cose]);
      const clientDataJSON = JSON.stringify({ type: 'webauthn.create', challenge: b64u(sha('enrol')), origin: from, crossOrigin });
      return { type: 'InstarApprover', v: 1, installation: installation.installation, principal: installation.principal, origin: installation.origin,
        rpId: installation.rpId, credentialId: b64u(id), alg: -7, publicKey: b64u(spki), clientDataJSON: b64u(Buffer.from(clientDataJSON)),
        authenticatorData: b64u(auth) };
    },
    assert(challengeBytes, { rp = rpId, from = origin, uv = true, up = true, type = 'webauthn.get', crossOrigin = false, topOrigin } = {}) {
      const auth = Buffer.concat([sha(rp), Buffer.from([flags(up, uv, false)]), Buffer.from([0, 0, 0, 1])]);
      const data = { type, challenge: b64u(challengeBytes), origin: from, crossOrigin };
      if (topOrigin !== undefined) data.topOrigin = topOrigin;
      const client = Buffer.from(JSON.stringify(data));
      return { credentialId: b64u(id), clientDataJSON: b64u(client), authenticatorData: b64u(auth),
        signature: b64u(sign('sha256', Buffer.concat([auth, sha(client)]), privateKey)) };
    },
  };
}
