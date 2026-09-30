// The phone approval client. Static, same-origin, no third-party code, nothing loaded from the agent.
// Modes (by URL fragment, never sent to any server): #enrol, #setup, #c=<challenge URL>[&n=<note URL>][&r=<return URL>].
import { approverRecord, actChallenge, b64u, canonical, digest, fetchBounded, openChallenge, parseInstallation, render, resultText } from './core.mjs';

const $ = id => document.getElementById(id);
const show = (id, on = true) => { $(id).hidden = !on; };
const say = (id, text) => { $(id).textContent = text; };
const params = new URLSearchParams(location.hash.slice(1));
const mode = location.hash === '#enrol' ? 'enrol' : location.hash === '#setup' ? 'setup' : params.has('c') ? 'confirm' : 'home';
const random = n => crypto.getRandomValues(new Uint8Array(n));
// GitHub prefills a NEW file from ?filename=&value= (tested); an edit of an existing file ignores ?value=.
const newFileLink = (repository, directory, name, value) =>
  `https://github.com/${repository}/new/main${directory ? `/${directory}` : ''}?filename=${encodeURIComponent(name)}&value=${encodeURIComponent(value)}`;

async function loadInstallation() {
  const installation = parseInstallation(await fetchBounded(new URL('installation.json', location.href).href, 'installation'));
  // The origin and rpId are pinned in the operator's record; a page served anywhere else refuses.
  if (location.origin !== installation.origin || location.hostname !== installation.rpId) throw new Error('this page is not at the installed origin; re-enrolment is required');
  return installation;
}

async function enrol() {
  const installation = await loadInstallation();
  say('enrol-where', `Approver for ${installation.installation} (${installation.principal}).`);
  $('enrol-go').onclick = async () => {
    try {
      $('enrol-go').disabled = true;
      const credential = await navigator.credentials.create({ publicKey: { challenge: random(32), rp: { id: installation.rpId, name: 'Instar approvals' },
        user: { id: random(16), name: installation.principal, displayName: 'Instar approver' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { userVerification: 'required', residentKey: 'required' }, attestation: 'none', timeout: 120000 } });
      const record = await approverRecord(installation, credential);
      const name = `${(await digest(record.credentialId)).slice(7, 23)}.json`;
      const link = newFileLink(installation.repository, 'approvers', name, `${JSON.stringify(record, null, 2)}\n`);
      $('enrol-save').href = link;
      show('enrol-done');
      say('enrol-result', 'Passkey created on this device. Now save it to your approvals repository.');
    } catch (error) { $('enrol-go').disabled = false; say('enrol-result', `Not added: ${error.message}`); }
  };
}

async function setup() {
  // The owner's one-time verifier key, generated in this browser. The private half goes only to the
  // repository secret form by the owner's own paste; this page sends it nowhere.
  const repository = location.pathname.split('/').filter(Boolean)[0];
  const owner = location.hostname.split('.')[0];
  // The key exists before any tap, so ONE tap both copies it (inside the tap, as browsers require) and opens
  // GitHub's secret form in a new tab. The supported origin is a user site, <login>.github.io, so the
  // hostname names the custodian's GitHub login.
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const secret = b64u(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const installation = { type: 'InstarApprovalInstallation', v: 1, installation: repository, origin: location.origin, rpId: location.hostname,
    repository: `${owner}/${repository}`, principal: `github:${owner}`,
    verifierKeys: [{ version: 1, publicKey: b64u(await crypto.subtle.exportKey('spki', pair.publicKey)) }] };
  parseInstallation(installation);
  $('setup-secret').value = secret;
  $('setup-secret-link').href = `https://github.com/${owner}/${repository}/settings/secrets/actions/new`;
  $('setup-secret-link').onclick = () => { navigator.clipboard.writeText(secret).then(() => say('setup-copied', 'Key copied.'), () => say('setup-copied', 'Copy the key above by hand.')); };
  $('setup-install-link').href = newFileLink(`${owner}/${repository}`, '', 'installation.json', `${JSON.stringify(installation, null, 2)}\n`);
  $('setup-ruleset-link').href = `https://github.com/${owner}/${repository}/settings/rules`;
}

async function confirm() {
  const installation = await loadInstallation();
  // Fetched once and frozen: what is shown is exactly what is signed. A change needs a fresh page.
  const envelope = await fetchBounded(params.get('c'), 'request');
  const challenge = await openChallenge(envelope, installation);
  const note = params.has('n') ? (await fetchBounded(params.get('n'), 'note')).note : null;
  const view = await render(challenge, note);
  if (Date.now() >= challenge.expiresAt) throw new Error('this request has expired');
  say('title', view.title); say('effect', view.effect);
  $('facts').replaceChildren(...view.facts.map(([key, value]) => { const row = document.createElement('li'); row.textContent = `${key}: ${value}`; return row; }));
  if (view.note !== null) { say('note', view.note); show('note-box'); }
  say('approve', view.approve);
  if (view.decline === null) show('decline', false); else say('decline', view.decline);
  show('confirm');
  const frozen = canonical(challenge);
  const act = async decision => {
    let signed = null;
    const tell = (delivery, error) => say('result', resultText({ decision, action: challenge.action, signed: signed !== null, delivery, error }));
    try {
      for (const button of document.querySelectorAll('#confirm button')) button.disabled = true;
      if (canonical(challenge) !== frozen) throw new Error('the request changed; reload to confirm again');
      const nonce = b64u(random(32));
      const expected = await actChallenge(challenge, decision, nonce);
      say('result', 'Waiting for your passkey...');
      const credential = await navigator.credentials.get({ publicKey: { challenge: expected, rpId: installation.rpId, userVerification: 'required', timeout: 120000 } });
      signed = { type: 'InstarApprovalAct', v: 1, challengeId: challenge.id, decision, nonce, assertion: {
        credentialId: credential.id, clientDataJSON: b64u(credential.response.clientDataJSON),
        authenticatorData: b64u(credential.response.authenticatorData), signature: b64u(credential.response.signature) } };
      $('act-out').value = JSON.stringify(signed);
      // "Sent" is claimed only after the return address confirmed receipt; with none, the owner sends it.
      let delivery = 'manual';
      if (params.has('r')) {
        const target = new URL(params.get('r'));
        if (target.protocol !== 'https:') throw new Error('return address must be HTTPS');
        tell('sending');
        const response = await fetch(target, { method: 'POST', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15_000), headers: { 'content-type': 'application/json' }, body: JSON.stringify(signed) });
        if (!response.ok) throw new Error(`the return address answered ${response.status}`);
        delivery = 'sent';
      }
      tell(delivery);
      show('act-box', delivery !== 'sent');
    } catch (error) {
      tell('failed', error.message);
      show('act-box', signed !== null);
    }
  };
  $('approve').onclick = () => act('approve');
  $('decline').onclick = () => act('decline');
}

(async () => {
  // Never inside another page's frame: the ceremony belongs to this origin's top-level page only.
  if (window.top !== window.self) { document.body.textContent = 'Refused: this page cannot run inside another page.'; return; }
  if (mode !== 'confirm') show(mode); else show('recovery', false);
  try { await ({ enrol, setup, confirm, home: async () => {} })[mode](); }
  catch (error) { say('error-text', `Refused: ${error.message}`); show('error'); show('confirm', false); }
})();
