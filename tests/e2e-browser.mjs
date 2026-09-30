// End-to-end driver on the real test origin with Chrome's virtual (software) authenticator.
//   node tests/e2e-browser.mjs enrol <state-dir>
//   node tests/e2e-browser.mjs confirm <state-dir> <approve|decline> <page-fragment> [--frame-from <origin>]
// Needs PLAYWRIGHT pointing at a playwright-core index.mjs. The test credential lives in <state-dir>.
import { readFileSync, writeFileSync } from 'node:fs';
const { chromium } = await import(process.env.PLAYWRIGHT);
const [mode, state, decision, fragment] = process.argv.slice(2);
const PAGE = process.env.PAGE ?? 'https://echoofdawn.github.io/instar-approvals-test/';

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, serviceWorkers: 'block' });
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
const report = {};
if (process.env.LOCAL_SITE) { // serve a faithful copy of this repository from another HTTPS origin (PAGE)
  const types = { html: 'text/html', js: 'text/javascript', mjs: 'text/javascript', css: 'text/css', json: 'application/json' };
  await context.route(`${PAGE}**`, route => { const path = new URL(route.request().url()).pathname.slice(1) || 'index.html';
    try { route.fulfill({ status: 200, contentType: types[path.split('.').pop()] ?? 'text/plain', body: readFileSync(`${process.env.LOCAL_SITE}/${path}`) }); }
    catch { route.fulfill({ status: 404, body: '' }); } });
}
page.on('console', message => { if (message.type() === 'error') (report.console ??= []).push(message.text().slice(0, 200)); });

if (mode === 'enrol') {
  await page.goto(`${PAGE}#enrol`);
  await page.click('#enrol-go');
  await page.waitForSelector('#enrol-done:not([hidden])', { timeout: 20000 });
  report.result = await page.textContent('#enrol-result');
  report.saveLink = await page.getAttribute('#enrol-save', 'href');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  writeFileSync(`${state}/credential.json`, JSON.stringify(credentials[0]), { mode: 0o600 });
  report.credentialId = credentials[0].credentialId;
} else if (mode === 'confirm') {
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: JSON.parse(readFileSync(`${state}/credential.json`, 'utf8')) });
  // The relay: intercept the return address and capture the signed act (a real relay forwards it).
  await page.route('https://relay.invalid/**', async route => {
    if (route.request().method() === 'POST') { report.posts = (report.posts ?? 0) + 1; report.act = JSON.parse(route.request().postData()); }
    // GET serves the requester's private note (the relay's job); POST receives the signed act.
    const url = route.request().url();
    const body = route.request().method() !== 'GET' ? '{}' : url.endsWith('/env') ? readFileSync(process.env.ENVELOPE, 'utf8')
      : JSON.stringify({ note: process.env.NOTE ?? '' });
    const status = route.request().method() === 'POST' ? Number(process.env.RELAY_STATUS ?? 200) : 200;
    await route.fulfill({ status, headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' }, body });
  });
  const frameFrom = process.argv.indexOf('--frame-from');
  if (frameFrom > 0) { // cross-origin embedding attempt: an outside page frames the approval page
    await page.goto(process.argv[frameFrom + 1]);
    await page.setContent(`<iframe id="f" src="${PAGE}#${fragment}" allow="publickey-credentials-get *" width="390" height="800"></iframe>`);
    await page.waitForTimeout(4000);
    report.framed = await page.frameLocator('#f').locator('body').innerText();
  } else {
    await page.goto(`${PAGE}#${fragment}`);
    await page.waitForFunction(() => !document.getElementById('confirm').hidden || !document.getElementById('error').hidden, null, { timeout: 20000 });
    report.shown = { title: await page.textContent('#title'), effect: await page.textContent('#effect'), facts: await page.textContent('#facts'),
      note: await page.isVisible('#note-box') ? await page.textContent('#note') : null, error: await page.isVisible('#error') ? await page.textContent('#error-text') : null };
    if (report.shown.error === null && decision !== 'none') {
      await page.click(decision === 'approve' ? '#approve' : '#decline');
      // Wait for the final state, past the in-progress ones ("Waiting for your passkey...", "Sending...").
      await page.waitForFunction(() => { const text = document.getElementById('result').textContent; return text !== '' && !text.endsWith('...'); }, null, { timeout: 20000 });
      report.posts ??= 0;
      report.copyBoxShown = await page.isVisible('#act-out');
      report.result = await page.textContent('#result');
      if (report.act === undefined && await page.isVisible('#act-out')) report.act = JSON.parse(await page.inputValue('#act-out'));
    }
  }
  if (report.act) writeFileSync(`${state}/act.json`, JSON.stringify(report.act, null, 2));
}
await browser.close();
console.log(JSON.stringify(report, null, 2));
