// The phone client's untrusted reads (MF5) and what its page tells the operator (MF4).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const TREE = process.env.TREE ?? join(import.meta.dirname, '..');
const C = await import(pathToFileURL(join(TREE, 'core.mjs')).href);
const page = readFileSync(join(TREE, 'index.html'), 'utf8'), readme = readFileSync(join(TREE, 'README.md'), 'utf8');

/** A fetch whose body streams `chunk` forever (or `total` bytes), counting what was pulled and whether it was cancelled. */
function streaming({ chunk = new Uint8Array(4096).fill(0x20), total = Infinity, stall = false } = {}) {
  const seen = { pulled: 0, cancelled: false };
  const fetchImpl = async (_url, init) => {
    assert.equal(init.credentials, 'omit');
    assert.equal(init.redirect, 'error');
    const body = new ReadableStream({
      async pull(controller) {
        if (stall) return new Promise(() => {}); // never answers
        if (seen.pulled >= total) { controller.close(); return; }
        seen.pulled += chunk.byteLength; controller.enqueue(chunk);
      },
      cancel() { seen.cancelled = true; },
    }, { highWaterMark: 0 });
    return new Response(body, { status: 200 });
  };
  return { fetchImpl, seen };
}

test('MF5: an endless body is cut off at the byte ceiling and the stream is cancelled', async () => {
  assert.equal(typeof C.fetchBounded, 'function', 'the client has a bounded reader');
  const { fetchImpl, seen } = streaming();
  await assert.rejects(C.fetchBounded('https://relay.example/c', 'request', { fetchImpl }), /request is too large/u);
  assert.ok(seen.pulled <= C.LIMITS.maxBody + 4096, `read ${seen.pulled} bytes, not the whole stream`);
  assert.equal(seen.cancelled, true);
});

test('MF5: a stalled body times out instead of hanging', { timeout: 5000 }, async () => {
  assert.equal(typeof C.fetchBounded, 'function');
  const { fetchImpl, seen } = streaming({ stall: true });
  const started = performance.now();
  await assert.rejects(C.fetchBounded('https://relay.example/c', 'request', { fetchImpl, timeoutMs: 200 }), /took too long/u);
  assert.ok(performance.now() - started < 2000);
  assert.equal(seen.cancelled, true);
});

test('MF5: the ceiling counts bytes, not characters; a small valid body is read; http is refused', async () => {
  assert.equal(typeof C.fetchBounded, 'function');
  const wide = new TextEncoder().encode(`{"n":"${'é'.repeat(9000)}"}`); // 9000 characters, 18000+ bytes
  const { fetchImpl: big } = streaming({ chunk: wide, total: wide.byteLength });
  await assert.rejects(C.fetchBounded('https://relay.example/n', 'note', { fetchImpl: big }), /too large/u);
  const ok = new TextEncoder().encode('{"note":"hello"}');
  const { fetchImpl: small } = streaming({ chunk: ok, total: ok.byteLength });
  assert.deepEqual(await C.fetchBounded('https://relay.example/n', 'note', { fetchImpl: small }), { note: 'hello' });
  await assert.rejects(C.fetchBounded('http://relay.example/n', 'note', { fetchImpl: small }), /HTTPS/u);
});

test('MF4: the stop is described as a signed request, not an immediate stop, and points to the real stop', async () => {
  const challenge = { action: 'emergency-stop', subject: { kind: 'stop' }, installation: 'x', principal: 'github:x', requestedBy: 'github:x', expiresAt: 0 };
  const view = await C.render(challenge, null);
  assert.doesNotMatch(`${view.title} ${view.effect}`, /at once|immediately stops|Stop now/u);
  assert.match(view.effect, /send "stop" in Telegram/u);
  assert.match(view.approve, /Sign stop request/u);
});

test('MF4 / R2-MF2: signing, delivery and acceptance are reported as separate states', () => {
  assert.equal(typeof C.resultText, 'function');
  const failed = C.resultText({ decision: 'approve', action: 'raise-caps', signed: true, delivery: 'failed', error: 'the return address answered 502' });
  assert.match(failed, /^Signed, but not delivered/u);
  assert.doesNotMatch(failed, /Not signed/u);
  assert.match(C.resultText({ decision: 'approve', signed: false, error: 'cancelled' }), /^Not signed: cancelled/u);
  assert.match(C.resultText({ decision: 'approve', action: 'raise-caps', signed: true, delivery: 'sent' }), /^Signed and sent: approved\. .*not recorded yet/u);
  for (const delivery of ['manual', undefined, 'sending']) {
    assert.doesNotMatch(C.resultText({ decision: 'approve', action: 'raise-caps', signed: true, delivery }), /sent:|and sent|recorded as/u);
  }
  const stop = C.resultText({ decision: 'approve', action: 'emergency-stop', signed: true, delivery: 'manual' });
  assert.match(stop, /^Signed: stop request\. Not sent/u);
  assert.match(stop, /send "stop" in Telegram/u);
});

test('MF4: the page gives the measured commit steps and the lose-your-phone path', () => {
  assert.doesNotMatch(page, /Tap "Commit changes", then "Commit changes" again/u);
  assert.match(page, /"Commit changes\.\.\.", then "Commit changes"/u);
  assert.match(page, /a pull request is not accepted/u);
  for (const text of [page, readme]) {
    assert.match(text, /phone <?b?>?and<?\/?b?>? on your Mac|phone and Mac/u);
    assert.match(text, /If every passkey is lost/u);
    assert.match(text, /only pauses the changes that need your approval/u);
    assert.doesNotMatch(text, /approvers\.json/u);
  }
});
