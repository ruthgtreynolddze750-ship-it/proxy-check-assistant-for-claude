const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, createHmac } = require('node:crypto');
const root = path.resolve(__dirname, '../../src/browser/trace_extension');

function harness(options = {}) {
  let now = 100000;
  const listeners = {};
  let challenge;
  let fetcher = async () => { throw new Error('no network'); };
  let creates = 0;
  const id = 'extension-id';
  const url = 'https://claude.ai/cdn-cgi/trace';
  const events = () => ({ addListener(fn) { this.fn = fn; } });
  const chrome = {
    runtime: { id, getURL: x => `chrome-extension://${id}/${x}`,
      onMessage: { addListener(fn) { listeners.message = fn; } } },
    tabs: { create(details, callback) { creates++; assert.equal(details.url, url); callback({ id: 42 }); },
      sendMessage(tab, msg, options, callback) { assert.equal(tab, 42); assert.equal(options.documentId, "doc-1"); challenge = msg.challenge; if (callback) callback(); } },
    webRequest: { onBeforeRequest: events(), onCompleted: events(), onBeforeRedirect: events(), onErrorOccurred: events() },
  };
  class FakeDate extends Date { static now() { return now; } }
  const context = vm.createContext({ chrome, crypto: options.crypto || webcrypto, Date: FakeDate, URL, console, TextEncoder, AbortController, setTimeout, clearTimeout, fetch: (...args) => fetcher(...args) });
  vm.runInContext(fs.readFileSync(path.join(root, 'worker.js'), 'utf8'), context);
  const popup = { id, url: `chrome-extension://${id}/popup.html` };
  const page = { id, url, frameId: 0, documentId: 'doc-1', tab: { id: 42 } };
  const send = (message, sender = popup) => { let reply; listeners.message(message, sender, value => { reply = value; }); return reply; };
  const sendAsync = (message, sender = popup) => new Promise(resolve => listeners.message(message, sender, resolve));
  const request = (event, extra = {}) => chrome.webRequest[event].fn({ tabId: 42, frameId: 0, type: 'main_frame', url, requestId: 'r1', ...extra });
  return { send, sendAsync, request, page, popup, setFetch(fn) { fetcher = fn; }, get challenge() { return challenge; }, get creates() { return creates; }, tick(ms) { now += ms; }, secretsCleared() { return vm.runInContext('!active || (active.expected === null && active.challenge === null)', context); } };
}

test('actual page and request events can create only a candidate, never a launch pass', () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' });
  h.request('onBeforeRequest'); h.send({ type: 'ready' }, h.page);
  h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  const r = h.send({ type: 'status' });
  assert.equal(r.diagnostic, 'candidate'); assert.equal(r.identity_status, 'unconfirmed');
  assert.equal(r.proxy_status, 'unconfirmed'); assert.equal(r.may_launch, false);
  assert.equal(JSON.stringify(r).includes('203.0.113.9'), false);
});

test('spoofed sender, wrong tab, invalid challenge and multiple sessions fail closed', () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' }, { id: 'other', url: 'https://evil.invalid' });
  assert.equal(h.creates, 0); h.send({ type: 'start', expectedIp: '203.0.113.9' });
  h.send({ type: 'start', expectedIp: '203.0.113.9' }); assert.equal(h.creates, 1);
  h.request('onBeforeRequest'); h.send({ type: 'ready' }, h.page);
  h.send({ type: 'capture', challenge: 'fake', ip: '203.0.113.9' }, h.page);
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, { ...h.page, tab: { id: 99 } });
  h.request('onCompleted', { statusCode: 200, fromCache: false });
  const r = h.send({ type: 'status' }); assert.notEqual(r.diagnostic, 'candidate'); assert.equal(r.may_launch, false);
});

test('cached, redirected, duplicate, mismatched and expired observations never become candidate', () => {
  for (const mode of ['cached', 'redirect', 'duplicate', 'mismatch', 'expired', 'badstatus']) {
    const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
    if (mode === 'duplicate') h.request('onBeforeRequest', { requestId: 'r2' });
    h.send({ type: 'ready' }, h.page);
    if (mode === 'redirect') h.request('onBeforeRedirect', { redirectUrl: 'https://evil.invalid/' });
    if (mode === 'expired') h.tick(61000);
    h.request('onCompleted', { statusCode: mode === 'badstatus' ? 503 : 200, fromCache: mode === 'cached' });
    h.send({ type: 'capture', challenge: h.challenge, ip: mode === 'mismatch' ? '203.0.113.10' : '203.0.113.9' }, h.page);
    const r = h.send({ type: 'status' }); assert.notEqual(r.diagnostic, 'candidate', mode); assert.equal(r.may_launch, false);
  }
});

test('content script accepts only the authorized document and does not use network APIs', () => {
  let listener; const messages = [];
  const chrome = { runtime: { id: 'extension-id', onMessage: { addListener(fn) { listener = fn; } }, sendMessage(m) { messages.push(m); } } };
  const document = { URL: 'https://claude.ai/cdn-cgi/trace', body: { innerText: 'fl=demo\nip=203.0.113.9\n' } };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'content.js'), 'utf8'), { chrome, document, URL });
  listener({ type: 'challenge', challenge: 'abc' }, { id: 'extension-id' });
  assert.equal(messages[0].type, 'ready'); assert.equal(messages[1].type, 'capture');
  assert.equal(messages[1].ip, '203.0.113.9'); assert.equal(messages[1].challenge, 'abc');
});

test('content rejects spoofed challenges and never forwards malformed or excessive page data', () => {
  let listener; const messages = [];
  const chrome = { runtime: { id: 'extension-id', onMessage: { addListener(fn) { listener = fn; } }, sendMessage(m) { messages.push(m); } } };
  const document = { URL: 'https://claude.ai/cdn-cgi/trace', body: { innerText: 'ip=private-data-not-an-ip' } };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'content.js'), 'utf8'), { chrome, document, URL });
  listener({ type: 'challenge', challenge: 'fake' }, { id: 'another-extension' });
  assert.equal(messages.length, 1);
  listener({ type: 'challenge', challenge: 'real' }, { id: 'extension-id' });
  assert.equal(messages[1].ip, '');
  assert.equal(JSON.stringify(messages).includes('private-data-not-an-ip'), false);
});

test('capture from a different document is ignored and expired session cannot be promoted', () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
  h.send({ type: 'ready' }, h.page); h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, { ...h.page, documentId: 'other-doc' });
  assert.notEqual(h.send({ type: 'status' }).diagnostic, 'candidate');
  h.tick(61000); h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  const expired = h.send({ type: 'status' });
  assert.equal(expired.reason, 'expired');
  assert.equal(expired.page_echo, 'unconfirmed');
  assert.equal(expired.target_request, 'unconfirmed');
});

test('manifest avoids broad tabs, storage, proxy and external messaging permissions', () => {
  const m = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8').replace(/^\uFEFF/, ''));
  assert.equal(m.manifest_version, 3);
  assert.equal(m.minimum_chrome_version, '106');
  assert.deepEqual(m.permissions, ['webRequest']);
  assert.deepEqual(m.host_permissions, ['https://claude.ai/*', 'http://127.0.0.1/*']);
  assert.equal(Object.hasOwn(m, 'externally_connectable'), false);
});

test('failed request clears expected IP and challenge from session memory', () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' });
  h.request('onBeforeRequest'); h.request('onErrorOccurred');
  assert.equal(h.send({ type: 'status' }).reason, 'request_failed');
  assert.equal(h.secretsCleared(), true);
});


test('candidate delivery authenticates a loopback bridge without transmitting token or IP', async () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
  h.send({ type: 'ready' }, h.page); h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  const session = h.send({ type: 'status' }).session_id;
  assert.match(session, /^[0-9a-f-]{36}$/);
  const token = 'A'.repeat(43), calls = [];
  h.setFetch(async (url, opts) => {
    calls.push({url, opts});
    if (calls.length === 1) {
      const nonce = new URL(url).searchParams.get('nonce');
      const proof = createHmac('sha256', token).update(`bridge-v1|server|${nonce}|${session}`).digest('hex');
      return { ok: true, json: async () => ({ accepted: true, proof }) };
    }
    return { ok: true, json: async () => ({ accepted: true, identity_status: 'unconfirmed', proxy_status: 'unconfirmed', may_launch: false }) };
  });
  const result = await h.sendAsync({ type: 'deliver', port: 41234, token });
  assert.equal(result.bridge_status, 'delivered'); assert.equal(result.may_launch, false);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(x => x.url.startsWith('http://127.0.0.1:41234/')));
  assert.equal(JSON.stringify(calls).includes(token), false);
  assert.equal(JSON.stringify(calls).includes('203.0.113.9'), false);
  const body = JSON.parse(calls[1].opts.body); assert.equal(body.session_id, session);
  assert.equal(body.diagnostic, 'candidate');
  const again = await h.sendAsync({ type: 'deliver', port: 41234, token });
  assert.equal(again.bridge_status, 'unconfirmed'); assert.equal(calls.length, 2);
});

test('invalid server proof prevents posting data or retrying', async () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
  h.send({ type: 'ready' }, h.page); h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  let count = 0; h.setFetch(async () => { count++; return { ok: true, json: async () => ({ accepted: true, proof: '0'.repeat(64) }) }; });
  const token = 'A'.repeat(43), result = await h.sendAsync({ type: 'deliver', port: 41234, token });
  assert.equal(result.bridge_status, 'unconfirmed'); assert.equal(count, 1);
  await h.sendAsync({ type: 'deliver', port: 41234, token }); assert.equal(count, 1);
});


test('cryptography failure returns unconfirmed without an unhandled promise', async () => {
  const badCrypto = { randomUUID: () => webcrypto.randomUUID(), subtle: { importKey: async () => { throw new Error('unavailable'); } } };
  const h = harness({ crypto: badCrypto }); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
  h.send({ type: 'ready' }, h.page); h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  const result = await h.sendAsync({ type: 'deliver', port: 41234, token: 'A'.repeat(43) });
  assert.equal(result.bridge_status, 'unconfirmed'); assert.equal(result.may_launch, false);
});

test('popup uses a single invitation and single pairing code without exposing the token', () => {
  const ids = ['start', 'status', 'clear', 'send', 'expected', 'pairing-invitation', 'pairing-code', 'result'];
  const elements = Object.fromEntries(ids.map(id => [id, { value: '', textContent: '', addEventListener(type, fn) { this.click = fn; } }]));
  const sent = []; const id = 'a'.repeat(32), session = '00000000-0000-4000-8000-000000000000';
  const chrome = { runtime: { id, sendMessage(message, cb) { sent.push(message); cb({ diagnostic: 'candidate', session_id: session, reason: 'page_match_only' }); } } };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'popup.js'), 'utf8'), { chrome, document: { getElementById: id => elements[id] } });
  elements.status.click();
  assert.equal(elements['pairing-invitation'].textContent, `${id}.${session}`);
  elements['pairing-code'].value = `41234:${'A'.repeat(43)}`; elements.send.click();
  assert.equal(elements['pairing-code'].value, '');
  assert.equal(sent[1].port, 41234); assert.equal(sent[1].token, 'A'.repeat(43));
  assert.equal(elements.result.textContent.includes('A'.repeat(43)), false);
});

test('clearing the session aborts an in-flight bridge request', async () => {
  const h = harness(); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
  h.send({ type: 'ready' }, h.page); h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  let started; const waiting = new Promise(resolve => { started = resolve; });
  let signal;
  h.setFetch((_url, opts) => { signal = opts.signal; started(); return new Promise((_resolve, reject) => {
    if (signal.aborted) reject(new Error('aborted'));
    else signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  }); });
  const delivery = h.sendAsync({ type: 'deliver', port: 41234, token: 'A'.repeat(43) });
  await waiting; h.send({ type: 'clear' });
  assert.equal(signal.aborted, true);
  assert.equal((await delivery).bridge_status, 'unconfirmed');
});

test('clearing while HMAC signing prevents a late evidence post', async () => {
  let signingStarted, releaseSign;
  const started = new Promise(resolve => { signingStarted = resolve; });
  const blocker = new Promise(resolve => { releaseSign = resolve; });
  const crypto = { randomUUID: () => webcrypto.randomUUID(), subtle: {
    importKey: (...args) => webcrypto.subtle.importKey(...args),
    verify: (...args) => webcrypto.subtle.verify(...args),
    sign: async (...args) => { signingStarted(); await blocker; return webcrypto.subtle.sign(...args); }
  } };
  const h = harness({ crypto }); h.send({ type: 'start', expectedIp: '203.0.113.9' }); h.request('onBeforeRequest');
  h.send({ type: 'ready' }, h.page); h.request('onCompleted', { statusCode: 200, fromCache: false });
  h.send({ type: 'capture', challenge: h.challenge, ip: '203.0.113.9' }, h.page);
  const session = h.send({ type: 'status' }).session_id; let calls = 0;
  h.setFetch(async url => { calls++; const nonce = new URL(url).searchParams.get('nonce');
    const proof = createHmac('sha256', 'A'.repeat(43)).update(`bridge-v1|server|${nonce}|${session}`).digest('hex');
    return { ok: true, json: async () => ({ accepted: true, proof }) };
  });
  const delivery = h.sendAsync({ type: 'deliver', port: 41234, token: 'A'.repeat(43) });
  await started; h.send({ type: 'clear' }); releaseSign();
  assert.equal((await delivery).bridge_status, 'unconfirmed'); assert.equal(calls, 1);
});
