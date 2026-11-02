'use strict';
// Synthetic Chrome events, actual extension worker and actual loopback HTTP bridge.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const data = JSON.parse(fs.readFileSync(0, 'utf8'));
const extensionId = 'a'.repeat(32);
const target = 'https://claude.ai/cdn-cgi/trace';
let messageListener;
let pageChallenge;
let uuidCount = 0;
const events = {};
const event = name => ({ addListener(fn) { events[name] = fn; } });
const chrome = {
  runtime: { id: extensionId, getURL: p => `chrome-extension://${extensionId}/${p}`,
    onMessage: { addListener(fn) { messageListener = fn; } } },
  tabs: { create(_options, callback) { callback({ id: 42 }); },
    sendMessage(_id, message, _options, callback) { pageChallenge = message.challenge; callback(); } },
  webRequest: { onBeforeRequest: event('before'), onBeforeRedirect: event('redirect'),
    onErrorOccurred: event('error'), onCompleted: event('completed') }
};
const controlledFetch = (raw, options) => {
  const url = new URL(raw);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' ||
      Number(url.port) !== data.port || !['/v1/challenge', '/v1/evidence'].includes(url.pathname)) {
    throw new Error('Non-loopback request denied');
  }
  // Node does not emulate extension Origin; this header is synthetic, not Chrome evidence.
  return fetch(url, { ...options, headers: { ...options.headers, Origin: `chrome-extension://${extensionId}` } });
};
const context = { chrome, URL, Date, TextEncoder, AbortController, setTimeout, clearTimeout,
  fetch: controlledFetch, crypto: { subtle: webcrypto.subtle, randomUUID() {
    uuidCount += 1;
    return uuidCount === 2 ? data.session_id : webcrypto.randomUUID();
  } } };
const workerPath = path.join(__dirname, '../../src/browser/trace_extension/worker.js');
vm.runInNewContext(fs.readFileSync(workerPath, 'utf8'), context, { filename: workerPath });
const popup = { id: extensionId, url: `chrome-extension://${extensionId}/popup.html` };
const page = { id: extensionId, url: target, frameId: 0, documentId: 'doc-1', tab: { id: 42 } };
const request = { tabId: 42, frameId: 0, type: 'main_frame', url: target, requestId: 'req-1' };
function send(message, sender) { return new Promise(resolve => messageListener(message, sender, resolve)); }
(async () => {
  await send({ type: 'start', expectedIp: '203.0.113.9' }, popup);
  events.before(request);
  await send({ type: 'ready' }, page);
  events.completed({ ...request, statusCode: 200, fromCache: false });
  await send({ type: 'capture', challenge: pageChallenge, ip: '203.0.113.9' }, page);
  const ids = ['start', 'status', 'clear', 'send', 'expected', 'pairing-invitation', 'pairing-code', 'result'];
  const elements = Object.fromEntries(ids.map(id => [id, { value: '', textContent: '', addEventListener(_type, fn) { this.click = fn; } }]));
  let delivered;
  const waiting = new Promise(resolve => { delivered = resolve; });
  chrome.runtime.sendMessage = (message, callback) => messageListener(message, popup, result => {
    callback(result);
    if (message.type === 'deliver') delivered(result);
  });
  vm.runInNewContext(fs.readFileSync(path.join(path.dirname(workerPath), 'popup.js'), 'utf8'),
    { chrome, document: { getElementById: id => elements[id] } });
  elements.status.click();
  const invitationValid = elements['pairing-invitation'].textContent === `${extensionId}.${data.session_id}`;
  elements['pairing-code'].value = data.pairing_code;
  elements.send.click();
  const result = await waiting;
  process.stdout.write(JSON.stringify({ bridge_status: result.bridge_status, may_launch: result.may_launch,
    invitation_valid: invitationValid, field_cleared: elements['pairing-code'].value === '' }));
})().catch(() => { process.stderr.write('Synthetic bridge integration failed'); process.exitCode = 1; });
