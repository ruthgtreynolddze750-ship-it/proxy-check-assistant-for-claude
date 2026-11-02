'use strict';
// Chrome events and Origin are simulated; HTTP connections are actual loopback sockets.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const data = JSON.parse(fs.readFileSync(0, 'utf8'));
const id = 'a'.repeat(32);
const target = `http://127.0.0.1:${data.target_port}/cdn-cgi/trace`;
let workerListener, contentListener, uuids = 0;
const events = {};
const event = name => ({ addListener(fn) { events[name] = fn; } });
const popup = { id, url: `chrome-extension://${id}/popup.html` };
const page = { id, url: target, frameId: 0, documentId: 'doc-1', tab: { id: 42 } };
const request = { tabId: 42, frameId: 0, type: 'main_frame', url: target, requestId: 'req-1' };
const chrome = {
  runtime: { id, getURL: p => `chrome-extension://${id}/${p}`,
    onMessage: { addListener(fn) { workerListener = fn; } } },
  tabs: { create(options, callback) { if (options.url !== target) throw new Error('wrong target'); callback({ id: 42 }); },
    sendMessage(_tab, message, _options, callback) { contentListener(message, { id }); callback(); } },
  webRequest: { onBeforeRequest: event('before'), onBeforeRedirect: event('redirect'),
    onErrorOccurred: event('error'), onCompleted: event('completed') }
};
const restrictedFetch = (raw, options) => {
  const u = new URL(raw);
  if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || Number(u.port) !== data.bridge_port ||
      !['/v1/challenge', '/v1/evidence'].includes(u.pathname)) throw new Error('non-loopback request denied');
  return fetch(u, { ...options, headers: { ...options.headers, Origin: `chrome-extension://${id}` } });
};
const context = { chrome, URL, Date, TextEncoder, AbortController, setTimeout, clearTimeout, fetch: restrictedFetch,
  crypto: { subtle: webcrypto.subtle, randomUUID() { uuids++; return uuids === 2 ? data.session : webcrypto.randomUUID(); } } };
const extension = path.join(data.fixture, 'extension');
vm.runInNewContext(fs.readFileSync(path.join(extension, 'worker.js'), 'utf8'), context);
const send = (message, sender = popup) => new Promise(resolve => workerListener(message, sender, resolve));
(async () => {
  await send({ type: 'start', expectedIp: '203.0.113.9' });
  events.before(request);
  const response = await fetch(target, { redirect: 'error' });
  const body = await response.text();
  events.completed({ ...request, statusCode: response.status, fromCache: false });
  const contentChrome = { runtime: { id, onMessage: { addListener(fn) { contentListener = fn; } },
    sendMessage(message) { workerListener(message, page, () => {}); } } };
  vm.runInNewContext(fs.readFileSync(path.join(extension, 'content.js'), 'utf8'),
    { chrome: contentChrome, URL, document: { URL: target, body: { innerText: body } } });
  const state = await send({ type: 'status' });
  const result = await send({ type: 'deliver', port: data.bridge_port, token: data.token });
  process.stdout.write(JSON.stringify({ page: state.diagnostic === 'candidate' ? 'synthetic_candidate' : 'unconfirmed',
    bridge: result.bridge_status, may_launch: result.may_launch }));
})().catch(() => { process.stderr.write('Synthetic fixture failed'); process.exitCode = 1; });
