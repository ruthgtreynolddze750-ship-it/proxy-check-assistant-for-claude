'use strict';
const TARGET = 'https://claude.ai/cdn-cgi/trace';
const TTL_MS = 60000;
let active = null;

function exactTarget(raw) {
  try {
    const u = new URL(raw);
    return u.origin === 'https://claude.ai' && u.pathname === '/cdn-cgi/trace' &&
           !u.search && !u.hash && !u.username && !u.password;
  } catch (_) { return false; }
}
function ipv4(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) return false;
  return value.split('.').every(x => Number(x) <= 255);
}
function isPopup(sender) {
  return sender && sender.id === chrome.runtime.id && !sender.tab && sender.url === chrome.runtime.getURL('popup.html');
}
function isPage(sender) {
  return !!(active && sender && sender.id === chrome.runtime.id && sender.frameId === 0 &&
    sender.tab && sender.tab.id === active.tabId && typeof sender.documentId === 'string' &&
    sender.documentId.length > 0 && exactTarget(sender.url));
}
function invalidate(reason) {
  if (active) { active.error = reason; active.expected = null; active.challenge = null;
    if (active.deliveryController) active.deliveryController.abort(); }
}
function expire() {
  if (active && (Date.now() < active.started || Date.now() - active.started > TTL_MS)) {
    invalidate('expired');
  }
}
function snapshot() {
  expire();
  const candidate = !!(active && !active.error && active.completed && active.pageMatch === true && active.requestId);
  return { diagnostic: candidate ? 'candidate' : 'unconfirmed',
    page_echo: active && !active.error && active.pageSeen ? 'seen' : 'unconfirmed',
    target_request: active && !active.error && active.completed ? 'observed' : 'unconfirmed',
    reason: active && active.error ? active.error : (candidate ? 'page_match_only' : 'insufficient_evidence'),
    session_id: candidate ? active.sessionId : null,
    identity_status: 'unconfirmed', proxy_status: 'unconfirmed', may_launch: false };
}
function requestMatches(d) {
  expire();
  return !!(active && !active.error && active.tabId !== null && d.tabId === active.tabId &&
    d.frameId === 0 && d.type === 'main_frame' && exactTarget(d.url));
}
const filter = { urls: ['https://claude.ai/cdn-cgi/trace*'], types: ['main_frame'] };
chrome.webRequest.onBeforeRequest.addListener(d => {
  if (!requestMatches(d)) return;
  if (active.requestId !== null || typeof d.requestId !== 'string' || !d.requestId) { invalidate('ambiguous_request'); return; }
  active.requestId = d.requestId;
}, filter);
chrome.webRequest.onBeforeRedirect.addListener(d => { if (requestMatches(d)) invalidate('redirected'); }, filter);
chrome.webRequest.onErrorOccurred.addListener(d => { if (requestMatches(d)) invalidate('request_failed'); }, filter);
chrome.webRequest.onCompleted.addListener(d => {
  if (!requestMatches(d)) return;
  if (d.requestId !== active.requestId || d.statusCode !== 200 || d.fromCache !== false) { invalidate('unverified_response'); return; }
  active.completed = true;
}, filter);
async function sendToBridge(session, port, token) {
  const controller = new AbortController();
  session.deliveryController = controller;
  const timer = setTimeout(() => controller.abort(), 4000);
  const root = 'http://127.0.0.1:' + String(port);
  const common = { cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal };
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', encoder.encode(token), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    if (controller.signal.aborted || active !== session) return false;
    const nonce = crypto.randomUUID();
    const response = await fetch(root + '/v1/challenge?nonce=' + nonce, { ...common, method: 'GET' });
    if (!response.ok) return false;
    const challenge = await response.json();
    if (!challenge || challenge.accepted !== true || typeof challenge.proof !== 'string' || !/^[0-9a-f]{64}$/.test(challenge.proof)) return false;
    const bytes = new Uint8Array(challenge.proof.match(/../g).map(x => parseInt(x, 16)));
    const serverMessage = 'bridge-v1|server|' + nonce + '|' + session.sessionId;
    if (!await crypto.subtle.verify('HMAC', key, bytes, encoder.encode(serverMessage))) return false;
    if (active !== session || snapshot().diagnostic !== 'candidate') return false;
    const clientMessage = 'bridge-v1|client|' + nonce + '|' + session.sessionId + '|' + TARGET + '|candidate|seen|observed';
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(clientMessage));
    if (controller.signal.aborted || active !== session || snapshot().diagnostic !== 'candidate') return false;
    const proof = Array.from(new Uint8Array(signature), x => x.toString(16).padStart(2, '0')).join('');
    const payload = { version: 1, nonce, session_id: session.sessionId, target: TARGET,
      diagnostic: 'candidate', page_echo: 'seen', target_request: 'observed', proof };
    const submitted = await fetch(root + '/v1/evidence', { ...common, method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: JSON.stringify(payload) });
    if (!submitted.ok) return false;
    const result = await submitted.json();
    return !!(result && result.accepted === true && result.identity_status === 'unconfirmed' &&
      result.proxy_status === 'unconfirmed' && result.may_launch === false);
  } catch (_) { return false; }
  finally { clearTimeout(timer); session.deliveryController = null; }
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  expire();
  if (!message || typeof message.type !== 'string') { respond(snapshot()); return false; }
  if (message.type === 'deliver' && isPopup(sender)) {
    const state = snapshot();
    if (!active || state.diagnostic !== 'candidate' || active.deliveryAttempted ||
        !Number.isInteger(message.port) || message.port < 1 || message.port > 65535 ||
        typeof message.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(message.token)) {
      respond({ ...state, bridge_status: 'unconfirmed' }); return false;
    }
    const session = active;
    session.deliveryAttempted = true;
    sendToBridge(session, message.port, message.token).then(ok => {
      const latest = snapshot();
      respond({ ...latest, bridge_status: ok && active === session && latest.diagnostic === 'candidate' ? 'delivered' : 'unconfirmed' });
    }, () => respond({ ...snapshot(), bridge_status: 'unconfirmed' }));
    return true;
  }
  if (message.type === 'status' && isPopup(sender)) { respond(snapshot()); return false; }
  if (message.type === 'clear' && isPopup(sender)) { invalidate('cancelled'); active = null; respond(snapshot()); return false; }
  if (message.type === 'start' && isPopup(sender)) {
    if (active && !active.error) { respond(snapshot()); return false; }
    if (!ipv4(message.expectedIp)) { active = { started: Date.now(), error: 'invalid_expected_ip', expected: null, challenge: null }; respond(snapshot()); return false; }
    active = { started: Date.now(), expected: message.expectedIp, challenge: crypto.randomUUID(), sessionId: crypto.randomUUID(), deliveryAttempted: false,
      tabId: null, documentId: null, requestId: null, completed: false, pageSeen: false, pageMatch: false, consumed: false, error: null };
    const thisSession = active;
    chrome.tabs.create({ url: TARGET, active: true }, tab => {
      if (active !== thisSession) { respond(snapshot()); return; }
      if (chrome.runtime.lastError || !tab || !Number.isInteger(tab.id)) invalidate('tab_unavailable');
      else active.tabId = tab.id;
      respond(snapshot());
    });
    return true;
  }
  if (message.type === 'ready' && isPage(sender) && !active.error && !active.consumed) {
    if (active.documentId && active.documentId !== sender.documentId) { invalidate('ambiguous_document'); respond(snapshot()); return false; }
    active.documentId = sender.documentId;
    const thisSession = active;
    chrome.tabs.sendMessage(active.tabId, { type: 'challenge', challenge: active.challenge }, { documentId: active.documentId }, () => {
      if (chrome.runtime.lastError && active === thisSession) invalidate('content_unavailable');
    });
    respond(snapshot()); return false;
  }
  if (message.type === 'capture' && isPage(sender) && !active.error && !active.consumed &&
      active.documentId === sender.documentId && typeof active.challenge === 'string' && message.challenge === active.challenge) {
    active.consumed = true;
    active.pageSeen = true;
    active.pageMatch = ipv4(message.ip) && message.ip === active.expected;
    if (!active.pageMatch) invalidate('echo_mismatch_or_invalid');
    active.expected = null; active.challenge = null;
    respond(snapshot()); return false;
  }
  respond({ diagnostic: 'unconfirmed', identity_status: 'unconfirmed', proxy_status: 'unconfirmed', may_launch: false });
  return false;
});
