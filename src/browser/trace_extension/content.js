'use strict';
(function () {
  function exactTarget(raw) {
    try { const u = new URL(raw); return u.origin === 'https://claude.ai' && u.pathname === '/cdn-cgi/trace' && !u.search && !u.hash && !u.username && !u.password; }
    catch (_) { return false; }
  }
  if (!exactTarget(document.URL)) return;
  let used = false;
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (!sender || sender.id !== chrome.runtime.id || sender.tab || used || !message || message.type !== 'challenge' || typeof message.challenge !== 'string' || !message.challenge) return;
    used = true;
    const text = document.body ? document.body.innerText : '';
    const entries = typeof text === 'string' && text.length <= 8192 ? text.split(/\r?\n/).filter(line => line.startsWith('ip=')) : [];
    const value = entries.length === 1 ? entries[0].slice(3) : '';
    const valid = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value) && value.split('.').every(part => Number(part) <= 255);
    const ip = valid ? value : '';
    chrome.runtime.sendMessage({ type: 'capture', challenge: message.challenge, ip });
  });
  chrome.runtime.sendMessage({ type: 'ready' });
})();
