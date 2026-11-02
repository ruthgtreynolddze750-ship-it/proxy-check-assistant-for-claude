'use strict';
// Executes our own page script against a minimal fake DOM; no Chrome is started.
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let handler;
let networkCalls = 0;
const elements = {
  trace: { value: input.trace }, expected: { value: input.expected },
  host: { value: input.host }, result: { textContent: '' },
  check: { addEventListener: (type, fn) => { if (type === 'click') handler = fn; } }
};
const noNetwork = () => { networkCalls++; throw new Error('network forbidden'); };
const context = { document: { getElementById: id => elements[id] },
                  fetch: noNetwork, XMLHttpRequest: noNetwork, WebSocket: noNetwork };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'offline_page.js'), 'utf8'), context,
                   { timeout: 1000 });
let page = null;
try { handler(); page = JSON.parse(elements.result.textContent); } catch (_) {}
process.stdout.write(JSON.stringify({ page, network_calls: networkCalls }));
