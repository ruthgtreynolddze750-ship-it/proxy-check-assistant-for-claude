'use strict';
// This page only handles supplied synthetic text; it never makes a request.
document.getElementById('check').addEventListener('click', () => {
  const trace = document.getElementById('trace').value;
  const expected = document.getElementById('expected').value;
  const host = document.getElementById('host').value;
  const ipLines = trace.split(/\r?\n/).filter(line => line.startsWith('ip='));
  const result = { source: 'synthetic_page', host, expected,
                   values: ipLines.map(line => line.slice(3)), may_launch: false };
  document.getElementById('result').textContent = JSON.stringify(result);
});
