'use strict';
const reasons = {
  expired: '本次挑战已过期，请重新开始。', invalid_expected_ip: '请输入有效的 IPv4 地址。',
  ambiguous_request: '检测到多个请求，无法关联。', redirected: '目标发生重定向，无法确认。',
  request_failed: '目标请求失败。', unverified_response: '响应状态或缓存状态不符合要求。',
  tab_unavailable: '无法创建测试标签页。', ambiguous_document: '页面身份不唯一。',
  content_unavailable: '无法与测试页面通信。', echo_mismatch_or_invalid: '回显无效或与预期不一致。',
  insufficient_evidence: '等待有效页面与请求证据。', page_match_only: '本次页面回显与预期一致，仅作为候选。'
};
function show(result) {
  const r = result || {};
  const reason = reasons[r.reason] || '无法确认本次检测。';
  document.getElementById('pairing-invitation').textContent = r.session_id ? chrome.runtime.id + '.' + r.session_id : '尚未形成候选';
  const bridge = r.bridge_status === 'delivered' ? '\n候选已发送至本机通道。' : '';
  document.getElementById('result').textContent = reason + bridge + '\n浏览器配置身份：未确认\n实际代理状态：未确认\n网页启动：不可放行';
}
document.getElementById('start').addEventListener('click', () => {
  const field = document.getElementById('expected'); const expectedIp = field.value.trim(); field.value = '';
  chrome.runtime.sendMessage({ type: 'start', expectedIp }, show);
});
document.getElementById('status').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'status' }, show));
document.getElementById('clear').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'clear' }, show));
document.getElementById('send').addEventListener('click', () => {
  const field = document.getElementById('pairing-code'); const code = field.value.trim(); field.value = '';
  const match = /^([1-9][0-9]{0,4}):([A-Za-z0-9_-]{43})$/.exec(code);
  const port = match ? Number(match[1]) : 0; const token = match ? match[2] : '';
  chrome.runtime.sendMessage({ type: 'deliver', port, token }, show);
});
