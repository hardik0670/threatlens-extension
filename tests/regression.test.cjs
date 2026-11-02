const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const root = path.resolve(__dirname, '..');

function background() {
  const storage = {};
  let listener;
  const context = vm.createContext({
    URL, Date, AbortSignal, console,
    chrome: {
      runtime: { onMessage: { addListener(fn) { listener = fn; } } },
      tabs: { onRemoved: { addListener() {} }, get: async () => ({ url: 'https://shop.example.com/item' }) },
      storage: { session: {
        async get(key) { return { [key]: storage[key] }; },
        async set(values) { Object.assign(storage, values); },
        async remove() {},
      } },
    },
    fetch: async () => ({ ok: true, json: async () => ({ threat_score: 0.8, verdict: 'High Risk', fired_rules: [{ rule: 'bad', adjustment: 0.3, reason: 'Danger' }] }) }),
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'background.js'), 'utf8'), context);
  return { context, send: (message, sender = {}) => new Promise(resolve => listener(message, sender, resolve)) };
}

function popup() {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      value: '', checked: false, style: {}, dataset: {}, textContent: '', innerHTML: '',
      classList: { contains: () => true, add() {}, remove() {} },
      children: [],
      querySelector(selector) { return selector === '.seller-actions' ? element(`actions-${id}`) : null; }, querySelectorAll() { return []; },
      getAttribute() { return '42'; }, setAttribute() {}, appendChild(child) { this.children.push(child); },
    });
    return elements.get(id);
  }
  const context = vm.createContext({
    URL, AbortSignal, console, Date, setInterval, clearInterval, setTimeout, clearTimeout,
    requestAnimationFrame: fn => fn(),
    document: { getElementById: element, addEventListener() {}, createElement: () => element(Math.random()) },
    localStorage: { getItem: () => null, setItem() {} },
    chrome: { runtime: { sendMessage: async () => ({}) } },
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'popup/popup.js'), 'utf8'), context);
  return { context, element };
}

test('page signals cannot leak across tabs, origins, or full URLs', async () => {
  const { send } = background();
  await send({ type: 'TRUST_SIGNALS', data: { hasContact: true } }, { tab: { id: 1 }, frameId: 0, url: 'https://shop.example.com/item' });
  assert.equal((await send({ type: 'GET_TRUST_SIGNALS', tabId: 1, url: 'https://shop.example.com' })).hasContact, true);
  assert.equal((await send({ type: 'GET_TRUST_SIGNALS', tabId: 2, url: 'https://shop.example.com' })).hasContact, undefined);
  assert.equal((await send({ type: 'GET_TRUST_SIGNALS', tabId: 1, url: 'https://attacker.com' })).hasContact, undefined);
  assert.equal((await send({ type: 'GET_TRUST_SIGNALS', tabId: 1, url: 'https://shop.example.com/other' })).hasContact, undefined);
});

test('legacy analysis maps the current API response', async () => {
  const { context } = background();
  const result = await vm.runInContext('analyzeWithAPI({ url: "https://example.com", domain: "example.com" })', context);
  assert.equal(result.score, 20);
  assert.equal(result.level, 'High Risk');
  assert.equal(result.levelClass, 'high');
  assert.equal(result.flags[0].detail, 'Danger');
});

test('background scan replies and retains a result for the popup', async () => {
  const { send } = background();
  const result = await send({ type: 'SCAN_URL', signals: { hasContact: true } }, { tab: { id: 1 }, frameId: 0, url: 'https://shop.example.com/item' });
  assert.equal(result.threat_score, 0.8);
  const cached = await send({ type: 'GET_RECENT_SCAN', tabId: 1, url: 'https://shop.example.com' });
  assert.equal(cached.analysis.threat_score, 0.8);
});

test('seller and AI network errors render without secondary ReferenceErrors', async () => {
  const { context, element } = popup();
  vm.runInContext(`state.lastScannedUrl = 'https://example.com'; state.lastAnalysis = { threat_score: 0.8 }; postJsonCached = async () => { throw new Error('Offline'); };`, context);
  await vm.runInContext('toggleSellerInsights()', context);
  assert.match(element('seller-insights-list').innerHTML, /Offline/);
  await vm.runInContext('toggleAiSummary()', context);
  assert.equal(element('threat-analysis-text').textContent, 'Failed to generate AI summary.');
});

test('seller analysis updates the same score used by AI summaries', async () => {
  const { context, element } = popup();
  vm.runInContext(`state.lastScannedUrl = 'https://example.com'; state.lastAnalysis = { threat_score: 0.8 };
    postJsonCached = async () => ({ data: { analysis: { threat_score: 0.4, verdict: 'Medium Risk', contact_signals: { uses_ecommerce: true }, domain_metadata: {}, fired_rules: [] } } });`, context);
  await vm.runInContext('toggleSellerInsights()', context);
  assert.equal(element('score-value').textContent, 60);
  assert.equal(vm.runInContext('state.lastAnalysis.threat_score', context), 0.4);
});

test('internal browser URLs are rejected and explanation cache includes analysis', () => {
  const { context } = popup();
  for (const url of ['chrome://settings', 'edge://settings', 'file:///tmp/file', 'javascript:alert(1)']) {
    assert.equal(vm.runInContext(`normaliseUrl(${JSON.stringify(url)})`, context), '');
  }
  assert.notEqual(vm.runInContext(`buildCacheKey('/explain', {url:'https://example.com',threat_score:0.2})`, context), vm.runInContext(`buildCacheKey('/explain', {url:'https://example.com',threat_score:0.8})`, context));
});

test('seller cards preserve contact roles, source actions, policy categories and escaped evidence', () => {
  const { context, element } = popup();
  vm.runInContext(`renderSellerInsights({ analysis: {
    contact_signals: { contacts: [
      { value: '+919150043065', display: '+91 91500 43065', channel: 'whatsapp', purpose: 'support', whatsapp_only: true, sources: [{url:'https://store.example/contact'}] },
      { value: '+919270036788', channel: 'phone', purpose: 'exchange', sources: [{url:'https://store.example/contact'}] }
    ] }, policies: {
      exchange: { status:'extracted', source_url:'https://store.example/refund', facts:[{ text:'Within 48 hours <img onerror=alert(1)>', context:'Exchange Policy' }] },
      shipping: { status:'discovered', source_url:'https://store.example/shipping', facts:[] }
    }, scan_status: {status:'partial'}
  }});`, context);
  const rows = element('seller-insights-list').children;
  const markup = rows.map(r => r.innerHTML).join('\n');
  assert.match(markup, /Support - WhatsApp only/);
  assert.match(markup, /Exchange - Phone/);
  assert.match(markup, /Shipping Policy/);
  assert.match(markup, /Exchange Policy/);
  assert.match(markup, /48 hours &lt;img/);
  assert.doesNotMatch(markup, /<img onerror/);
  assert.match(markup, /contents could not be verified/);
  assert.match(markup, /Scan coverage/);
  const actions = rows[0].querySelector('.seller-actions').children;
  assert.equal(actions[0].dataset.payload, '+919150043065');
  assert.equal(actions[1].dataset.payload, 'https://store.example/contact');
});

test('partial evidence cannot earn a strong transparency badge', () => {
  const { context } = popup();
  const level = vm.runInContext(`showSellerTransparencyBadge({
    contacts:[{validated:true, channel:'phone'}], emails:['support@example.com'],
    has_return_policy:true, has_refund_policy:true, has_privacy_policy:true
  }, {status:'partial'})`, context);
  assert.equal(level, 'incomplete');
});

test('changed browser evidence invalidates seller cache entries', () => {
  const { context } = popup();
  const different = vm.runInContext(`buildCacheKey('/seller-insights', {url:'https://example.com',signals:{contactBlocks:[{text:'Old number'}]}})
    !== buildCacheKey('/seller-insights', {url:'https://example.com',signals:{contactBlocks:[{text:'New number'}]}})`, context);
  assert.equal(different, true);
});

test('seller requests reject an incompatible backend instead of showing old scraped data', async () => {
  const { context } = popup();
  context.fetch = async () => ({ ok: true, json: async () => ({ analysis: { contact_signals: {} } }) });
  await assert.rejects(vm.runInContext(`postJson('/seller-insights', {url:'https://example.com'})`, context), /waiting for a service update/);
  context.fetch = async () => ({ ok: true, json: async () => ({ analysis: { extraction_version: 'seller-v2' } }) });
  const response = await vm.runInContext(`postJson('/seller-insights', {url:'https://example.com'})`, context);
  assert.equal(response.analysis.extraction_version, 'seller-v2');
});

test('release version and production API permissions match the popup and worker', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  const html = fs.readFileSync(path.join(root, 'popup/popup.html'), 'utf8');
  assert.ok(html.includes(`ThreatLens v${manifest.version}`));
  const endpoints = ['background.js', 'popup/popup.js'].map(file => fs.readFileSync(path.join(root, file), 'utf8').match(/const API_BASE = "([^"]+)"/)[1]);
  assert.equal(endpoints[0], endpoints[1]);
  assert.ok(manifest.host_permissions.includes(`${endpoints[0]}/*`));
});
