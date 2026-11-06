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

test('seller email actions compose to each displayed address, never its evidence page', () => {
  const { context, element } = popup();
  vm.runInContext(`renderSellerInsights({analysis: {contact_signals: {
    emails: ['hello@urbanmonkey.com', 'customer.care@urbanmonkey.com'],
    email_records: [{sources: [{url: 'https://www.urbanmonkey.com/policies/refund-policy'}]}]
  }}})`, context);
  const buttons = element('seller-insights-list').children.flatMap(row => row.querySelector('.seller-actions').children);
  const links = buttons.filter(button => button.dataset.kind === 'external');
  assert.equal(links.length, 2);
  assert.deepEqual(links.map(button => new URL(button.dataset.payload).searchParams.get('to')), ['hello@urbanmonkey.com', 'customer.care@urbanmonkey.com']);
  assert.ok(links.every(button => new URL(button.dataset.payload).hostname === 'mail.google.com'));
  const opened = [];
  context.chrome.tabs = { create: args => opened.push(args.url) };
  for (const button of links) context.handleSellerListAction({target: {closest: () => button}});
  assert.deepEqual(opened, links.map(button => button.dataset.payload));
});

test('seller actions reject unsafe URLs and open validated phone URIs', () => {
  const { context } = popup();
  const opened = [];
  context.chrome.tabs = { create: args => opened.push(args.url) };
  for (const payload of ['javascript:alert(1)', 'data:text/html,bad', 'https://user:pass@example.com', 'tel:bad', 'tel:+919111553117']) {
    context.handleSellerListAction({target: {closest: () => ({dataset: {kind: 'external', payload}})}});
  }
  assert.deepEqual(opened, ['tel:+919111553117']);
});

test('alternative policy sources remain clickable and privacy emails are labelled', () => {
  const { context, element } = popup();
  vm.runInContext(`renderSellerInsights({analysis: {contact_signals: {
    emails:['privacy@example.com'], email_records:[{value:'privacy@example.com', purpose:'privacy'}]
  }, policies: {return: {status:'extracted', source_url:'https://store.example/returns',
    alternative_sources:[{source_url:'https://store.example/refunds'}]}},
    policy_summaries:{return_policy:'Returns within 7 days.'}}})`, context);
  const rows = element('seller-insights-list').children;
  assert.match(rows[1].innerHTML, /Privacy contact/);
  assert.match(rows[2].innerHTML, /terms may differ/);
  const links = rows[2].querySelector('.seller-actions').children;
  assert.deepEqual(links.map(button => button.dataset.payload), ['https://store.example/returns', 'https://store.example/refunds']);
  assert.match(links[1].title, /other Return Policy source/);
});

test('oversized browser policy blocks explicitly mark evidence incomplete', () => {
  const longBlock = {tagName:'P', innerText:'Returns are accepted. '.repeat(100),
    closest: () => null, getClientRects: () => [1]};
  const context = vm.createContext({URL, console, location: {href:'https://store.example/refund-policy'},
    window: {addEventListener() {}}, Node: {ELEMENT_NODE:1}, MutationObserver: class {observe() {}},
    document: {title:'Refund policy', readyState:'loading', body:{},
      querySelectorAll: () => [], querySelector: () => ({querySelectorAll: () => [longBlock]})}});
  vm.runInContext(fs.readFileSync(path.join(root, 'contentScript.js'), 'utf8'), context);
  assert.equal(vm.runInContext('collectSellerSignals().evidenceTruncated', context), true);
});

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
    }, policy_summaries: { exchange_policy: 'Within 48 hours <img onerror=alert(1)>' }, scan_status: {status:'partial'}
  }});`, context);
  const rows = element('seller-insights-list').children;
  const markup = rows.map(r => r.innerHTML).join('\n');
  assert.match(markup, /Support - WhatsApp only/);
  assert.match(markup, /Exchange - Phone/);
  assert.match(markup, /Shipping Policy/);
  assert.match(markup, /Exchange Policy/);
  assert.match(markup, /48 hours &lt;img/);
  assert.doesNotMatch(markup, /<img onerror/);
  assert.match(markup, /policy content could not be verified/);
  assert.match(markup, /Scan coverage/);
  const actions = rows[0].querySelector('.seller-actions').children;
  assert.equal(actions[0].dataset.payload, '+919150043065');
  assert.equal(actions[1].dataset.payload, 'https://wa.me/919150043065');
});

test('only return, exchange and refund show summaries; other policies show links', () => {
  const { context, element } = popup();
  const kinds = ['return', 'exchange', 'refund', 'shipping', 'cancellation', 'privacy', 'terms'];
  const policies = Object.fromEntries(kinds.map(kind => [kind, {
    status: 'extracted', source_url: `https://store.example/${kind}`,
    facts: Array.from({length: 5}, () => ({text: 'Raw source text must stay out of the panel'})),
  }]));
  const policy_summaries = Object.fromEntries(kinds.map(kind => [`${kind}_policy`, `Summary for ${kind}`]));
  context.sellerResponse = { analysis: { policies, policy_summaries } };
  vm.runInContext('renderSellerInsights(sellerResponse)', context);
  const rows = element('seller-insights-list').children.slice(2, 9);
  rows.forEach((row, i) => {
    assert.match(row.innerHTML, i < 3 ? new RegExp(`Summary for ${kinds[i]}`) : /Open policy page/);
    if (i >= 3) assert.doesNotMatch(row.innerHTML, /Summary for/);
    assert.doesNotMatch(row.innerHTML, /Raw source text|Published source excerpts|extracted terms|<details>/);
    assert.equal(row.querySelector('.seller-actions').children[0].dataset.payload, `https://store.example/${kinds[i]}`);
  });
});

test('summary policies keep a link when a summary is unavailable', () => {
  const { context, element } = popup();
  vm.runInContext(`renderSellerInsights({analysis: {contact_signals: {
    return_policy_url: 'https://store.example/returns',
    privacy_policy_url: 'https://store.example/privacy'
  }}})`, context);
  const rows = element('seller-insights-list').children;
  assert.match(rows[2].innerHTML, /couldn&#39;t be summarised/);
  assert.equal(rows[2].querySelector('.seller-actions').children[0].dataset.payload, 'https://store.example/returns');
  assert.match(rows[7].innerHTML, /Open policy page/);
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
