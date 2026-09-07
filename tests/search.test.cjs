const { test } = require('node:test');
const assert = require('node:assert/strict');
const { rankCatalog, rankVulnerabilities, mergeVulnerabilities } = require('../static/search.js');
const catalog = require('../static/suggestion-catalog.json');
const vulnerabilityIndex = require('../static/vulnerability-index.json');

test('threshold, aliases, case folding, and word matches', () => {
  assert.deepEqual(rankCatalog(catalog, 'r'), []);
  assert.equal(rankCatalog(catalog, ' RCE ')[0].query, 'remote code execution');
  assert.equal(rankCatalog(catalog, 'sqli')[0].label, 'SQL injection');
  assert.equal(rankCatalog(catalog, 'bypass')[0].label, 'Authentication bypass');
  assert.ok(rankCatalog(catalog, 'open').length >= 2);
  assert.deepEqual(rankCatalog(catalog, 'unlistedvendor'), []);
});
test('exact before prefix before word matches; deduplicate and limit', () => {
  const item = label => ({ label, query: label, aliases: [] });
  const entries = [item('Some open'), item('OpenSSL'), item('open'), item('open'),
    item('OpenSSH'), item('OpenOther'), item('OpenMore')];
  const result = rankCatalog(entries, 'open');
  assert.equal(result[0].label, 'open');
  assert.equal(result.length, 4);
  assert.equal(new Set(result.map(item => item.query)).size, 4);
  assert.ok(!result.some(item => item.label === 'Some open'));
});

const vm = require('node:vm');
const fs = require('node:fs');
function harness() {
  class Element {
    constructor() { this.children = []; this.handlers = {}; this.attrs = {}; this.value = ''; this.hidden = true; }
    addEventListener(name, fn) { (this.handlers[name] ||= []).push(fn); }
    fire(name, extra = {}) { for (const fn of this.handlers[name] || []) fn({ preventDefault() {}, ...extra }); }
    setAttribute(name, value) { this.attrs[name] = value; }
    removeAttribute(name) { delete this.attrs[name]; }
    append(...children) { this.children.push(...children); }
    replaceChildren() { this.children = []; }
    scrollIntoView() {}
    contains(target) { return target === this || this.children.some(child => child.contains(target)); }
  }
  const input = new Element(), button = new Element(), menu = new Element(), hint = new Element();
  const form = new Element(), document = new Element(), window = new Element();
  menu.id = 'search-suggestions';
  form.append(input, button, menu, hint);
  form.querySelector = selector => selector === '.search-input' ? input : button;
  form.requestSubmit = () => { form.submitted = input.value; form.fire('submit'); };
  document.querySelector = selector => ({ '.search-form': form, '#search-suggestions': menu,
    '#suggestion-status': hint, '#search-status': new Element() })[selector];
  document.createElement = () => new Element();
  window.location = { assign: url => { window.destination = url; } };
  const requests = [], timers = new Map();
  let nextTimer = 0;
  vm.runInNewContext(fs.readFileSync(require.resolve('../static/search.js'), 'utf8'), {
    document, window, AbortController,
    setTimeout: fn => { timers.set(++nextTimer, fn); return nextTimer; },
    clearTimeout: id => timers.delete(id),
    fetch: (url, options) => url.includes('/static/') ? Promise.resolve({ json: async () => url.includes('catalog') ? catalog : vulnerabilityIndex }) :
      new Promise(resolve => requests.push({ url, options, resolve })),
  });
  return { input, menu, hint, form, window, requests,
    type(value) { input.value = value; input.fire('input'); },
    runTimer() { const callbacks = [...timers.values()]; timers.clear(); callbacks.forEach(fn => fn()); },
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
const reply = (request, records) => request.resolve({ ok: true, json: async () => records });

test('stale responses, dismissal, clearing, and failure preserve usable UI', async () => {
  const h = harness(); await settle();
  h.type('open'); h.runTimer();
  h.type('rce'); h.runTimer();
  assert.equal(h.requests[0].options.signal.aborted, true);
  reply(h.requests[1], [{ cveId: 'CVE-2024-0001', title: '<script>unsafe</script>' }]);
  await settle();
  assert.equal(h.menu.children[1].children[1].textContent, '<script>unsafe</script>');
  reply(h.requests[0], [{ cveId: 'CVE-2024-9999', title: 'Old' }]);
  await settle();
  assert.equal(h.menu.children[1].children[0].textContent, 'CVE-2024-0001');
  h.type('openssl'); h.runTimer(); h.input.fire('keydown', { key: 'Escape' });
  reply(h.requests[2], []); await settle(); assert.equal(h.menu.hidden, true);
  h.type('chrome'); h.runTimer(); h.type('');
  reply(h.requests[3], []); await settle(); assert.equal(h.menu.hidden, true);
  h.type('rce'); h.runTimer(); h.requests[4].resolve({ ok: false });
  await settle();
  assert.equal(h.menu.hidden, false);
  assert.match(h.hint.textContent, /unavailable/);
  assert.equal(h.menu.children[0].children[0].textContent, 'Remote code execution');
});
test('keyboard selection, search action, pointer selection, and CVE navigation', async () => {
  const h = harness(); await settle();
  h.type('op'); h.input.fire('keydown', { key: 'ArrowUp' });
  assert.equal(h.input.attrs['aria-activedescendant'], 'suggestion-2');
  h.input.fire('keydown', { key: 'Enter' }); assert.equal(h.form.submitted, 'op');
  h.type('rce'); h.input.fire('keydown', { key: 'ArrowDown' });
  h.runTimer(); reply(h.requests[0], [{ cveId: 'CVE-2024-0001', title: 'Example' }]); await settle();
  assert.equal(h.input.attrs['aria-activedescendant'], 'suggestion-0');
  h.input.fire('keydown', { key: 'Enter' }); assert.equal(h.form.submitted, 'remote code execution');
  h.type('openssl'); h.menu.children[0].fire('click'); assert.equal(h.form.submitted, 'OpenSSL');
  h.type('test'); h.runTimer(); reply(h.requests[1], [{ cveId: 'CVE-2024-0001', title: 'Example' }]); await settle();
  h.menu.children[0].fire('click'); assert.equal(h.window.destination, '/cve/CVE-2024-0001');
});

test('CVE number, full ID, names, spacing, prefixes, and conservative typos', () => {
  for (const query of ['46300', '4630', 'CVE-2026-46300', 'Fragnesia', 'fragn', 'fragnesa', 'frganesia']) {
    assert.equal(rankVulnerabilities(vulnerabilityIndex, query)[0].cveId, 'CVE-2026-46300', query);
  }
  for (const query of ['dirty frag', 'DirtyFrag', 'dirty-frag', 'dirty   frag']) {
    const matches = rankVulnerabilities(vulnerabilityIndex, query);
    assert.deepEqual(matches.map(item => item.cveId), ['CVE-2026-43284', 'CVE-2026-43500', 'CVE-2026-46300']);
    assert.match(matches[2].title, /Related to Dirty Frag/);
  }
  for (const query of ['46301', '!!!', 'unknownnickname']) assert.deepEqual(rankVulnerabilities(vulnerabilityIndex, query), []);
  assert.equal(rankCatalog(catalog, 'opnessl')[0].label, 'OpenSSL');
});
test('numeric matching includes multiple years, preserves names, and deduplicates live CVEs', () => {
  const extra = { ...vulnerabilityIndex[0], cveId: 'CVE-2025-46300', label: 'Test fixture' };
  const indexed = rankVulnerabilities([...vulnerabilityIndex, extra], '46300');
  assert.equal(indexed.length, 2);
  const merged = mergeVulnerabilities(indexed, [{ cveId: 'CVE-2026-46300', title: 'Live text' }]);
  assert.equal(merged.length, 2);
  assert.equal(merged.find(item => item.cveId === 'CVE-2026-46300').title, 'Fragnesia');
});
test('named CVEs are immediate and navigate even when live suggestions fail', async () => {
  const h = harness(); await settle();
  h.type('46300');
  assert.equal(h.menu.children[0].children[0].textContent, 'CVE-2026-46300');
  assert.equal(h.menu.children[0].children[1].textContent, 'Fragnesia');
  h.runTimer(); h.requests[0].resolve({ ok: false }); await settle();
  h.menu.children[0].fire('click');
  assert.equal(h.window.destination, '/cve/CVE-2026-46300');
});
