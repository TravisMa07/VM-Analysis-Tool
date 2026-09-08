// Deterministic name and identifier matching; no embeddings required.
const normalizeTerm = value => value.toLowerCase().replace(/[^a-z0-9]/g, '');
function oneEdit(a, b) {
  if (Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const differences = [...a].map((value, i) => value !== b[i] ? i : -1).filter(i => i >= 0);
    return differences.length <= 1 || (differences.length === 2 && differences[1] === differences[0] + 1 &&
      a[differences[0]] === b[differences[1]] && a[differences[1]] === b[differences[0]]);
  }
  const [shorter, longer] = a.length < b.length ? [a, b] : [b, a];
  return [...longer].some((_, i) => longer.slice(0, i) + longer.slice(i + 1) === shorter);
}
function termScore(term, query) {
  const value = normalizeTerm(term), key = normalizeTerm(query);
  if (!key) return 99;
  if (value === key) return 0;
  if (value.startsWith(key)) return 1;
  if (term.split(/[\s-]+/).some(word => normalizeTerm(word).startsWith(key))) return 2;
  if (key.length >= 5 && /^[a-z]+$/.test(key) && oneEdit(value, key)) return 3;
  return 99;
}
function identifierScore(cveId, query) {
  const key = normalizeTerm(query);
  if (/^\d+$/.test(key)) {
    const number = cveId.split('-').pop();
    return number === key ? 0 : number.startsWith(key) ? 1 : 99;
  }
  return termScore(cveId, query);
}
function rankCatalog(catalog, query) {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const seen = new Set();
  return catalog.map(item => {
    const scores = [item.label, item.query, ...item.aliases].map(value => {
      return termScore(value, q);
    });
    return { item, score: Math.min(...scores) };
  }).filter(match => match.score < 99)
    .sort((a, b) => a.score - b.score || a.item.label.localeCompare(b.item.label))
    .filter(({ item }) => {
      const key = item.query.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).slice(0, 4).map(({ item }) => item);
}
function rankVulnerabilities(index, query) {
  if (query.trim().length < 2) return [];
  return index.map(item => {
    let score = Math.min(identifierScore(item.cveId, query),
      ...[item.label, ...item.aliases].map(term => termScore(term, query)));
    const related = item.relatedTerms.find(term => termScore(term, query) < 3);
    let title = item.label;
    if (score === 99 && related) { score = 4; title += ` — Related to ${related}`; }
    return { ...item, title, score };
  }).filter(item => item.score < 99).sort((a, b) => a.score - b.score || a.cveId.localeCompare(b.cveId)).slice(0, 4);
}
function mergeVulnerabilities(indexed, live) {
  const seen = new Set();
  return [...indexed.filter(item => item.score < 4),
    ...live.filter(item => !indexed.some(entry => entry.cveId === item.cveId)),
    ...indexed.filter(item => item.score === 4)]
    .filter(item => { if (seen.has(item.cveId)) return false; seen.add(item.cveId); return true; }).slice(0, 4);
}
if (typeof module !== 'undefined') module.exports = { rankCatalog, rankVulnerabilities, mergeVulnerabilities };

const form = typeof document !== 'undefined' && document.querySelector('.search-form');
if (form) {
  const input = form.querySelector('.search-input');
  const button = form.querySelector('button[type="submit"]');
  const status = document.querySelector('#search-status');
  const menu = document.querySelector('#search-suggestions');
  const hint = document.querySelector('#suggestion-status');
  const demo = form.dataset?.demo === 'true';
  const demoRecords = demo ? JSON.parse(document.querySelector('#demo-records').textContent) : [];
  let catalog = [], vulnerabilityIndex = [], live = [], options = [], active = -1;
  let timer, controller, generation = 0, composing = false;
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-controls', menu.id);
  input.setAttribute('aria-expanded', 'false');
  input.setAttribute('autocomplete', 'off');

  function cancel() {
    generation++;
    clearTimeout(timer);
    controller?.abort();
    hint.textContent = '';
  }
  function close() {
    cancel();
    menu.hidden = true;
    active = -1;
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
  }
  function highlight(index) {
    active = index;
    Array.from(menu.children).forEach((row, i) => row.setAttribute('aria-selected', String(i === active)));
    if (active >= 0) {
      input.setAttribute('aria-activedescendant', menu.children[active].id);
      menu.children[active].scrollIntoView({ block: 'nearest' });
    } else input.removeAttribute('aria-activedescendant');
  }
  function choose(index) {
    const option = options[index];
    if (!option) return;
    close();
    if (option.cveId) window.location.assign(`/cve/${encodeURIComponent(option.cveId)}${demo ? "?demo=1" : ""}`);
    else {
      input.value = option.query;
      form.requestSubmit();
    }
  }
  function render() {
    const query = input.value.trim();
    const selected = options[active];
    options = [...rankCatalog(catalog, query), ...mergeVulnerabilities(rankVulnerabilities(vulnerabilityIndex, query), live),
      { label: `Search for “${query}”`, category: 'Search', query }];
    menu.replaceChildren();
    options.forEach((option, index) => {
      const row = document.createElement('li');
      row.id = `suggestion-${index}`;
      row.setAttribute('role', 'option');
      const label = document.createElement('strong');
      label.textContent = option.cveId || option.label;
      const description = document.createElement('span');
      description.textContent = option.cveId ? option.title : option.category;
      row.append(label, description);
      row.addEventListener('pointerdown', event => event.preventDefault());
      row.addEventListener('click', () => choose(index));
      menu.append(row);
    });
    highlight(selected ? options.findIndex(option => selected.cveId ? option.cveId === selected.cveId :
      option.query === selected.query && option.category === selected.category) : -1);
    menu.hidden = false;
    input.setAttribute('aria-expanded', 'true');
  }
  function update() {
    cancel();
    live = [];
    active = -1;
    const query = input.value.trim();
    if (composing || query.length < 2) { close(); return; }
    if (demo) {
      live = demoRecords.filter(item => `${item.cveId} ${item.title} ${item.summary}`.toLowerCase().includes(query.toLowerCase())).slice(0, 4);
      render(); return;
    }
    render();
    if (query.length < 3 || query.length > 200) return;
    const version = generation;
    timer = setTimeout(async () => {
      controller = new AbortController();
      hint.textContent = 'Loading CVE suggestions…';
      try {
        const response = await fetch(`/api/suggestions?q=${encodeURIComponent(query)}`, { signal: controller.signal });
        if (!response.ok) throw new Error('Suggestions unavailable');
        const records = await response.json();
        if (version !== generation) return;
        live = records;
        render();
        const count = options.filter(option => option.cveId).length;
        hint.textContent = count ? `${count} CVE suggestions available.` : 'No indexed CVE matches. You can still search NVD.';
      } catch (error) {
        if (version === generation && error.name !== 'AbortError') {
          hint.textContent = 'Live suggestions unavailable. You can still search.';
        }
      }
    }, 500);
  }
  if (!demo) fetch('/static/suggestion-catalog.json').then(response => response.json()).then(data => {
    catalog = data;
    if (!menu.hidden) render();
  }).catch(() => {});
  if (!demo) fetch('/static/vulnerability-index.json').then(response => response.json()).then(data => {
    vulnerabilityIndex = data;
    if (!menu.hidden) render();
  }).catch(() => {});
  input.addEventListener('input', update);
  input.addEventListener('focus', update);
  input.addEventListener('compositionstart', () => { composing = true; close(); });
  input.addEventListener('compositionend', () => { composing = false; update(); });
  input.addEventListener('keydown', event => {
    if (event.isComposing) return;
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    if (event.key === 'Tab') close();
    if (['ArrowDown', 'ArrowUp'].includes(event.key)) {
      event.preventDefault();
      if (menu.hidden) update();
      if (!menu.hidden) highlight(active < 0 ? (event.key === 'ArrowDown' ? 0 : options.length - 1) :
        (active + (event.key === 'ArrowDown' ? 1 : options.length - 1)) % options.length);
    }
    if (event.key === 'Enter' && !menu.hidden && active >= 0) {
      event.preventDefault();
      choose(active);
    }
  });
  document.addEventListener('pointerdown', event => { if (!form.contains(event.target)) close(); });
  form.addEventListener('focusout', event => { if (!form.contains(event.relatedTarget)) close(); });
  form.addEventListener('submit', () => {
    close();
    button.disabled = true;
    button.textContent = 'Searching…';
    status.textContent = demo ? 'Loading demo results…' : 'Requesting vulnerability data from NVD…';
  });
  window.addEventListener('pageshow', () => {
    close();
    button.disabled = false;
    button.textContent = 'Search';
    status.textContent = '';
  });
}
