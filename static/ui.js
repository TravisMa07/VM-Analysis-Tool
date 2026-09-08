/* Progressive enhancement: ordinary forms and next-page links work without JS. */
(() => {
  document.documentElement.classList.add('js');
  document.querySelector('.clear-search')?.addEventListener('click', () => {
    const input = document.querySelector('.search-input');
    input.value = ''; input.dispatchEvent(new Event('input')); input.focus();
  });
  document.querySelectorAll('.copy-summary').forEach(button => button.addEventListener('click', async () => {
    const section = button.closest('details'), text = section.querySelector('textarea'), status = section.querySelector('.copy-status');
    try { await navigator.clipboard.writeText(text.value); status.textContent = 'Summary copied.'; }
    catch { text.focus(); text.select(); status.textContent = 'Select and copy the summary below.'; }
  }));
  const results = document.querySelector('.results');
  if (!results) return;
  const items = document.querySelector('#result-items'), count = document.querySelector('#result-count');
  const more = document.querySelector('#load-more'), status = document.querySelector('#pagination-status');
  let next = results.dataset.next === '' ? null : Number(results.dataset.next), total = Number(results.dataset.total), busy = false;
  const query = results.dataset.query;
  const key = `vm-results:${location.pathname}${location.search}`;
  const seen = new Set([...items.querySelectorAll('[data-cve]')].map(row => row.dataset.cve));
  function update() {
    count.textContent = `Showing ${seen.size} of ${total} results`;
    if (more) { more.hidden = next === null; if (next !== null) more.href = `/?q=${encodeURIComponent(query)}&startIndex=${next}`; }
    status.textContent = next === null && seen.size ? 'All results shown.' : '';
  }
  function append(item) {
    if (seen.has(item.cveId)) return;
    seen.add(item.cveId);
    const row = document.createElement('article'); row.className = 'result-row'; row.dataset.cve = item.cveId;
    const link = document.createElement('a'); link.href = `/cve/${encodeURIComponent(item.cveId)}`;
    const id = document.createElement('span'); id.className = 'result-id'; id.textContent = item.cveId;
    const title = document.createElement('h2'); title.textContent = item.title;
    link.append(id, title);
    const summary = document.createElement('p'); summary.textContent = item.summary;
    const meta = document.createElement('div'); meta.className = 'result-meta';
    const date = item.published ? new Date(item.published.slice(0, 10) + 'T00:00:00Z') : null;
    const published = date && !Number.isNaN(date.getTime()) ? date.toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric', timeZone:'UTC'}) : item.published || 'Not available';
    const score = item.cvssBaseScore == null ? 'N/A' : Number(item.cvssBaseScore).toFixed(1);
    meta.textContent = `CVSS ${score} · ${item.cvssSeverity || 'Severity unavailable'} · Published ${published}`;
    row.append(link, summary, meta); items.append(row);
  }
  let appended = [];
  // Restore only history traversal, never a freshly submitted query or normal reload.
  if (performance.getEntriesByType('navigation')[0]?.type === 'back_forward') {
    try {
      const saved = JSON.parse(sessionStorage.getItem(key));
      if (saved && Date.now() - saved.at < 30 * 60 * 1000) {
        appended = saved.items; appended.forEach(append); next = saved.next; total = saved.total; update();
        requestAnimationFrame(() => window.scrollTo(0, saved.scroll));
      }
    } catch { /* Storage is optional. */ }
  }
  window.addEventListener('pagehide', () => {
    try { sessionStorage.setItem(key, JSON.stringify({ items: appended, next, total, scroll: scrollY, at: Date.now() })); } catch {}
  });
  more?.addEventListener('click', async event => {
    event.preventDefault(); if (busy || next === null) return;
    busy = true; more.setAttribute('aria-disabled', 'true'); more.textContent = 'Loading…'; status.textContent = '';
    const offset = next;
    try {
      const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=10&startIndex=${offset}`);
      if (!response.ok) throw new Error('Search failed');
      const page = await response.json();
      const previousScroll = scrollY;
      const previousCount = items.children.length;
      page.results.forEach(item => { if (!seen.has(item.cveId)) { appended.push(item); append(item); } });
      total = page.totalResults;
      next = page.results.length && page.nextStartIndex > offset ? page.nextStartIndex : null;
      update();
      items.children[previousCount]?.querySelector('a')?.focus({preventScroll: true});
      window.scrollTo(0, previousScroll);
    } catch { status.textContent = 'Could not load more results. Your results are still here. Try again.'; }
    finally { busy = false; more.removeAttribute('aria-disabled'); more.textContent = 'Load more'; }
  });
})();
