(() => {
  document.documentElement.classList.add('js');
  const form = document.querySelector('.search-form'), input = form.querySelector('input');
  const menu = document.querySelector('#search-suggestions');
  const rows = [...document.querySelectorAll('.result-row')], details = [...document.querySelectorAll('.offline-detail')];
  const results = document.querySelector('.results'), records = JSON.parse(document.querySelector('#demo-records').textContent);
  let active = -1, options = [];
  input.setAttribute('role', 'combobox'); input.setAttribute('aria-controls', menu.id); input.setAttribute('aria-autocomplete', 'list'); input.setAttribute('autocomplete', 'off');
  function close() { menu.hidden = true; active = -1; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); }
  function render() {
    const params = new URLSearchParams(location.hash.slice(1));
    const identifier = location.hash.slice(1), detail = details.find(section => section.id === identifier);
    details.forEach(section => section.hidden = section !== detail); results.hidden = !!detail;
    document.querySelector('main').classList.toggle('analysis-page', !!detail);
    if (!detail) {
      const query = params.get('q') || ''; input.value = query;
      rows.forEach(row => row.hidden = !row.textContent.toLowerCase().includes(query.toLowerCase()));
      const count = rows.filter(row => !row.hidden).length;
      document.querySelector('#result-count').textContent = `Showing ${count} of ${count} demo results`;
      document.querySelector('#pagination-status').textContent = count ? 'All results shown.' : 'No matching CVEs. Try a broader keyword.';
    }
    close();
  }
  function search() { location.hash = `q=${encodeURIComponent(input.value.trim())}`; close(); }
  function choose(i) { const option = options[i]; if (!option) return; if (option.cveId) location.hash = option.cveId; else search(); close(); }
  input.addEventListener('input', () => {
    const query = input.value.trim().toLowerCase(); close(); if (query.length < 2) return;
    options = [...records.filter(item => `${item.cveId} ${item.title} ${item.summary}`.toLowerCase().includes(query)), {title:`Search for “${input.value}”`}];
    menu.replaceChildren();
    options.forEach((item,i) => { const row = document.createElement('li'); row.id = `offline-option-${i}`; row.setAttribute('role','option'); row.textContent = item.cveId ? `${item.cveId} · ${item.title}` : item.title; row.addEventListener('pointerdown',e => e.preventDefault()); row.addEventListener('click',()=>choose(i)); menu.append(row); });
    menu.hidden = false; input.setAttribute('aria-expanded','true');
  });
  input.addEventListener('keydown', event => {
    if (event.isComposing) return;
    if (event.key === 'Escape' || event.key === 'Tab') close();
    if (!menu.hidden && ['ArrowDown','ArrowUp'].includes(event.key)) {
      event.preventDefault(); active = (active + (event.key === 'ArrowDown' ? 1 : options.length - 1) + options.length) % options.length;
      [...menu.children].forEach((row,i)=>row.setAttribute('aria-selected',String(i===active)));
      input.setAttribute('aria-activedescendant',menu.children[active].id);
    }
    if (event.key === 'Enter' && active >= 0) { event.preventDefault(); choose(active); }
  });
  document.addEventListener('pointerdown', event => { if (!form.contains(event.target)) close(); });
  form.addEventListener('focusout', event => { if (!form.contains(event.relatedTarget)) close(); });
  form.addEventListener('submit', event => { event.preventDefault(); search(); });
  form.querySelector('.clear-search').addEventListener('click', () => { input.value = ''; close(); input.focus(); });
  document.querySelectorAll('.copy-summary').forEach(button => button.addEventListener('click',async()=>{
    const section=button.closest('details'), text=section.querySelector('textarea'), status=section.querySelector('.copy-status');
    try { await navigator.clipboard.writeText(text.value); status.textContent='Summary copied.'; }
    catch { text.focus(); text.select(); status.textContent='Select and copy the summary below.'; }
  }));
  window.addEventListener('hashchange', () => { if (location.hash === '#content') return; render(); window.scrollTo(0,0); }); render();
})();
