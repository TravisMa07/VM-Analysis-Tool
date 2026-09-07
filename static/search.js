// Optional feedback only: searching still works with JavaScript disabled.
const form = document.querySelector('.search-form');
if (form) {
  const button = form.querySelector('button');
  const status = document.querySelector('#search-status');
  form.addEventListener('submit', () => {
    button.disabled = true;
    button.textContent = 'Searching…';
    status.textContent = 'Requesting vulnerability data from NVD…';
  });
  window.addEventListener('pageshow', () => {
    button.disabled = false;
    button.textContent = 'Search';
    status.textContent = '';
  });
}
