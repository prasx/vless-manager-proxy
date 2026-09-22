(function() {
  const html = document.documentElement;
  const key = 'xray-theme';

  function setTheme(t) {
    html.setAttribute('data-theme', t);
    localStorage.setItem(key, t);
  }

  function toggleTheme() {
    const cur = html.getAttribute('data-theme');
    setTheme(cur === 'light' ? 'dark' : 'light');
  }

  const saved = localStorage.getItem(key);
  if (saved === 'light' || saved === 'dark') {
    html.setAttribute('data-theme', saved);
  }

  window.toggleTheme = toggleTheme;
})();

function toggleNav() {
  const nav = document.getElementById('mainNav');
  const toggle = document.getElementById('navToggle');
  if (!nav) return;
  const open = nav.classList.toggle('nav-open');
  if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
}
