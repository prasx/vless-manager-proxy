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

// Мобильное меню закрывается кликом вне его и по Escape: иначе оно остаётся
// открытым поверх страницы после ухода в другую часть экрана.
document.addEventListener('click', (e) => {
  const nav = document.getElementById('mainNav');
  const toggle = document.getElementById('navToggle');
  if (!nav || !nav.classList.contains('nav-open')) return;
  if (nav.contains(e.target) || (toggle && toggle.contains(e.target))) return;
  nav.classList.remove('nav-open');
  if (toggle) toggle.setAttribute('aria-expanded', 'false');
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const nav = document.getElementById('mainNav');
  const toggle = document.getElementById('navToggle');
  if (!nav || !nav.classList.contains('nav-open')) return;
  nav.classList.remove('nav-open');
  if (toggle) toggle.setAttribute('aria-expanded', 'false');
});
