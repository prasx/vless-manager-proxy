function toast(msg, type) {
  type = type || 'info';
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add('toast-in'));
  setTimeout(() => {
    el.classList.remove('toast-in');
    el.addEventListener('transitionend', () => el.remove());
  }, 3000);
}
