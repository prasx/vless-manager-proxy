/* Колокольчик уведомлений.

   Попап — прямоугольник 9:16 (пропорция задана в style.css), внизу ссылка на
   логи целиком. Внутри — только WARN: это записи о том, что реально пошло не
   так (источник не импортировался, узел отвалился, прогон не прошёл). Полный
   журнал со всеми уровнями остаётся на странице логов, куда ведёт ссылка внизу.

   Непрочитанное считаем по id последней прочитанной записи в localStorage,
   поэтому счётчик переживает перезагрузку страницы и общий для всех вкладок
   панели. Открытие попапа помечает показанное прочитанным. */
(function () {
  const SEEN_KEY = 'vless.notif.seen';
  const LEVEL = 'WARN';         // единственный уровень, попадающий в уведомления
  const CLOSED_POLL_MS = 15000; // свёрнутый колокольчик: только за счётчиком
  const OPEN_POLL_MS = 4000;    // открытый попап: держим список свежим
  const PANEL_LIMIT = 40;
  const BADGE_MAX = 99;

  const bell = $('notifBell');
  const pop = $('notifPop');
  if (!bell || !pop) return;
  const badge = $('notifBadge');
  const list = $('notifList');
  const count = $('notifCount');

  let isOpen = false;
  let loading = false;
  let timer = null;
  let seen = readSeen();

  // ─── Прочитанное ───

  function readSeen() {
    const v = parseInt(localStorage.getItem(SEEN_KEY) || '0', 10);
    return Number.isFinite(v) && v > 0 ? v : 0;
  }

  function markSeen(id) {
    if (!id || id <= seen) return;
    seen = id;
    try {
      localStorage.setItem(SEEN_KEY, String(seen));
    } catch (_) {
      /* приватный режим: счётчик живёт до перезагрузки */
    }
  }

  function updateBadge(rows) {
    const unread = rows.filter(r => r.id > seen).length;
    if (isOpen || !unread) {
      hideBadge();
      return;
    }
    badge.textContent = unread > BADGE_MAX ? BADGE_MAX + '+' : String(unread);
    badge.hidden = false;
    bell.classList.add('has-unread');
    bell.title = `Предупреждения: ${unread} новых`;
  }

  function hideBadge() {
    badge.hidden = true;
    bell.classList.remove('has-unread');
    bell.title = 'Предупреждения';
  }

  // ─── Загрузка ───

  async function tick() {
    if (loading) return;
    loading = true;
    try {
      const data = await api('GET', `/api/logs?limit=${PANEL_LIMIT}&level=${LEVEL}`);
      if (data.error) {
        if (isOpen && !list.childElementCount) renderError(data.error);
        return;
      }
      const rows = data.logs || [];
      if (isOpen) {
        render(rows);
        markSeen(maxId(rows));
        hideBadge();
      } else {
        updateBadge(rows);
      }
    } finally {
      loading = false;
    }
  }

  function maxId(rows) {
    let max = seen;
    for (const r of rows) if (r.id > max) max = r.id;
    return max;
  }

  // ─── Отрисовка ───

  function render(rows) {
    list.innerHTML = '';
    setCount(rows.length);
    if (!rows.length) {
      renderNotice('предупреждений нет');
      return;
    }
    for (const row of rows) list.appendChild(itemEl(row));
  }

  function setCount(n) {
    if (!count) return;
    count.textContent = n ? `${n}` : '';
  }

  function renderNotice(text) {
    const el = document.createElement('div');
    el.className = 'notif-empty';
    el.textContent = text;
    list.appendChild(el);
  }

  function renderError(msg) {
    list.innerHTML = '';
    setCount(0);
    const box = document.createElement('div');
    box.className = 'notif-empty notif-empty-error';
    box.textContent = 'не удалось загрузить: ' + msg;
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'btn btn-sm';
    retry.textContent = 'повторить';
    retry.style.marginTop = '10px';
    retry.addEventListener('click', tick);
    list.appendChild(box);
    list.appendChild(retry);
  }

  function itemEl(row) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'notif-item';
    item.title = 'Открыть логи';
    item.addEventListener('click', () => { window.location.href = '/logs'; });

    const top = document.createElement('div');
    top.className = 'notif-item-top';

    const lvl = document.createElement('span');
    lvl.className = 'notif-lvl lvl-warn';
    lvl.textContent = LEVEL;
    top.appendChild(lvl);

    const time = document.createElement('span');
    time.className = 'notif-time';
    time.textContent = shortTime(row.timestamp);
    top.appendChild(time);

    const msg = document.createElement('div');
    msg.className = 'notif-msg';
    msg.textContent = row.message || '';

    item.appendChild(top);
    item.appendChild(msg);
    return item;
  }

  /** '2026-10-05 17:04:08' → '17:04:08', иначе строка как есть. */
  function shortTime(ts) {
    const s = String(ts == null ? '' : ts);
    return /\d{2}:\d{2}:\d{2}$/.test(s) ? s.slice(-8) : s;
  }

  // ─── Открытие и закрытие ───

  function openPop() {
    isOpen = true;
    pop.hidden = false;
    bell.setAttribute('aria-expanded', 'true');
    hideBadge();
    document.addEventListener('keydown', onKey);
    document.addEventListener('click', onOutside, true);
    window.addEventListener('scroll', closePop, { passive: true });
    tick();
    // Открытая панель опрашивается чаще закрытой — переводим таймер сразу,
    // не дожидаясь конца текущего интервала.
    schedule();
  }

  function closePop() {
    if (!isOpen) return;
    isOpen = false;
    pop.hidden = true;
    bell.setAttribute('aria-expanded', 'false');
    document.removeEventListener('keydown', onKey);
    document.removeEventListener('click', onOutside, true);
    window.removeEventListener('scroll', closePop);
    tick();      // вернуть актуальный счётчик новой волны событий
    schedule();  // и вернуться к редкому опросу
  }

  function onKey(e) {
    if (e.key === 'Escape') {
      closePop();
      bell.focus();
    }
  }

  function onOutside(e) {
    // Клик внутри колокольчика или попапа попапом и управляется — закрываем только
    // клики снаружи. Проверяем вложенность явно, а не через общий родительский
    // элемент: так код не зависит от того, обёрнуты ли кнопка и панель в один узел.
    const target = e.target;
    if (target && (bell.contains(target) || pop.contains(target))) return;
    closePop();
  }

  bell.addEventListener('click', () => (isOpen ? closePop() : openPop()));

  // ─── Опрос ───

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      await tick();
      schedule();
    }, isOpen ? OPEN_POLL_MS : CLOSED_POLL_MS);
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      clearTimeout(timer);
      timer = null;
    } else if (!timer) {
      tick();
      schedule();
    }
  });

  schedule();
  tick();
})();
