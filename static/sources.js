const $ = s => document.querySelector(s);
let _editTxtId = null;

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtUtcTime(t) {
  if (!t) return '';
  const d = new Date(String(t).replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? String(t) : d.toLocaleString();
}

function renderSummary(sources) {
  const el = $('#srcSummary');
  if (!el) return;
  if (!sources.length) { el.innerHTML = ''; return; }
  const total = sources.length;
  const prox = sources.reduce((a, s) => a + (s.count || 0), 0);
  const work = sources.reduce((a, s) => a + (s.working || 0), 0);
  el.innerHTML =
    `<span>источников: <b>${total}</b></span>` +
    `<span>прокси: <b>${prox}</b></span>` +
    `<span>рабочих: <b>${work}</b></span>`;
}

function renderList(sources) {
  const list = $('#list');
  list.innerHTML = '';
  if (!sources.length) {
    list.innerHTML = '<div class="empty">// источников пока нет — добавьте URL-подписку или TXT-список ниже</div>';
    return;
  }
  for (const s of sources) {
    const card = document.createElement('div');
    card.className = 'card';
    const isTxt = (s.type || 'url') === 'txt';
    const imported = s.last_import ? fmtUtcTime(s.last_import) : 'никогда';
    const count = s.count != null ? s.count : '—';
    const working = s.working != null ? s.working : 0;
    card.innerHTML = `
      <div class="c-body">
        <div class="c-name">
          <span class="c-type ${isTxt ? 'type-txt' : 'type-url'}">${isTxt ? 'TXT' : 'URL'}</span>
          ${esc(s.name)}
        </div>
        <div class="c-url" title="${isTxt ? 'TXT-источник' : esc(s.url)}">${isTxt ? 'TXT-источник' : esc(s.url)}</div>
        <div class="c-meta">
          <span class="c-counts">прокси: <b>${count}</b> · рабочих: <span class="${working > 0 ? 'ok' : 'bad'}">${working}</span></span>
          &nbsp;·&nbsp; импорт: ${imported}
        </div>
      </div>
      <div class="c-actions">
        ${isTxt ? `<button class="btn btn-sm" onclick="editTxtContent(${s.id})">изменить</button>` : ''}
        <button class="btn btn-sm btn-apply" onclick="importOne(${s.id})">импорт</button>
        <button class="btn btn-sm btn-danger" onclick="delSource(${s.id})">удалить</button>
      </div>
    `;
    list.appendChild(card);
  }
}

async function load() {
  const [sources, settings] = await Promise.all([
    api('GET', '/api/sources'),
    api('GET', '/api/settings'),
  ]);
  renderSummary(sources || []);
  renderList(sources || []);
  const chk = $('#chkSafeOnly');
  if (chk && settings.safe_only_import === 'true') {
    chk.checked = true;
  }
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-active'));
  document.querySelector(`.tab[data-tab="${tab}"]`).classList.add('tab-active');
  document.getElementById('urlSourceForm').style.display = tab === 'url' ? '' : 'none';
  document.getElementById('txtSourceForm').style.display = tab === 'txt' ? '' : 'none';
}

async function toggleSafeOnly() {
  const val = $('#chkSafeOnly').checked ? 'true' : 'false';
  await api('POST', '/api/settings', { safe_only_import: val });
  toast(`Безопасный импорт: ${val === 'true' ? 'включён' : 'выключен'}`);
}

// ─── Добавление ───

async function addProxy() {
  const link = $('#inpProxy').value.trim();
  if (!link) return toast('Вставьте vless:// ссылку', 'error');
  const res = await api('POST', '/api/add', { link });
  if (res.error) return toast(res.error, 'error');
  $('#inpProxy').value = '';
  toast('прокси добавлен — тест стартует, если нет другого замера', 'success');
}

async function addSource() {
  const name = $('#inpName').value.trim();
  const url = $('#inpUrl').value.trim();
  if (!name) return toast('Укажите имя источника', 'error');
  if (!url || !/^https?:\/\//i.test(url)) return toast('Некорректный URL подписки', 'error');
  const res = await api('POST', '/api/sources', { name, url });
  if (res.error) return toast(res.error, 'error');
  $('#inpName').value = '';
  $('#inpUrl').value = '';
  toast('источник добавлен', 'success');
  load();
}

async function addTxtSource() {
  const name = $('#inpNameTxt').value.trim();
  const content = $('#inpTxtContent').value.trim();
  if (!name) return toast('Укажите имя TXT-источника', 'error');
  if (!content) return toast('Вставьте vless:// ссылки (по одной на строку)', 'error');
  const res = await api('POST', '/api/sources/txt', { name, content });
  if (res.error) return toast(res.error, 'error');
  $('#inpNameTxt').value = '';
  $('#inpTxtContent').value = '';
  toast('TXT-источник добавлен', 'success');
  load();
}

// ─── Редактирование TXT ───

async function editTxtContent(id) {
  const res = await api('GET', `/api/sources/${id}/content`);
  if (res.error) return toast(res.error, 'error');
  _editTxtId = id;
  $('#dlgTxtContent').value = res.content || '';
  const dlg = document.getElementById('dlgEditTxt');
  dlg.showModal();
  document.body.classList.add('modal-open');
}

// Клик по подложке (вне окна диалога) закрывает его
(function setupDialogClickOutside() {
  const dlg = document.getElementById('dlgEditTxt');
  if (!dlg) return;
  dlg.addEventListener('close', () => document.body.classList.remove('modal-open'));
  dlg.addEventListener('click', (e) => {
    const r = dlg.getBoundingClientRect();
    const inside = e.clientX >= r.left && e.clientX <= r.right &&
                   e.clientY >= r.top && e.clientY <= r.bottom;
    if (!inside) dlg.close();
  });
})();

async function saveTxtContent(withImport) {
  const id = _editTxtId;
  if (id === null) return;
  const content = $('#dlgTxtContent').value.trim();
  if (!content) return toast('Содержимое не может быть пустым', 'error');
  const btn = $('#btnSaveTxt');
  if (btn) { btn.disabled = true; btn.textContent = 'Сохранение…'; }
  const res = await api('PUT', `/api/sources/${id}/content`, { content });
  if (res.error) {
    toast(res.error, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Сохранить'; }
    return;
  }
  document.getElementById('dlgEditTxt').close();
  _editTxtId = null;
  if (withImport) {
    toast('контент сохранён, импортируем…');
    const imp = await api('POST', `/api/sources/${id}/import`);
    if (imp.error) {
      toast(`импорт не удался: ${imp.error}`, 'error');
    } else {
      toast(`импортировано прокси: ${imp.added} — замеры запускаются отдельно`, 'success');
    }
  } else {
    toast('контент сохранён', 'success');
  }
  load();
}

// ─── Удаление / импорт ───

async function delSource(id) {
  if (!confirm('Удалить источник #' + id + '?')) return;
  await api('DELETE', `/api/sources/${id}`);
  toast('источник удалён');
  load();
}

async function importOne(id) {
  const btn = document.querySelector(`button[onclick*="importOne(${id})"]`);
  await busyButton(btn, 'Импорт…', async () => {
    const res = await api('POST', `/api/sources/${id}/import`);
    if (res.error) return toast(`импорт не удался: ${res.error}`, 'error');
    toast(`импортировано прокси: ${res.added} — замеры запускаются отдельно («Тест всех» на дашборде)`, 'success');
  });
  load();
}

async function importAll() {
  const btn = document.querySelector('button[onclick*="importAll"]');
  await busyButton(btn, 'Импортируем…', async () => {
    const res = await api('POST', '/api/sources/import-all');
    if (res.error) return toast(`импорт не удался: ${res.error}`, 'error');
    if (res.errors && res.errors.length) {
      toast(`импортировано ${res.added} прокси — ${res.errors.length} источник(ов) с ошибками`, 'error');
    } else {
      toast(`импортировано ${res.added} прокси — замеры запускаются отдельно`, 'success');
    }
  });
  load();
}

async function busyButton(btn, busyText, fn) {
  if (!btn) return fn();
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = busyText;
  try { return await fn(); }
  finally { btn.disabled = false; btn.textContent = old; }
}

// ─── Enter в формах = добавить ───
function bindEnter(id, fn) {
  const el = $(id);
  if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); fn(); } });
}
bindEnter('inpProxy', addProxy);
bindEnter('inpName', addSource);
bindEnter('inpUrl', addSource);
bindEnter('inpNameTxt', addTxtSource);

load();
