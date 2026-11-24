// Страница источников: список, импорт, диагностика связи.
// $, esc(), fmtUtcTime() и api() приходят из api.js (подключается до этого файла).

let _editTxtId = null;

// Статусы импорта приходят с сервера кодами; подписи и цвета держим здесь.
const IMPORT_STATUS_LABELS = {
  ok: 'ок',
  not_modified: 'без изменений',
  empty: 'нет ссылок',
  no_content: 'пустой TXT',
  http_error: 'ошибка HTTP',
  network_error: 'сеть недоступна',
  bad_url: 'битый URL',
  skipped: 'пропущен',
  error: 'ошибка',
};

const IMPORT_STATUS_CLASS = {
  ok: 'ok',
  not_modified: 'muted',
  empty: 'warn',
  no_content: 'warn',
  http_error: 'bad',
  network_error: 'bad',
  bad_url: 'bad',
  skipped: 'muted',
  error: 'bad',
};

const DIAG_STEP_LABELS = { url: 'URL', dns: 'DNS', tcp: 'TCP', tls: 'TLS', http: 'HTTP' };

function statusText(status) {
  if (!status) return '—';
  return IMPORT_STATUS_LABELS[status] || status;
}

function statusClass(status) {
  return IMPORT_STATUS_CLASS[status] || 'muted';
}

function renderSummary(sources) {
  const el = $('#srcSummary');
  if (!el) return;
  if (!sources.length) { el.innerHTML = ''; return; }
  const total = sources.length;
  const prox = sources.reduce((a, s) => a + (s.count || 0), 0);
  const work = sources.reduce((a, s) => a + (s.working || 0), 0);
  const measured = sources.reduce((a, s) => a + (s.measured || 0), 0);
  const attention = sources.filter(s => ['weak', 'bad', 'stale', 'broken'].includes(s.verdict)).length;
  const broken = sources.filter(s => s.last_status &&
    ['network_error', 'http_error', 'bad_url', 'error'].includes(s.last_status)).length;
  el.innerHTML =
    `<span>источников: <b>${total}</b></span>` +
    `<span>прокси: <b>${prox}</b></span>` +
    `<span>рабочих: <b>${work}</b></span>` +
    `<span>замерено: <b>${measured}</b></span>` +
    (attention ? `<span class="summary-warn">требуют внимания: <b>${attention}</b></span>` : '') +
    (broken ? `<span class="summary-bad">с ошибкой импорта: <b>${broken}</b></span>` : '');
}

// Подписи и цвета вердиктов источников приходят кодами — держим их здесь.
const VERDICT_CLASS = {
  healthy: 'ok',
  weak: 'warn',
  bad: 'bad',
  stale: 'warn',
  broken: 'bad',
  inactive: 'muted',
};

function renderList(sources) {
  const list = $('#list');
  list.innerHTML = '';
  if (!sources.length) {
    list.innerHTML = '<div class="empty">// источников пока нет. Добавьте URL-подписку или TXT-список ниже</div>';
    return;
  }
  for (const s of sources) {
    const card = document.createElement('div');
    card.className = 'card';
    const isTxt = (s.type || 'url') === 'txt';
    const imported = s.last_import ? fmtUtcTime(s.last_import) : 'никогда';
    const count = s.count != null ? s.count : 'нет';
    const working = s.working != null ? s.working : 0;
    const measured = s.measured != null ? s.measured : 0;
    const score = s.score != null ? s.score : 0;
    const verdict = s.verdict || 'inactive';
    const st = s.last_status;
    const stTitle = [s.last_error, s.last_import ? 'последний импорт: ' + imported : '']
      .filter(Boolean).join(' · ');
    card.innerHTML = `
      <div class="c-body">
        <div class="c-name">
          <span class="c-type ${isTxt ? 'type-txt' : 'type-url'}">${isTxt ? 'TXT' : 'URL'}</span>
          <span class="c-prio" title="Приоритет по качеству источника">#${s.priority || '—'}</span>
          ${esc(s.name)}
          <span class="c-quality v-${VERDICT_CLASS[verdict] || 'muted'}"
                title="Оценка источника: ${score}/100 · ${esc(s.recommendation || '')}">${score}</span>
          <span class="c-status st-${statusClass(st)}" title="${esc(stTitle)}">импорт: ${esc(statusText(st))}</span>
        </div>
        <div class="c-url" title="${isTxt ? 'TXT-источник' : esc(s.url)}">${isTxt ? 'TXT-источник' : esc(s.url)}</div>
        <div class="c-meta">
          <span class="c-counts">прокси: <b>${count}</b> · рабочих: <span class="${working > 0 ? 'ok' : 'bad'}">${working}</span>
            · замерено: <b>${measured}</b> · качество: <b>${score}</b>
            <span class="c-verdict v-${VERDICT_CLASS[verdict] || 'muted'}">${esc(s.verdict_label || verdict)}</span></span>
          &nbsp;·&nbsp; импорт: ${imported}
        </div>
        ${s.recommendation && verdict !== 'healthy'
          ? `<div class="c-reco v-${VERDICT_CLASS[verdict] || 'muted'}">${esc(s.recommendation)}</div>` : ''}
        ${s.last_error ? `<div class="c-error" title="${esc(s.last_error)}">${esc(s.last_error)}</div>` : ''}
      </div>
      <div class="c-actions">
        ${isTxt ? `<button class="btn btn-sm" type="button" onclick="editTxtContent(${s.id})">изменить</button>` : ''}
        ${isTxt ? '' : `<button class="btn btn-sm" type="button" onclick="checkSource(${s.id})" title="Проверить доступность источника">связь</button>`}
        <button class="btn btn-sm btn-apply" type="button" onclick="importOne(${s.id})">импорт</button>
        <button class="btn btn-sm btn-danger" type="button" onclick="delSource(${s.id})">удалить</button>
      </div>
    `;
    list.appendChild(card);
  }
}

// ─── Состав конфига: что реально уйдёт в Xray и подписку ───

const EXCLUDE_LABELS = {
  stale: 'устарело',
  slow: 'медленнее порога',
  unmeasured: 'без замера',
  blocked: 'страна исключена',
  invalid: 'битая ссылка',
};

function fmtSpeed(kbps) {
  if (!kbps) return '—';
  return kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mbps` : `${kbps} Kbps`;
}

function renderConfigPreview(d) {
  const el = $('#configPreview');
  if (!el) return;
  const c = d.counts || {};
  const s = d.settings || {};
  const selected = d.selected || [];
  const excluded = c.stale + c.slow + c.unmeasured + c.blocked + c.invalid;

  const chips = [
    `<span>в конфиг <b>${selected.length}</b> из <b>${c.working_total || 0}</b> рабочих</span>`,
    `<span>замерено <b>${selected.filter(r => r.tier === 1).length}</b> из <b>${selected.length}</b></span>`,
    `<span>свежесть ≤ <b>${d.fresh_minutes}</b> мин</span>`,
    `<span>лимит <b>${s.max_active_proxies != null ? s.max_active_proxies : '—'}</b></span>`,
  ];
  for (const key of ['stale', 'slow', 'unmeasured', 'blocked', 'invalid']) {
    if (c[key]) chips.push(`<span class="summary-bad">${EXCLUDE_LABELS[key]}: <b>${c[key]}</b></span>`);
  }
  if (!excluded) chips.push('<span>отсеяно: <b>0</b></span>');

  let html = `<div class="cp-chips">${chips.join('')}</div>`;

  if (d.fallback === 'slow') {
    html += `<div class="cp-alert">Все замеренные профили медленнее порога скорости —
      временно используются они. Снизьте «Мин. скорость» или найдите узлы быстрее.</div>`;
  } else if (d.fallback === 'unmeasured') {
    html += `<div class="cp-alert">Строгий отбор не дал ни одного замеренного профиля —
      в конфиг идут незамеренные. Проверьте стадию замера скорости и URL замера.</div>`;
  } else if (d.fallback === 'stale') {
    html += `<div class="cp-alert">Нет свежих профилей: временно используются устаревшие.
      Запустите «Актуализировать» или «Тест всех».</div>`;
  }

  if (!selected.length) {
    html += '<div class="empty">// нечего отправить в конфиг: нет рабочих свежих профилей</div>';
    el.innerHTML = html;
    return;
  }

  const rows = selected.map(r => `<tr>
      <td>${esc(r.host)}</td>
      <td>${esc(r.country || '—')}</td>
      <td><span class="cp-tier ${r.tier === 1 ? 'ok' : 'muted'}">${esc(r.tier_label)}</span></td>
      <td class="num">${r.latency_vless} ms</td>
      <td class="num">${fmtSpeed(r.speed_kbps)}</td>
      <td>${r.age_min != null ? r.age_min + ' мин' : '—'}</td>
      <td>${esc(r.source_name || '—')}</td>
    </tr>`).join('');
  html += `<details class="cp-details">
      <summary>показать отобранные профили (${selected.length})</summary>
      <div class="cp-table-wrap"><table class="cp-table">
        <thead><tr><th>хост</th><th>страна</th><th>приоритет</th><th>пинг</th><th>скорость</th><th>тест</th><th>источник</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </details>`;

  const groups = {};
  for (const e of (d.excluded || [])) {
    (groups[e.reason] = groups[e.reason] || []).push(e);
  }
  const groupKeys = Object.keys(groups);
  if (groupKeys.length) {
    const items = groupKeys.map(key => {
      const list = groups[key];
      const totalForReason = c[key] != null ? c[key] : list.length;
      const sample = list.slice(0, 8).map(e =>
        `<li><span class="cp-ex-host">${esc(e.host)}</span>
           <span class="cp-ex-detail">${esc(e.detail || '')}</span></li>`).join('');
      const more = list.length > 8 ? `<li class="cp-ex-more">…и ещё ${list.length - 8} показанных</li>` : '';
      const capped = totalForReason > list.length
        ? ` · в ответе первые ${list.length}` : '';
      return `<div class="cp-group">
          <div class="cp-group-head">${EXCLUDE_LABELS[key] || key}: <b>${totalForReason}</b>${capped}</div>
          <ul class="cp-ex-list">${sample}${more}</ul>
        </div>`;
    }).join('');
    html += `<details class="cp-details">
        <summary>почему не попали другие (${excluded})</summary>
        ${items}
      </details>`;
  }

  el.innerHTML = html;
}

async function load() {
  const list = $('#list');
  const err = $('#srcError');
  if (err) { err.hidden = true; err.innerHTML = ''; }
  list.innerHTML = '<div class="empty">// загрузка источников…</div>';
  const [sources, settings, preview] = await Promise.all([
    api('GET', '/api/sources'),
    api('GET', '/api/settings'),
    api('GET', '/api/config/preview'),
  ]);
  const cause = sources.error || settings.error;
  if (cause) {
    list.innerHTML = '';
    renderSummary([]);
    showLoadError(cause);
    return;
  }
  renderSummary(sources || []);
  renderList(sources || []);
  if (!preview.error) renderConfigPreview(preview);
  const chk = $('#chkSafeOnly');
  if (chk && settings.safe_only_import === 'true') {
    chk.checked = true;
  }
}

async function refreshStale() {
  const btn = $('#btnRefreshStale');
  await busyButton(btn, 'Запускаем…', async () => {
    const res = await api('POST', '/api/refresh-stale');
    if (res.busy) return toast('Идёт другой замер — попробуйте позже', 'error');
    if (res.error && !res.success) return toast(res.error, 'error');
    if (!res.success) return toast(res.reason || 'нечего актуализировать', 'info');
    if (res.speed_will_truncate) {
      toast(`в прогон ${res.queued} профилей, но замеров успеет ~${res.speed_measurements}`
        + ` из-за бюджета ${res.speed_budget_sec}с — увеличьте бюджет стадии скорости`, 'info');
    } else {
      toast(`в прогон поставлено ${res.queued} профилей`, 'success');
    }
  });
  load();
}


function showLoadError(cause) {
  const err = $('#srcError');
  if (!err) return;
  err.hidden = false;
  err.innerHTML = `<span>Не удалось загрузить источники: ${esc(cause)}</span>
    <button class="btn btn-sm" onclick="load()">повторить</button>`;
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-active'));
  document.querySelector(`.tab[data-tab="${tab}"]`).classList.add('tab-active');
  document.getElementById('urlSourceForm').style.display = tab === 'url' ? '' : 'none';
  document.getElementById('txtSourceForm').style.display = tab === 'txt' ? '' : 'none';
}

async function toggleSafeOnly() {
  const chk = $('#chkSafeOnly');
  const prev = !chk.checked;
  const val = chk.checked ? 'true' : 'false';
  const res = await api('POST', '/api/settings', { safe_only_import: val });
  if (res.error) {
    chk.checked = prev;
    return toast(res.error, 'error');
  }
  toast(`Безопасный импорт: ${val === 'true' ? 'включён' : 'выключен'}`);
}

// ─── Отчёт об импорте ───

function hideReport() {
  const box = $('#importReport');
  if (!box) return;
  box.hidden = true;
  box.innerHTML = '';
}

function showReport(html) {
  const box = $('#importReport');
  if (!box) return;
  box.innerHTML = html;
  box.hidden = false;
}

function reportHead(title, info) {
  return `<div class="ir-head"><b>${esc(title)}</b><span>${esc(info)}</span>
    <button class="btn btn-sm" type="button" onclick="hideReport()">скрыть</button></div>`;
}

function resultRow(r) {
  const counts = [];
  if (r.added) counts.push(`новых ${r.added}`);
  if (r.duplicates) counts.push(`уже было ${r.duplicates}`);
  if (r.skipped_unencrypted) counts.push(`без шифрования ${r.skipped_unencrypted}`);
  if (r.deleted) counts.push(`удалено устаревших ${r.deleted}`);
  if (r.seconds) counts.push(`${r.seconds} с`);
  const reason = r.reason || r.error || '';
  return `<li class="ir-item st-${statusClass(r.status)}">
    <span class="ir-name">${esc(r.name || '#' + r.id)}</span>
    <span class="ir-status">${esc(r.status_label || statusText(r.status))}</span>
    <span class="ir-detail">${esc(counts.join(' · '))}${reason ? (counts.length ? ' — ' : '') + esc(reason) : ''}</span>
  </li>`;
}

function renderImportReport(title, results, summary) {
  const info = summary
    ? `новых ${summary.added} · уже было ${summary.duplicates} · без шифрования ${summary.skipped_unencrypted}`
      + ` · ок ${summary.ok} · ошибок ${summary.failed} · пусто ${summary.empty}`
      + (summary.skipped ? ` · пропущено ${summary.skipped}` : '')
      + ` · ${summary.seconds} с`
    : `${results.length} источник(ов)`;
  const alert = summary && summary.network_down
    ? `<div class="ir-alert">Сеть недоступна: остальные источники пропущены, чтобы прогон не держал
       блокировку замеров. Проверьте «Прокси для импорта» (настройки → Сеть) или нажмите «Проверить связь».</div>`
    : '';
  showReport(reportHead(title, info) + alert +
    `<ul class="ir-list">${results.map(resultRow).join('')}</ul>`);
}

// ─── Диагностика связи ───

function renderDiagnose(reports) {
  if (!reports.length) {
    showReport(reportHead('Проверка связи', 'URL-источников нет'));
    return;
  }
  const items = reports.map(rep => {
    const steps = (rep.steps || []).map(s =>
      `<span class="dg-step ${s.ok ? 'ok' : 'bad'}" title="${esc(s.detail || '')}">`
      + `${esc(DIAG_STEP_LABELS[s.step] || s.step)}${s.ms != null ? ' ' + s.ms + ' мс' : ''}</span>`
    ).join('');
    return `<li class="ir-item st-${rep.ok ? 'ok' : 'bad'}">
      <span class="ir-name">${esc((rep.url || '').replace(/^https?:\/\//, '').slice(0, 60))}</span>
      <span class="dg-steps">${steps}</span>
      <span class="ir-detail">${esc(rep.hint || '')}</span>
    </li>`;
  }).join('');
  showReport(reportHead('Проверка связи', `${reports.length} хост(ов) · DNS → TCP → TLS → HTTP`)
    + `<ul class="ir-list">${items}</ul>`);
}

async function checkConnectivity() {
  const btn = $('#btnCheckConnect');
  await busyButton(btn, 'Проверяем…', async () => {
    const res = await api('GET', '/api/import/diagnose');
    if (res.error) return toast(res.error, 'error');
    renderDiagnose(res.reports || []);
  });
}

async function checkSource(id) {
  const btn = document.querySelector(`button[onclick*="checkSource(${id})"]`);
  await busyButton(btn, 'Проверяем…', async () => {
    const res = await api('GET', `/api/import/diagnose?source_id=${id}`);
    if (res.error) return toast(res.error, 'error');
    renderDiagnose(res.reports || []);
  });
}

// Добавление

async function addProxy() {
  const link = $('#inpProxy').value.trim();
  if (!link) return toast('Вставьте vless:// ссылку', 'error');
  const res = await api('POST', '/api/add', { link });
  if (res.error) return toast(res.error, 'error');
  $('#inpProxy').value = '';
  toast('прокси добавлен. Тест стартует, если нет другого замера', 'success');
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

// Редактирование TXT

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
    const imp = await api('POST', `/api/sources/${id}/import`);
    renderImportReport(`Импорт источника #${id}`, [imp]);
    if (imp.error) toast(`импорт: ${imp.status_label || 'ошибка'} — ${imp.error}`, 'error');
    else toast(`импортировано прокси: ${imp.added}`, 'success');
  } else {
    toast('контент сохранён', 'success');
  }
  load();
}

// Удаление и импорт

async function delSource(id) {
  if (!confirm('Удалить источник #' + id + '?')) return;
  const res = await api('DELETE', `/api/sources/${id}`);
  if (res.error) return toast(`источник не удалён: ${res.error}`, 'error');
  toast('источник удалён', 'success');
  load();
}

async function importOne(id) {
  const btn = document.querySelector(`button[onclick*="importOne(${id})"]`);
  await busyButton(btn, 'Импорт…', async () => {
    const res = await api('POST', `/api/sources/${id}/import`);
    if (res.error && !res.status) return toast(`импорт не удался: ${res.error}`, 'error');
    renderImportReport(`Импорт источника #${id}`, [res]);
    if (res.status === 'ok') {
      toast(`импортировано прокси: ${res.added}${res.skipped_unencrypted ? `, без шифрования пропущено ${res.skipped_unencrypted}` : ''}`, 'success');
    } else {
      toast(`${res.name || '#' + id}: ${res.status_label || statusText(res.status)}${res.reason ? ' — ' + res.reason : ''}`,
        res.status === 'not_modified' ? 'info' : 'error');
    }
  });
  load();
}

async function importAll() {
  const btn = $('#btnImportAll');
  await busyButton(btn, 'Импортируем…', async () => {
    const res = await api('POST', '/api/sources/import-all');
    if (res.error) return toast(`импорт не удался: ${res.error}`, 'error');
    renderImportReport('Импорт всех источников', res.results || [], res);
    if (res.network_down) {
      toast('Сеть недоступна: прогон остановлен, подробности в отчёте', 'error');
    } else if (res.failed) {
      toast(`новых прокси: ${res.added}; источников с ошибкой: ${res.failed}`, 'error');
    } else {
      toast(`новых прокси: ${res.added}. Замеры запускаются отдельно`, 'success');
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

// Enter в формах: добавить
function bindEnter(id, fn) {
  const el = $(id);
  if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); fn(); } });
}
bindEnter('inpProxy', addProxy);
bindEnter('inpName', addSource);
bindEnter('inpUrl', addSource);
bindEnter('inpNameTxt', addTxtSource);

load();
