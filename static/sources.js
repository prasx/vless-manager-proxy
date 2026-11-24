// Страница источников: сводка, состав конфига, список, импорт, диагностика.
// $, esc(), fmtUtcTime() и api() приходят из api.js.

let _editTxtId = null;

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

const VERDICT_CLASS = {
  healthy: 'healthy',
  weak: 'weak',
  bad: 'bad',
  stale: 'stale',
  broken: 'broken',
  inactive: 'inactive',
  duplicate: 'duplicate',
  empty: 'empty',
};

const DIAG_STEP_LABELS = { url: 'URL', dns: 'DNS', tcp: 'TCP', tls: 'TLS', http: 'HTTP' };

function statusText(status) {
  if (!status) return 'не было';
  return IMPORT_STATUS_LABELS[status] || status;
}

function statusClass(status) {
  return IMPORT_STATUS_CLASS[status] || 'muted';
}

function fmtSpeed(kbps) {
  if (!kbps) return '—';
  return kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mbps` : `${kbps} Kbps`;
}

// Длинную причину отказа обрезаем до показа, полный текст остаётся в title:
// иначе неразрывная строка выходит за ячейку и наезжает на соседнюю колонку.
function shortError(text, limit = 60) {
  const s = String(text || '').trim();
  return s.length > limit ? s.slice(0, limit - 1) + '…' : s;
}

// В строке источника год не нужен: он есть в title, а в ячейку должно
// помещаться время и счётчики импорта без переносов на три строки.
function fmtImportTime(t) {
  const d = utcDate(t);
  if (!d) return t ? String(t) : '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// ─── Сводка ───

function renderSummary(sources) {
  const el = $('#srcSummary');
  if (!el) return;
  if (!sources.length) {
    el.textContent = 'Источников пока нет: добавьте подписку или список ссылок.';
    return;
  }
  const total = sources.reduce((a, s) => a + (s.count || 0), 0);
  const working = sources.reduce((a, s) => a + (s.working || 0), 0);
  const measured = sources.reduce((a, s) => a + (s.measured || 0), 0);
  const attention = sources.filter(s => ['weak', 'bad', 'stale', 'broken', 'duplicate', 'empty'].includes(s.verdict)).length;
  const parts = [
    `Работают <b>${working}</b> из <b>${total}</b> профилей, замерено <b>${measured}</b>.`,
  ];
  if (attention) {
    parts.push(`<span class="text-warn">Требуют внимания ${attention} из ${sources.length} источников.</span>`);
  } else {
    parts.push('Все источники в норме.');
  }
  el.innerHTML = parts.join(' ');
}

// ─── Список источников: таблица на десктопе, карточки на телефоне ───

function ratioPct(s) {
  const total = s.count || 0;
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round(((s.working || 0) / total) * 100)));
}

function sourceActionsHTML(s) {
  const isTxt = (s.type || 'url') === 'txt';
  const edit = isTxt
    ? `<button class="btn btn-sm btn-ghost" type="button" onclick="editTxtContent(${s.id})">изменить</button>`
    : `<button class="btn btn-sm btn-ghost" type="button" onclick="checkSource(${s.id})" title="Проверить доступность источника">связь</button>`;
  return `${edit}
    <button class="btn btn-sm" type="button" onclick="importOne(${s.id})">импорт</button>
    <button class="btn btn-sm btn-danger-ghost" type="button" onclick="delSource(${s.id})">удалить</button>`;
}

function renderList(sources) {
  const list = $('#list');
  if (!list) return;
  if (!sources.length) {
    list.innerHTML = '<div class="empty">// источников пока нет. Нажмите «Добавить источник или прокси» ниже.</div>';
    return;
  }

  const rows = sources.map(s => {
    const isTxt = (s.type || 'url') === 'txt';
    const count = s.count || 0;
    const working = s.working || 0;
    const measured = s.measured || 0;
    const verdict = s.verdict || 'inactive';
    const vcls = VERDICT_CLASS[verdict] || 'inactive';
    const importedFull = s.last_import ? fmtUtcTime(s.last_import) : 'не было';
    const imported = s.last_import ? fmtImportTime(s.last_import) : 'не было';
    const reco = s.recommendation || '';
    const importCounts = s.last_parsed > 0
      ? `новых ${s.last_added || 0} · дублей ${s.last_duplicates || 0}`
      : '';
    return `<tr>
      <td class="id">${s.priority || '—'}</td>
      <td>
        <span class="src-name">${esc(s.name || '#' + s.id)}</span>
        <span class="src-type">${isTxt ? 'TXT' : 'URL'}</span>
        <span class="src-url" title="${isTxt ? 'TXT-источник' : esc(s.url)}">${isTxt ? 'TXT-источник' : esc(s.url)}</span>
        ${s.last_error ? `<span class="src-error" title="${esc(s.last_error)}">${esc(shortError(s.last_error))}</span>` : ''}
      </td>
      <td class="src-out">
        <b>${working}</b> / ${count}
        <span class="src-ratio" title="рабочих ${working} из ${count}"><span style="width:${ratioPct(s)}%"></span></span>
        <span class="src-measured">замерено ${measured}</span>
      </td>
      <td>
        <span class="badge st-${statusClass(s.last_status)}">${esc(statusText(s.last_status))}</span>
        <span class="src-import-time" title="${esc(importedFull)}">${esc(imported)}</span>
        ${importCounts ? `<span class="src-import-counts">${esc(importCounts)}</span>` : ''}
      </td>
      <td class="src-verdict">
        <span class="src-score">${s.score != null ? s.score : 0}</span>
        <span class="${vcls}" title="${esc(reco)}">${esc(s.verdict_label || '—')}</span>
      </td>
      <td class="src-actions">${sourceActionsHTML(s)}</td>
    </tr>`;
  }).join('');

  const cards = sources.map(s => {
    const isTxt = (s.type || 'url') === 'txt';
    const verdict = s.verdict || 'inactive';
    const vcls = VERDICT_CLASS[verdict] || 'inactive';
    const importedFull = s.last_import ? fmtUtcTime(s.last_import) : 'не было';
    const imported = s.last_import ? fmtImportTime(s.last_import) : 'не было';
    const measured = s.measured || 0;
    const reco = s.recommendation || '';
    const importCounts = s.last_parsed > 0
      ? `<span>новых <b>${s.last_added || 0}</b>, дублей <b>${s.last_duplicates || 0}</b></span>`
      : '';
    return `<div class="src-card">
      <div class="src-card-top">
        <span class="src-type">${isTxt ? 'TXT' : 'URL'}</span>
        <span class="src-name">${esc(s.name || '#' + s.id)}</span>
        <span class="src-score">${s.score != null ? s.score : 0}</span>
        <span class="${vcls}">${esc(s.verdict_label || '—')}</span>
      </div>
      <div class="src-url" title="${isTxt ? 'TXT-источник' : esc(s.url)}">${isTxt ? 'TXT-источник' : esc(s.url)}</div>
      ${s.last_error ? `<div class="src-error" title="${esc(s.last_error)}">${esc(shortError(s.last_error, 90))}</div>` : ''}
      <div class="src-card-meta">
        <span>рабочих <b>${s.working || 0}</b> из <b>${s.count || 0}</b></span>
        <span>замерено <b>${measured}</b></span>
        <span title="${esc(importedFull)}">импорт: ${esc(statusText(s.last_status))}, ${esc(imported)}</span>
        ${importCounts}
      </div>
      ${reco && verdict !== 'healthy' ? `<div class="src-reco">${esc(reco)}</div>` : ''}
      <div class="src-card-actions">${sourceActionsHTML(s)}</div>
    </div>`;
  }).join('');

  list.innerHTML = `
    <table class="src-table data-table">
      <colgroup>
        <col class="src-col-id"><col><col class="src-col-out"><col class="src-col-imp"><col class="src-col-val"><col class="src-col-act">
      </colgroup>
      <thead>
        <tr>
          <th class="num">#</th><th>Источник</th><th>Выход</th><th>Импорт</th><th>Оценка</th><th class="actions-head"><span class="sr-only">Действия</span></th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="src-cards">${cards}</div>`;
}

// ─── Состав конфига: что уйдёт в Xray и подписку ───

const EXCLUDE_LABELS = {
  stale: 'устарело',
  slow: 'медленнее порога',
  unmeasured: 'без замера',
  blocked: 'страна исключена',
  invalid: 'битая ссылка',
};

function renderConfigPreview(d) {
  const el = $('#configPreview');
  if (!el) return;
  const c = d.counts || {};
  const s = d.settings || {};
  const selected = d.selected || [];
  const measured = selected.filter(r => r.tier === 1).length;
  const excluded = c.stale + c.slow + c.unmeasured + c.blocked + c.invalid;

  const stats = [
    `<span class="cp-stat">в конфиг <b>${selected.length}</b> из <b>${c.working_total || 0}</b> рабочих</span>`,
    `<span class="cp-stat">замерено <b>${measured}</b></span>`,
    `<span class="cp-stat">свежесть до <b>${d.fresh_minutes}</b> мин</span>`,
    `<span class="cp-stat">лимит <b>${s.max_active_proxies != null ? s.max_active_proxies : '—'}</b></span>`,
  ];
  if (excluded) {
    const parts = [];
    for (const key of ['stale', 'slow', 'unmeasured', 'blocked', 'invalid']) {
      if (c[key]) parts.push(`${EXCLUDE_LABELS[key]} ${c[key]}`);
    }
    stats.push(`<span class="cp-stat text-bad">отсеяно: ${parts.join(', ')}</span>`);
  }
  if (d.strict) {
    stats.push('<span class="cp-stat text-warn">только замеренные</span>');
  }

  let html = `<div class="cp-head">
      <h2>Состав конфига и подписки</h2>
      <span class="cp-sub">порядок: по приоритету, замеренные выше незамеренных</span>
    </div>
    <div class="cp-stats">${stats.join('')}</div>`;

  if (d.fallback === 'slow') {
    html += `<div class="cp-alert">Все замеренные профили медленнее порога скорости, временно используются они. Снизьте «Мин. скорость» или найдите узлы быстрее.</div>`;
  } else if (d.fallback === 'unmeasured') {
    html += `<div class="cp-alert">Строгий отбор не дал ни одного замеренного профиля, в конфиг идут незамеренные. Проверьте стадию замера скорости и URL замера.</div>`;
  } else if (d.fallback === 'stale') {
    html += `<div class="cp-alert">Нет свежих профилей, временно используются устаревшие. Запустите «Актуализировать».</div>`;
  }

  if (!selected.length) {
    if (d.strict) {
      html += '<div class="cp-alert">Включён строгий отбор «только замеренные», но замеренных свежих профилей нет. Запустите «Актуализировать» или выключите строгий отбор в настройках.</div>';
    } else {
      html += '<div class="empty">// нечего отправить в конфиг: нет рабочих свежих профилей</div>';
    }
    el.innerHTML = html;
    return;
  }

  const rows = selected.map(r => `<tr>
      <td>${esc(r.host)}</td>
      <td>${esc(r.country || '—')}</td>
      <td><span class="cp-tier ${r.tier === 1 ? 'ok' : 'muted'}">${esc(r.tier_label)}</span></td>
      <td class="num">${r.latency_vless} мс</td>
      <td class="num">${fmtSpeed(r.speed_kbps)}</td>
      <td>${r.age_min != null ? r.age_min + ' мин' : '—'}</td>
      <td>${esc(r.source_name || '—')}</td>
    </tr>`).join('');
  html += `<details class="cp-details">
      <summary>Показать отобранные профили (${selected.length})</summary>
      <div class="cp-table-wrap"><table class="cp-table">
        <thead><tr><th>Хост</th><th>Страна</th><th>Приоритет</th><th>Пинг</th><th>Скорость</th><th>Тест</th><th>Источник</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </details>`;

  const groups = {};
  for (const e of (d.excluded || [])) (groups[e.reason] = groups[e.reason] || []).push(e);
  const groupKeys = Object.keys(groups);
  if (groupKeys.length) {
    const items = groupKeys.map(key => {
      const list = groups[key];
      const totalForReason = c[key] != null ? c[key] : list.length;
      const sample = list.slice(0, 8).map(e =>
        `<li><span class="cp-ex-host">${esc(e.host)}</span>
           <span class="cp-ex-detail">${esc(e.detail || '')}</span></li>`).join('');
      const more = list.length > 8 ? `<li class="cp-ex-more">и ещё ${list.length - 8} показанных</li>` : '';
      const capped = totalForReason > list.length ? `, в ответе первые ${list.length}` : '';
      return `<div class="cp-group">
          <div class="cp-group-head">${EXCLUDE_LABELS[key] || key}: <b>${totalForReason}</b>${capped}</div>
          <ul class="cp-ex-list">${sample}${more}</ul>
        </div>`;
    }).join('');
    html += `<details class="cp-details">
        <summary>Почему не попали другие (${excluded})</summary>
        ${items}
      </details>`;
  }

  el.innerHTML = html;
}

// ─── Загрузка ───

async function load() {
  const list = $('#list');
  const err = $('#srcError');
  if (err) { err.hidden = true; err.innerHTML = ''; }
  if (list) list.innerHTML = '<div class="empty">// загрузка источников…</div>';
  const [sources, settings, preview] = await Promise.all([
    api('GET', '/api/sources'),
    api('GET', '/api/settings'),
    api('GET', '/api/config/preview'),
  ]);
  const cause = sources.error || settings.error;
  if (cause) {
    if (list) list.innerHTML = '';
    renderSummary([]);
    showLoadError(cause);
    return;
  }
  renderSummary(sources || []);
  renderList(sources || []);
  if (!preview.error) renderConfigPreview(preview);
  const chk = $('#chkSafeOnly');
  if (chk && settings.safe_only_import === 'true') chk.checked = true;
}

function showLoadError(cause) {
  const err = $('#srcError');
  if (!err) return;
  err.hidden = false;
  err.innerHTML = `<span>Не удалось загрузить источники: ${esc(cause)}</span>
    <button class="btn btn-sm" onclick="load()">повторить</button>`;
}

async function refreshStale() {
  const btn = $('#btnRefreshStale');
  await busyButton(btn, 'Запускаем…', async () => {
    const res = await api('POST', '/api/refresh-stale');
    if (res.busy) return toast('Идёт другой замер, попробуйте позже', 'error');
    if (res.error && !res.success) return toast(res.error, 'error');
    if (!res.success) return toast(res.reason || 'нечего актуализировать');
    if (res.speed_will_truncate) {
      toast(`в прогон ${res.queued} профилей, замеров успеет примерно ${res.speed_measurements} из-за бюджета ${res.speed_budget_sec}с`, 'info');
    } else {
      toast(`в прогон поставлено ${res.queued} профилей`, 'success');
    }
  });
  load();
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => {
    const on = t.dataset.tab === tab;
    t.classList.toggle('tab-active', on);
    t.setAttribute('aria-selected', on ? 'true' : 'false');
  });
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
    <button class="btn btn-sm btn-ghost" type="button" onclick="hideReport()">скрыть</button></div>`;
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
    <span class="ir-detail">${esc(counts.join(', '))}${reason ? (counts.length ? ', ' : '') + esc(reason) : ''}</span>
  </li>`;
}

function renderImportReport(title, results, summary) {
  const info = summary
    ? `новых ${summary.added}, уже было ${summary.duplicates}, без шифрования ${summary.skipped_unencrypted}`
      + `, ок ${summary.ok}, ошибок ${summary.failed}, пусто ${summary.empty}`
      + (summary.skipped ? `, пропущено ${summary.skipped}` : '')
      + `, ${summary.seconds} с`
    : `${results.length} источников`;
  const alert = summary && summary.network_down
    ? `<div class="ir-alert">Сеть недоступна: остальные источники пропущены, чтобы прогон не держал
       блокировку замеров. Проверьте «Прокси для импорта» в настройках или нажмите «Проверить связь».</div>`
    : '';
  showReport(reportHead(title, info) + alert +
    `<ul class="ir-list">${results.map(resultRow).join('')}</ul>`);
}

// ─── Диагностика связи ───

function renderDiagnose(reports, meta = {}) {
  const total = meta.total != null ? meta.total : reports.length;
  const checked = meta.checked != null ? meta.checked : reports.length;
  const skipped = meta.skipped || 0;
  if (!reports.length) {
    showReport(reportHead('Проверка источников', 'URL-источников нет'));
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
  const info = `${checked} из ${total} URL-источников; профили не тестируются: для них «Актуализировать»`
    + (skipped ? `; ${skipped} не проверялись, нажмите «связь» у источника` : '');
  showReport(reportHead('Проверка источников', info)
    + `<ul class="ir-list">${items}</ul>`);
}

async function checkConnectivity() {
  const btn = $('#btnCheckConnect');
  await busyButton(btn, 'Проверяем…', async () => {
    const res = await api('GET', '/api/import/diagnose');
    if (res.error) return toast(res.error, 'error');
    renderDiagnose(res.reports || [], {
      total: res.total,
      checked: res.checked,
      skipped: res.skipped,
    });
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

// ─── Добавление ───

async function addProxy() {
  const link = $('#inpProxy').value.trim();
  if (!link) return toast('Вставьте vless:// ссылку', 'error');
  const res = await api('POST', '/api/add', { link });
  if (res.error) return toast(res.error, 'error');
  $('#inpProxy').value = '';
  toast('прокси добавлен, тест стартует, если нет другого замера', 'success');
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
  if (!content) return toast('Вставьте vless:// ссылки по одной на строку', 'error');
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
    if (imp.error) toast(`импорт: ${imp.status_label || 'ошибка'}, ${imp.error}`, 'error');
    else toast(`импортировано прокси: ${imp.added}`, 'success');
  } else {
    toast('контент сохранён', 'success');
  }
  load();
}

// ─── Удаление и импорт ───

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
      toast(`${res.name || '#' + id}: ${res.status_label || statusText(res.status)}${res.reason ? ', ' + res.reason : ''}`,
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
      toast(`новых прокси: ${res.added}, источников с ошибкой: ${res.failed}`, 'error');
    } else {
      toast(`новых прокси: ${res.added}. Замеры запускаются отдельно`, 'success');
    }
  });
  load();
}

async function busyButton(btn, busyText, fn) {
  if (!btn) return fn();
  const disabled = btn.disabled;
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = busyText;
  try { return await fn(); }
  finally { btn.disabled = disabled; btn.textContent = old; }
}

function bindEnter(id, fn) {
  const el = $(id);
  if (el) el.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); fn(); }
  });
}
bindEnter('inpProxy', addProxy);
bindEnter('inpName', addSource);
bindEnter('inpUrl', addSource);
bindEnter('inpNameTxt', addTxtSource);

load();
