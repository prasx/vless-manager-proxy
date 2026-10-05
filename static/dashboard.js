// $, $$ и api() приходят из api.js (подключается до этого файла в base.html).

let currentFilter = '';
let currentSource = '';
let currentReason = '';
let allProxies = [];
let totalCount = 0;
let isLoading = false;
const PAGE_SIZE = 50;
const linkMap = {};
const selected = new Set();

function formatSpeed(kbps) {
  if (!kbps) return '<span class="dim">нет</span>';
  if (kbps >= 1000) return `${(kbps / 1000).toFixed(1)} Mbps`;
  return `${kbps} Kbps`;
}

// ─── Состояния данных: загрузка, ошибка, отсутствующее значение ───

function showDataError(text) {
  const box = $('#dataError');
  const label = $('#dataErrorText');
  if (!box || !label) return;
  label.textContent = '// ' + text;
  box.hidden = false;
}

function hideDataError() {
  const box = $('#dataError');
  if (box) box.hidden = true;
}

// Заглушка на время первой загрузки: пустая таблица читалась как «прокси нет».
function listPlaceholder(text) {
  return `<tr><td colspan="9" class="empty">${esc(text)}</td></tr>`;
}

function renderListLoading() {
  const tb = $('#tbodyDesktop');
  const list = $('#mobileList');
  if (tb) tb.innerHTML = listPlaceholder('// загрузка списка…');
  if (list) list.innerHTML = '<div class="empty" style="margin:0">// загрузка списка…</div>';
}

function renderListError(reason) {
  const msg = '// не удалось загрузить список: ' + (reason || 'нет ответа') + '. Нажмите «повторить» выше.';
  const tb = $('#tbodyDesktop');
  const list = $('#mobileList');
  if (tb) tb.innerHTML = listPlaceholder(msg);
  if (list) list.innerHTML = `<div class="empty" style="margin:0">${esc(msg)}</div>`;
}

let currentSearch = '';
let _initialMetaLoaded = false;

function makeProxiesUrl(limit, offset) {
  let url = '/api/proxies?filter=' + currentFilter;
  if (currentReason) {
    url += '&reason=' + encodeURIComponent(currentReason);
  }
  if (currentSource) {
    url += '&source=' + currentSource;
  }
  if (currentSearch) {
    url += '&search=' + encodeURIComponent(currentSearch);
  }
  if (limit != null) url += `&limit=${limit}&offset=${offset}`;
  return url;
}

let searchTimer;
$('#searchInput')?.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    currentSearch = $('#searchInput').value.trim();
    loadData();
  }, 300);
});

function setActiveFilter(f) {
  $$('.stat-card').forEach(el => {
    const on = el.dataset.filter === f;
    el.classList.toggle('active', on);
    el.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

function setFilter(f) {
  currentFilter = f;
  // reason-фильтр имеет смысл только в представлении «не работает»
  if (f !== 'failed' && currentReason) {
    currentReason = '';
    const sel = $('#reasonFilter');
    if (sel) sel.value = '';
  }
  setActiveFilter(f);
  loadData();
}

function setSource(src) {
  currentSource = src;
  updateSourceButtons();
  loadData();
}

// ─── Фильтр по причине отказа ───
const REASON_RU = {
  'timeout': 'таймаут',
  'connection refused': 'соединение отклонено',
  'connection reset': 'соединение сброшено',
  'dns lookup failed': 'DNS не резолвится',
  'tls error': 'ошибка TLS',
  'invalid link': 'некорректная ссылка',
  'xray start failed': 'Xray не стартовал',
  'internal test error': 'внутренняя ошибка теста',
};

function reasonRu(reason) {
  if (!reason) return '';
  if (reason === 'http') return 'HTTP-ошибка';
  for (const [k, v] of Object.entries(REASON_RU)) {
    if (reason.startsWith(k)) return v;
  }
  if (reason.startsWith('xray binary not found')) return 'нет бинарника Xray';
  return reason;
}

function renderReasonFilter(reasons) {
  const sel = $('#reasonFilter');
  if (!sel) return;
  const list = reasons || [];
  let opts = '<option value="">причина отказа: все</option>';
  if (list.length || (currentReason === 'none')) {
    opts += '<option value="none">без причины</option>';
  }
  for (const r of list) {
    opts += `<option value="${esc(r.reason)}" title="${esc(r.reason)}">${esc(reasonRu(r.reason))} · ${r.count}</option>`;
  }
  sel.innerHTML = opts;
  sel.style.display = list.length || currentReason === 'none' ? '' : 'none';
  if (currentReason && !list.some(x => x.reason === currentReason) && currentReason !== 'none') {
    // причина исчезла (например, после перетеста): сбрасываем фильтр
    currentReason = '';
    loadData();
  } else {
    sel.value = currentReason;
  }
}

function onReasonChange() {
  const sel = $('#reasonFilter');
  const v = sel ? sel.value : '';
  // выбор причины автоматически показывает раздел «failed»
  if (v && currentFilter !== 'failed') {
    currentFilter = 'failed';
    setActiveFilter('failed');
  }
  currentReason = v;
  loadData();
}

function updateSourceButtons() {
  $$('.source-bar .btn').forEach(el => {
    if (el) el.classList.toggle('btn-primary', el.dataset.source === currentSource);
  });
  const sel = $('.source-select');
  if (sel) sel.value = currentSource;
}

async function loadData() {
  if (isLoading) return;
  isLoading = true;
  allProxies = [];
  totalCount = 0;
  selected.clear();
  resetSelectAll();
  updateBatchButtons();
  try {
    await fetchPage(true);
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    showDataError('не удалось обновить список: ' + msg);
    renderListError(msg);
  } finally {
    isLoading = false;
  }
}

async function loadMore() {
  if (isLoading) return;
  isLoading = true;
  try {
    await fetchPage(false);
  } catch (e) {
    showDataError('не удалось догрузить список: ' + (e && e.message ? e.message : e));
  } finally {
    isLoading = false;
  }
}

async function fetchPage(reset) {
  const offset = reset ? 0 : allProxies.length;

  if (reset) renderListLoading();

  const data = await api('GET', makeProxiesUrl(PAGE_SIZE, offset));

  // api() не отдаёт reject: ошибка приходит телом {error}, и раньше она попадала в список как данные
  if (data && data.error) {
    showDataError('не удалось получить список прокси: ' + data.error);
    renderListError(data.error);
    return;
  }

  const proxies = Array.isArray(data) ? data : (Array.isArray(data.proxies) ? data.proxies : []);
  totalCount = data && data.total != null ? data.total : proxies.length;
  hideDataError();

  if (reset) {
    allProxies = proxies;
  } else {
    allProxies = [...allProxies, ...proxies];
  }

  if (reset) {
    proxies.forEach(p => linkMap[p.id] = p.link);
  } else {
    proxies.forEach(p => { if (!linkMap[p.id]) linkMap[p.id] = p.link; });
  }

  // Список рисуется до метаданных: /api/xray/status и /api/health отвечают около двух секунд,
  // и раньше таблица всё это время оставалась заглушкой загрузки.
  renderMobile(allProxies);
  renderDesktop(allProxies);
  updatePagination();
  isLoading = false;

  if (reset && !_initialMetaLoaded) {
    _initialMetaLoaded = true;
    const [status, ob, xr, health] = await Promise.all([
      api('GET', '/api/status'),
      api('GET', '/api/xray/outbounds'),
      api('GET', '/api/xray/status'),
      api('GET', '/api/health'),
    ]);
    renderHealth(health);
    renderStats(status);
    if (status && !status.error) {
      renderSourceButtons(status.sources, status.unknown_count, status.total);
      renderReasonFilter(status.reasons || []);
    } else {
      // метаданные не загрузились: пробуем снова на следующем обновлении
      _initialMetaLoaded = false;
    }
    renderTraffic(ob, xr);
  }
}

function renderStats(status) {
  const ids = ['statTotal', 'statWorking', 'statFailed', 'statTopSpeed'];
  if (!status || status.error) {
    const why = status && status.error ? status.error : 'нет ответа';
    ids.forEach(id => {
      const el = $(`#${id}`);
      if (!el) return;
      el.textContent = '-';
      el.title = 'не удалось получить /api/status: ' + why;
    });
    return;
  }
  $('#statTotal').textContent = status.total;
  $('#statWorking').textContent = status.working;
  $('#statFailed').textContent = status.failed;
  $('#statTopSpeed').textContent = status.top_speed;
  const speedLabel = document.querySelector('.stat-card[data-filter="top_speed"] .label-s');
  if (speedLabel && status.top_speed_threshold) {
    const mbps = status.top_speed_threshold / 1000;
    speedLabel.textContent = mbps >= 1 ? `топ-скорость ≥${mbps}Mbps` : `топ-скорость ≥${status.top_speed_threshold}Kbps`;
  }
}

function renderHealth(health) {
  const el = $('#healthIndicator');
  if (!el) return;
  // Недоступный API и неисправный Xray это разные вещи, и раньше они выглядели одинаково
  if (!health || health.error) {
    const why = health && health.error ? health.error : 'нет ответа /api/health';
    el.innerHTML = `<span class="badge badge-muted" title="${esc(why)}">нет связи с API</span>`;
    return;
  }
  el.innerHTML = health.status === 'ok'
    ? '<span class="badge badge-green">исправен</span>'
    : '<span class="badge badge-red">проблемы</span>';
}

function renderTraffic(ob, xr) {
  const el = $('#activeInfo');
  if (!el) return;
  const outboundFailed = !ob || !!ob.error;
  const nodes = outboundFailed ? null : (ob.nodes || []);
  const traffic = outboundFailed ? {} : (ob.traffic || {});
  let html = '// outbounds: ';
  if (nodes === null) {
    html += 'нет данных';
  } else if (nodes.length) {
    const withTraffic = nodes.filter(t => traffic[t]?.downlink);
    html += `<b>${nodes.length}</b> (с трафиком: ${withTraffic.length})`;
  } else {
    html += 'нет';
  }
  if (xr && xr.error) {
    html += ` <span class="badge badge-muted" title="${esc(xr.error)}">нет связи с API</span>`;
  } else {
    html += xr && xr.running
      ? ' <span class="badge badge-green">работает</span>'
      : ' <span class="badge badge-red">остановлен</span>';
  }
  el.innerHTML = html;
}

function renderSourceButtons(sources, unknownCount, totalCount) {
  const bar = $('#sourceBar');
  if (!bar) return;
  const list = sources || [];
  // Пересборка на каждом обновлении (раз в 5 с во время теста) сбрасывала фокус,
  // поэтому кнопки перерисовываются только когда набор источников изменился.
  const signature = JSON.stringify([list.map(s => [s.id, s.name, s.cnt]), unknownCount]);
  if (bar.dataset.signature === signature) { updateSourceButtons(); return; }
  bar.dataset.signature = signature;
  $$('.source-btn-src, .source-select').forEach(el => el.remove());

  const totalSrc = list.length + (unknownCount > 0 ? 1 : 0);
  const allBtn = $('#sourceAll');
  const unknownBtn = $('#sourceUnknown');

  if (totalSrc <= 4) {
    // inline buttons: show All + source buttons
    if (allBtn) allBtn.style.display = '';
    // Кнопка «Свои» есть в разметке (templates/index.html), поэтому её не создаём,
    // а только показываем при наличии прокси без источника.
    if (unknownBtn) {
      unknownBtn.textContent = 'Свои ' + unknownCount;
      unknownBtn.style.display = unknownCount > 0 ? '' : 'none';
    }
    for (const s of list) {
      const id = 'srcBtn-' + s.id;
      let btn = document.getElementById(id);
      if (!btn) {
        btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-sm source-btn-src';
        btn.id = id;
        btn.dataset.source = String(s.id);
        btn.onclick = () => setSource(String(s.id));
        bar.appendChild(btn);
      }
      btn.textContent = s.name + ' ' + s.cnt;
    }
  } else {
    if (allBtn) allBtn.style.display = 'none';
    const sel = document.createElement('select');
    sel.className = 'input source-select';
    sel.setAttribute('aria-label', 'Источник прокси');
    sel.style.width = 'auto';
    sel.style.maxWidth = '280px';
    let opts = `<option value="">Все (${totalCount || 0})</option>`;
    if (unknownCount > 0) {
      opts += `<option value="unknown">Свои (${unknownCount})</option>`;
    }
    for (const s of list) {
      opts += `<option value="${esc(s.id)}">${esc(s.name)} (${esc(s.cnt)})</option>`;
    }
    sel.innerHTML = opts;
    sel.value = currentSource;
    sel.onchange = () => setSource(sel.value);
    bar.appendChild(sel);
    if (unknownBtn) unknownBtn.style.display = 'none';
  }
  updateSourceButtons();
}

function updatePagination() {
  const bar = $('#paginationBar');
  const btn = $('#showMoreBtn');
  const info = $('#paginationInfo');
  if (!bar || !btn || !info) return;

  if (allProxies.length >= totalCount || totalCount <= PAGE_SIZE) {
    bar.style.display = 'none';
    return;
  }

  bar.style.display = 'flex';
  const remaining = totalCount - allProxies.length;
  const next = Math.min(PAGE_SIZE, remaining);
  btn.textContent = `Показать ещё ${next} (${allProxies.length}/${totalCount})`;
  info.textContent = `Показано ${allProxies.length} из ${totalCount}`;
}

function statusBadge(status, failedSince) {
  if (status === 'working') return 'badge-green';
  if (status === 'failed' && failedSince) {
    const since = utcDate(failedSince);
    return since && (Date.now() - since.getTime()) / 3600000 < 24
      ? 'badge-orange' : 'badge-red';
  }
  return status === 'failed' ? 'badge-orange' : 'badge-muted';
}

function testTooltip(p) {
  const parts = [];
  if (p.last_error) parts.push('причина: ' + p.last_error);
  if (p.last_test_at) parts.push('проверен: ' + fmtUtcTime(p.last_test_at));
  return esc(parts.join('\n'));
}

function errorHint(p) {
  if (p.status !== 'failed' || !p.last_error) return '';
  const err = String(p.last_error);
  const short = err.length > 60 ? err.slice(0, 60) + '…' : err;
  return `<span class="cell-err" title="${esc(err)}">${esc(short)}</span>`;
}

const STATUS_RU = { working: 'работает', failed: 'не работает', pending: 'ожидает' };

function statusText(s) {
  return STATUS_RU[s] || s;
}

function securityBadge(sec) {
  if (!sec || sec === 'none') return ' <span class="badge badge-orange" title="без шифрования транспорта">без TLS</span>';
  return '';
}

function toggleSelect(id) {
  if (selected.has(id)) selected.delete(id); else selected.add(id);
  updateBatchButtons();
  $$(`.row-chk[data-id="${id}"]`).forEach(cb => { cb.checked = selected.has(id); });
  syncSelectAll();
}

// Раньше у чекбокса строки и у мобильной карточки был один и тот же id,
// поэтому на телефоне выбор вообще не переключался.
function toggleSelectAllFrom(checked) {
  for (const p of allProxies) {
    if (checked) selected.add(p.id); else selected.delete(p.id);
  }
  $$('.row-chk').forEach(cb => { cb.checked = checked; });
  updateBatchButtons();
}

function toggleSelectAll() {
  const desktop = $('#selectAll');
  toggleSelectAllFrom(!!(desktop && desktop.checked));
}

function syncSelectAll() {
  const all = allProxies.length > 0 && allProxies.every(p => selected.has(p.id));
  const desktop = $('#selectAll');
  if (desktop) desktop.checked = all;
  const mobile = $('#selectAllMobile');
  if (mobile) mobile.checked = all;
}

function resetSelectAll() {
  const desktop = $('#selectAll');
  if (desktop) desktop.checked = false;
  const mobile = $('#selectAllMobile');
  if (mobile) mobile.checked = false;
}

function updateBatchButtons() {
  const cnt = selected.size;
  const hasSel = cnt > 0;
  $('#batchDeleteBtn').style.display = hasSel ? 'inline-flex' : 'none';
  $('#batchTestBtn').style.display = hasSel ? 'inline-flex' : 'none';
  $('#testAllBtn').style.display = hasSel ? 'none' : 'inline-flex';
  $('#retestFailedBtn').style.display = hasSel ? 'none' : 'inline-flex';
  $('#cleanupBtn').style.display = hasSel ? 'none' : 'inline-flex';
  const bc = $('#batchCount');
  if (hasSel) { bc.textContent = `выбрано: ${cnt}`; bc.style.display = ''; }
  else { bc.textContent = ''; bc.style.display = 'none'; }
}

async function batchDelete() {
  if (!confirm(`Удалить выбранные прокси (${selected.size})?`)) return;
  const ids = Array.from(selected);
  const r = await api('POST', '/api/proxies/batch-delete', {ids});
  if (r.error) return toast(r.error, 'error');
  const deleted = r.deleted != null ? r.deleted : ids.length;
  toast(`удалено прокси: ${deleted}`, 'success');
  loadData();
}

async function batchTest() {
  const ids = Array.from(selected);
  const r = await api('POST', '/api/proxies/batch-test', {ids});
  if (r.error) return toast(r.error, 'error');
  toast(`тестируем ${ids.length} прокси…`);
  setTimeout(loadData, 3000);
}

function renderDesktop(proxies) {
  const tb = $('#tbodyDesktop');
  tb.innerHTML = '';
  if (!proxies.length) {
    tb.innerHTML = '<tr><td colspan="9" class="empty">// прокси не найдены</td></tr>';
    return;
  }
  for (const p of proxies) {
    const tr = document.createElement('tr');
    const badgeCls = statusBadge(p.status, p.failed_since);
    const speedHtml = p.speed_kbps ? formatSpeed(p.speed_kbps) : '<span class="dim">нет</span>';
    const vlessClass = p.latency_vless && p.latency_vless < 300 ? 'lat-good' : p.latency_vless >= 300 ? 'lat-bad' : 'dim';
    const vlessHtml = p.latency_vless ? `<span class="${vlessClass}">${p.latency_vless}мс</span>` : '<span class="dim">нет</span>';
    tr.innerHTML = `
      <td class="chk"><input type="checkbox" class="chk-custom row-chk" data-id="${p.id}" aria-label="Выбрать прокси ${p.id}" ${selected.has(p.id)?'checked':''} onchange="toggleSelect(${p.id})"></td>
      <td class="id">${p.id}</td>
      <td class="host-cell" title="${esc(p.host)}">${esc(p.host)}</td>
      <td>${esc(p.port)}</td>
      <td>${esc(p.country || 'нет')}${securityBadge(p.security)}</td>
      <td class="status-cell"><span class="badge ${badgeCls}" title="${testTooltip(p)}">${statusText(p.status)}</span>${errorHint(p)}</td>
      <td class="speed-cell">${speedHtml}</td>
      <td class="lat-cell">${vlessHtml}</td>
      <td class="actions-cell">
        <button class="btn btn-sm" onclick="copyLink(${p.id})">копия</button>
        <button class="btn btn-sm" onclick="testOne(${p.id})">тест</button>
        <button class="btn btn-sm btn-danger" onclick="delOne(${p.id})">удалить</button>
      </td>
    `;
    tb.appendChild(tr);
  }
}

function renderMobile(proxies) {
  const list = $('#mobileList');
  list.innerHTML = '';
  if (!proxies.length) {
    list.innerHTML = '<div class="empty" style="margin:0">// прокси не найдены</div>';
    return;
  }
  for (const p of proxies) {
    const badgeCls = statusBadge(p.status, p.failed_since);
    const speedHtml = p.speed_kbps ? formatSpeed(p.speed_kbps) : '<span class="dim">нет</span>';
    const vlessClass = p.latency_vless && p.latency_vless < 300 ? 'lat-good' : p.latency_vless >= 300 ? 'lat-bad' : 'dim';
    const card = document.createElement('div');
    card.className = 'mobile-card';
    card.innerHTML = `
      <div class="mc-chk"><input type="checkbox" class="chk-custom row-chk" data-id="${p.id}" aria-label="Выбрать прокси ${p.id}" ${selected.has(p.id)?'checked':''} onchange="toggleSelect(${p.id})"></div>
      <div class="mc-host" title="${esc(p.host)}">${esc(p.host)}</div>
      <div class="mc-meta">
        <span>#${p.id}</span><span>${esc(p.port)}</span><span>${esc(p.country || 'нет')}${securityBadge(p.security)}</span>
      </div>
      <div class="mc-actions">
        <button class="btn btn-sm" onclick="copyLink(${p.id})">копия</button>
        <button class="btn btn-sm" onclick="testOne(${p.id})">тест</button>
        <button class="btn btn-sm btn-danger" onclick="delOne(${p.id})">удалить</button>
      </div>
      <div class="mc-status">
        <span class="badge ${badgeCls}" title="${testTooltip(p)}">${statusText(p.status)}</span>
        ${errorHint(p)}
        <span class="${vlessClass}">VLESS: ${p.latency_vless ? p.latency_vless + 'мс' : 'нет'}</span>
        <span>Скорость: ${speedHtml}</span>
      </div>
    `;
    list.appendChild(card);
  }
}



$$('.stat-card').forEach(el => {
  el.addEventListener('click', () => setFilter(el.dataset.filter));
});
$('#reasonFilter')?.addEventListener('change', onReasonChange);

async function testOne(id) {
  const r = await api('POST',`/api/test/${id}`);
  if (r.error) return toast(r.error, 'error');
  if (r.status === 'working') {
    const speedStr = r.speed ? ` · ${formatSpeed(r.speed)}` : '';
    toast(`прокси #${id} работает: ${r.latency}мс${speedStr}`, 'success');
  }
  else toast(`прокси #${id} не работает${r.error ? ': ' + r.error : ''}`);
  loadData();
}

function copyLink(id) {
  const link = linkMap[id];
  if (!link) return;
  const ta = document.createElement('textarea');
  ta.value = link;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand('copy');
    toast('ссылка скопирована', 'success');
  } catch (e) {
    toast('не удалось скопировать', 'error');
  }
  ta.remove();
}

async function delOne(id) {
  if (!confirm(`Удалить прокси #${id}?`)) return;
  await api('DELETE',`/api/delete/${id}`);
  toast(`прокси #${id} удалён`);
  loadData();
}

async function testAll() {
  const r = await api('POST','/api/test-all');
  if (r.error) return toast(r.error, 'error');
  toast('запущен полный тест прокси');
  setTimeout(loadData, 3000);
}

async function retestFailed() {
  const r = await api('POST','/api/test-failed');
  if (r.error) return toast(r.error, 'error');
  if (!r.queued) { toast('нет неработающих прокси для перетеста'); return; }
  toast(`запущен перетест ${r.queued} неработающих прокси…`);
  setTimeout(loadData, 3000);
}

async function cancelTest() {
  const r = await api('POST','/api/test-cancel');
  if (r.error) return toast(r.error, 'error');
  toast('тест отменён');
}

async function cleanupFailed() {
  if (!confirm('Удалить ВСЕ неработающие прокси? Рабочие можно восстановить повторным импортом из Источников.')) return;
  const r = await api('POST','/api/cleanup');
  if (r.error) return toast(r.error, 'error');
  if (r.deleted > 0) toast(`удалено неработающих прокси: ${r.deleted}`, 'success');
  else toast('неработающих прокси нет');
  loadData();
}

window.addEventListener('resize', () => {
  renderMobile(allProxies);
  renderDesktop(allProxies);
});

loadData();

// Обновление счётчиков, когда фоновая проверка не идёт (во время теста их обновляет SSE)
setInterval(() => {
  if (_wasRunning) return;
  updateStats();
}, 15000);

// ─── Last test row ───

function updateLastTestRow(text) {
  const el = $('#lastTestRow');
  if (el) el.textContent = text || '';
}

// ─── SSE for progress bar ───

let _wasRunning = false;
let _lastLoadDuringTest = 0;
let _lastStatsRefresh = 0;

const LABEL_RU = {
  'all': 'Тест всех прокси',
  'batch-test': 'Тест выбранных',
  'retest-failed': 'Перетест неработающих',
  'import+check': 'Импорт + проверка',
  'db-check': 'Проверка из БД',
  'single': 'Тест прокси',
};

const STAGE_ICO = { 'check': '✓', 'ping': '↕', 'speed': '↓', 'import': '⇩' };

function stageStatusText(st) {
  if (!st) return '';
  switch (st.key) {
    case 'check': return `${st.done}/${st.total} · работает ${st.ok}`;
    case 'ping':  return `${st.done}/${st.total} · измерено ${st.ok}`;
    case 'speed': return `${st.done}/${st.total} профилей`;
    case 'import': return `${st.done}/${st.total} источников`;
    default: return `${st.done}/${st.total}`;
  }
}

function renderStageSteps(stages) {
  const box = $('#stageSteps');
  if (!box) return;
  if (!stages || !stages.length) { box.style.display = 'none'; box.innerHTML = ''; return; }
  const order = { 'import': 0, 'check': 1, 'ping': 2, 'speed': 3 };
  const sorted = stages.slice().sort((a, b) => (order[a.key] ?? 9) - (order[b.key] ?? 9));
  box.innerHTML = sorted.map(st => {
    const status = st.status || 'pending';
    const cls = status === 'active' ? 'st-active' : `st-${status}`;
    const ico = status === 'done' ? '✓'
      : status === 'active' ? (STAGE_ICO[st.key] || '●')
      : status === 'canceled' ? '✕' : (STAGE_ICO[st.key] || '·');
    return `<span class="stage-chip ${cls}"><span class="st-ico">${ico}</span>${esc(st.title)}${status === 'active' && st.total ? ' <b>· ' + stageStatusText(st) + '</b>' : ''}</span>`;
  }).join('');
  box.style.display = 'flex';
}

function labelRu(l) { return LABEL_RU[l] || l; }

function fmtElapsed(secs) {
  const s = Math.floor(secs);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h) return `${h}h ${m % 60}m ${s % 60}s`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

async function updateStats() {
  const status = await api('GET', '/api/status');
  if (!status || status.error) {
    showDataError('не удалось обновить счётчики: ' + (status && status.error ? status.error : 'нет ответа'));
    renderStats(status);
    return;
  }
  renderStats(status);
  renderReasonFilter(status.reasons || []);
}

function setStatUpdating(on) {
  $$('.stat-card').forEach(el => el.classList.toggle('updating', on));
}

function resetStatNumbers() {
  ['statTotal','statWorking','statFailed','statTopSpeed'].forEach(id => {
    const el = $(`#${id}`);
    if (el) {
      el.textContent = '…';
      el.title = 'идёт прогон, значения обновятся после его завершения';
    }
  });
}

function onProgressEvent(p) {
  const bar = $('#testProgressBar');
  const fill = $('#testProgressFill');
  const label = $('#testProgressLabel');
  const detail = $('#testProgressDetail');
  const steps = $('#stageSteps');
  const btns = ['testAllBtn', 'batchTestBtn', 'retestFailedBtn', 'cleanupBtn', 'batchDeleteBtn'];
  const cancelBtn = $('#cancelTestBtn');

  if (p.running) {
    if (!_wasRunning) {
      if (_initialMetaLoaded) resetStatNumbers();
      setStatUpdating(true);
    }
    _wasRunning = true;

    const stages = p.stages || [];
    renderStageSteps(stages);
    if (steps) steps.style.display = 'flex';
    bar.style.display = 'block';
    bar.style.height = '4px';
    bar.style.background = 'var(--border)';
    fill.style.background = 'var(--green)';
    fill.style.height = '100%';

    const active = stages.find(s => s.status === 'active');
    const frac = (active && active.total > 0) ? (active.done / active.total) : 0;
    fill.style.width = Math.max(2, Math.min(100, frac * 100)) + '%';

    const elapsed = p.started_at ? fmtElapsed((Date.now() / 1000) - p.started_at) : '';
    const stTitle = active ? active.title : '';
    const phaseText = active
      ? (active.key === 'check'
          ? `${active.done}/${active.total} · работает ${active.ok}, нет ${Math.max(0, active.done - active.ok)}`
          : stageStatusText(active))
      : `${p.done}/${p.total}`;
    label.textContent = p.cancel_requested
      ? `«${labelRu(p.label)}»: отмена… · ${elapsed}`
      : `«${labelRu(p.label)}» → ${stTitle}: ${phaseText} · ${elapsed}`;

    if (detail) {
      if (p.current) {
        detail.textContent = 'сейчас: ' + p.current;
        detail.style.display = '';
      } else {
        detail.style.display = 'none';
      }
    }

    btns.forEach(id => { const b = $(`#${id}`); if (b) b.disabled = true; });
    if (cancelBtn) cancelBtn.style.display = 'inline-flex';
    if (Date.now() - _lastLoadDuringTest > 5000) {
      _lastLoadDuringTest = Date.now();
      loadData();
    }
    if (Date.now() - _lastStatsRefresh > 5000) {
      _lastStatsRefresh = Date.now();
      updateStats();
    }
  } else {
    if (steps) { steps.style.display = 'none'; steps.innerHTML = ''; }
    if (detail) detail.style.display = 'none';
    bar.style.display = p.last_completed ? 'block' : 'none';
    bar.style.height = 'auto';
    bar.style.background = 'none';
    fill.style.width = '100%';
    fill.style.background = 'var(--text-muted)';
    fill.style.height = '2px';
    if (p.last_completed) {
      updateLastTestRow(`Последний прогон «${labelRu(p.last_label)}»: работает ${p.last_ok} из ${p.last_total}, завершён ${p.last_completed}`);
    }
    btns.forEach(id => { const b = $(`#${id}`); if (b) b.disabled = false; });
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (_wasRunning) {
      _wasRunning = false;
      _lastLoadDuringTest = 0;
      _lastStatsRefresh = 0;
      _initialMetaLoaded = false;
      loadData().then(() => setStatUpdating(false));
    }
  }
}

function connectSSE() {
  const es = new EventSource('/api/test-progress/stream');
  es.onmessage = (e) => {
    try { onProgressEvent(JSON.parse(e.data)); } catch(_) {}
  };
  es.onerror = () => {
    es.close();
    // fallback to polling if SSE fails
    fallbackPoll();
  };
  return es;
}

let _pollTimer;
function fallbackPoll() {
  _pollTimer = setInterval(async () => {
    try { onProgressEvent(await api('GET', '/api/test-progress')); } catch(_) {}
  }, 2000);
}

connectSSE();

// ─── Connections Modal ───

let _connRefreshTimer = null;

function setBodyModalLock(lock) {
  document.body.classList.toggle('modal-open', !!lock);
}

function toggleConnModal() {
  const m = $('#connModal');
  if (!m) return;
  const open = m.classList.toggle('open');
  setBodyModalLock(open);
  if (open) {
    loadConnections();
    loadPerIPTraffic();
    _connRefreshTimer = setInterval(() => {
      loadConnections();
      loadPerIPTraffic();
    }, 3000);
  } else {
    if (_connRefreshTimer) clearInterval(_connRefreshTimer);
    _connRefreshTimer = null;
  }
}

function closeConnModal() {
  const m = $('#connModal');
  if (m) {
    m.classList.remove('open');
    setBodyModalLock(false);
  }
  if (_connRefreshTimer) clearInterval(_connRefreshTimer);
  _connRefreshTimer = null;
}

// Клик по подложке (вне окна) закрывает модалку
document.addEventListener('click', (e) => {
  const m = $('#connModal');
  if (m && m.classList.contains('open') && e.target === m) {
    closeConnModal();
  }
});

function formatConnBytes(b) {
  if (b == null) return '0B';
  if (b <= 0) return '0B';
  if (b < 1024) return b + 'B';
  if (b < 1048576) return (b / 1024).toFixed(1) + 'KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + 'MB';
  return (b / 1073741824).toFixed(2) + 'GB';
}

async function loadPerIPTraffic() {
  const el = $('#connPerIP');
  if (!el) return;
  try {
    const data = await api('GET', '/api/connections/traffic');
    if (data && data.error) {
      el.innerHTML = `<div class="conn-empty">// не удалось получить трафик по клиентам: ${esc(data.error)}</div>`;
      return;
    }
    const clients = data.clients || [];
    if (!clients.length) {
      el.innerHTML = '<div class="conn-empty">// трафика по клиентам пока нет</div>';
      return;
    }
    const maxBytes = Math.max(...clients.map(c => c.bytes_down), 1);
    let html = '<table><thead><tr><th>Клиент</th><th>Соед.</th><th>↓</th><th>↑</th><th></th></tr></thead><tbody>';
    for (const c of clients) {
      const pct = (c.bytes_down / maxBytes) * 100;
      html += `<tr>
        <td class="ip">${esc(c.ip)}</td>
        <td>${esc(c.connections)}</td>
        <td class="bytes">${formatConnBytes(c.bytes_down)}</td>
        <td class="bytes">${formatConnBytes(c.bytes_up)}</td>
        <td><span class="bar" style="width:${pct}%"></span></td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = `<div class="conn-empty">// не удалось получить трафик по клиентам: ${esc(e && e.message ? e.message : e)}</div>`;
  }
}

function filterConnTable() {
  const q = ($('#connFilter') || {}).value || '';
  const rows = ($('#connTbody') || {}).children;
  if (!rows) return;
  for (const tr of rows) {
    const text = tr.textContent || '';
    tr.style.display = q ? (text.includes(q) ? '' : 'none') : '';
  }
}

// Цвет бейджа выводится из статуса соединения: раньше каждая строка была зелёной
function connStatusClass(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'ESTABLISHED' || s === 'LISTEN' || s === 'LISTENING') return 'badge-green';
  if (!s) return 'badge-muted';
  return 'badge-orange';
}

async function loadConnections() {
  const wrap = $('#connTableWrap');
  if (!wrap) return;
  try {
    const data = await api('GET', '/api/connections/list');
    if (data && data.error) {
      wrap.innerHTML = `<div class="data-error" role="status"><span>// не удалось получить соединения: ${esc(data.error)}</span>` +
        '<button type="button" class="btn btn-sm" onclick="loadConnections()">повторить</button></div>';
      return;
    }
    const conns = data.connections || [];
    if (!conns.length) {
      wrap.innerHTML = '<div class="conn-empty">// активных соединений нет</div>';
      return;
    }
    let html = `<table class="conn-table">
      <thead><tr><th>Процесс</th><th>PID</th><th>Локальный</th><th>Удалённый</th><th>Статус</th><th class="bytes">↓/↑</th><th></th></tr></thead>
      <tbody id="connTbody">`;
    for (const c of conns) {
      const remote = `${c.remote}:${c.remote_port}`;
      const local = `${c.local}:${c.local_port}`;
      const traffic = formatConnBytes(c.bytes_out || 0) + (c.bytes_in ? '/' + formatConnBytes(c.bytes_in) : '');
      const proc = c.process || 'нет';
      // remote приходит из /proc: в inline-обработчик пускаем только адрес из допустимых символов
      const remoteIp = /^[0-9a-fA-F:.]+$/.test(String(c.remote || '')) ? String(c.remote) : '';
      const closeCell = remoteIp
        ? `<button type="button" class="btn btn-sm btn-danger" onclick="closeConn('${remoteIp}',${Number(c.remote_port) || 0})">закрыть</button>`
        : '<span class="dim">нет данных</span>';
      html += `<tr>
        <td class="proc" title="${esc(proc)}">${esc(proc)}</td>
        <td>${c.pid != null ? esc(c.pid) : 'нет'}</td>
        <td>${esc(local)}</td>
        <td>${esc(remote)}</td>
        <td><span class="badge ${connStatusClass(c.status)}">${esc(c.status || 'неизвестно')}</span></td>
        <td class="bytes" title="вниз/вверх">${traffic}</td>
        <td>${closeCell}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
    // переприменяем активный фильтр
    filterConnTable();
  } catch (e) {
    wrap.innerHTML = `<div class="data-error" role="status"><span>// не удалось загрузить соединения: ${esc(e && e.message ? e.message : e)}</span>` +
      '<button type="button" class="btn btn-sm" onclick="loadConnections()">повторить</button></div>';
  }
}

async function closeConn(host, port) {
  if (!confirm(`Закрыть соединение с ${host}:${port}?`)) return;
  const r = await api('POST', '/api/connections/close', {remote_host: host, remote_port: port});
  if (r.success) toast(`закрыто: ${host}:${port}`, 'success');
  else toast(`не удалось закрыть ${host}:${port}`, 'error');
  loadConnections();
  loadPerIPTraffic();
}

async function flushConns() {
  if (!confirm('Закрыть все активные соединения? Это может прервать активные загрузки.')) return;
  const r = await api('POST', '/api/connections/flush');
  if (r.error) return toast(r.error, 'error');
  toast(`закрыто соединений: ${r.killed != null ? r.killed : 0}`, 'success');
  loadConnections();
  loadPerIPTraffic();
}

// close modal on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeConnModal();
});
