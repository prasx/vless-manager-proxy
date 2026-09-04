const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

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
  if (!kbps) return '<span class="dim">—</span>';
  if (kbps >= 1000) return `${(kbps / 1000).toFixed(1)} Mbps`;
  return `${kbps} Kbps`;
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

function setFilter(f) {
  currentFilter = f;
  // reason-фильтр имеет смысл только в представлении «не работает»
  if (f !== 'failed' && currentReason) {
    currentReason = '';
    const sel = $('#reasonFilter');
    if (sel) sel.value = '';
  }
  $$('.stat-card').forEach(el => el.classList.toggle('active', el.dataset.filter === f));
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
    // причина исчезла (например, после перетеста) — сбрасываем фильтр
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
    $$('.stat-card').forEach(el => el.classList.toggle('active', el.dataset.filter === 'failed'));
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
  isLoading = true;
  allProxies = [];
  totalCount = 0;
  selected.clear();
  updateBatchButtons();
  await fetchPage(true);
  isLoading = false;
}

async function loadMore() {
  if (isLoading) return;
  isLoading = true;
  await fetchPage(false);
  isLoading = false;
}

async function fetchPage(reset) {
  const offset = reset ? 0 : allProxies.length;

  const data = await api('GET', makeProxiesUrl(PAGE_SIZE, offset));

  const proxies = data.proxies || data;
  totalCount = data.total != null ? data.total : proxies.length;

  if (reset) {
    allProxies = proxies;
  } else {
    allProxies = [...allProxies, ...proxies];
  }

  if (reset) {
    if (!_initialMetaLoaded) {
      _initialMetaLoaded = true;
      const [status, ob, xr, health] = await Promise.all([
        api('GET', '/api/status'),
        api('GET', '/api/xray/outbounds').catch(() => ({nodes:[], traffic:{}})),
        api('GET', '/api/xray/status').catch(() => ({running:false})),
        api('GET', '/api/health').catch(() => null),
      ]);
      const healthEl = $('#healthIndicator');
      if (healthEl) {
        const ok = health?.status === 'ok';
        healthEl.innerHTML = ok
          ? '<span class="badge badge-green" style="margin-left:8px;font-size:0.62rem">исправен</span>'
          : '<span class="badge badge-red" style="margin-left:8px;font-size:0.62rem">проблемы</span>';
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
      renderSourceButtons(status.sources, status.unknown_count, status.total);
      renderReasonFilter(status.reasons || []);
      renderTraffic(ob, xr);
    }
    proxies.forEach(p => linkMap[p.id] = p.link);
  } else {
    proxies.forEach(p => { if (!linkMap[p.id]) linkMap[p.id] = p.link; });
  }

  renderMobile(allProxies);
  renderDesktop(allProxies);

  updatePagination();
}

function renderTraffic(ob, xr) {
  const el = $('#activeInfo');
  if (!el) return;
  const nodes = ob.nodes || [];
  const run = xr.running;
  const traffic = ob.traffic || {};
  const withTraffic = nodes.filter(t => traffic[t]?.downlink);
  let html = '// outbounds: ';
  if (nodes.length) {
    html += `<b>${nodes.length}</b> (с трафиком: ${withTraffic.length})`;
  } else {
    html += '—';
  }
  html += run
    ? ' <span class="badge badge-green" style="font-size:0.62rem">работает</span>'
    : ' <span class="badge badge-red" style="font-size:0.62rem">остановлен</span>';
  el.innerHTML = html;
}

function renderSourceButtons(sources, unknownCount, totalCount) {
  const bar = $('#sourceBar');
  if (!bar) return;
  $$('.source-btn-src, .source-select').forEach(el => el.remove());

  const totalSrc = (sources || []).length + (unknownCount > 0 ? 1 : 0);
  const allBtn = $('#sourceAll');
  const unknownBtn = $('#sourceUnknown');

  if (totalSrc <= 4) {
    // inline buttons — show All + source buttons
    if (allBtn) allBtn.style.display = '';
    if (unknownCount > 0) {
      if (!unknownBtn) {
        unknownBtn = document.createElement('button');
        unknownBtn.className = 'btn btn-sm';
        unknownBtn.id = 'sourceUnknown';
        unknownBtn.dataset.source = 'unknown';
        unknownBtn.onclick = () => setSource('unknown');
        bar.appendChild(unknownBtn);
      }
      unknownBtn.textContent = 'Свои ' + unknownCount;
      unknownBtn.style.display = '';
    } else if (unknownBtn) {
      unknownBtn.style.display = 'none';
    }
    for (const s of (sources || [])) {
      const id = 'srcBtn-' + s.id;
      let btn = document.getElementById(id);
      if (!btn) {
        btn = document.createElement('button');
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
    sel.style.width = 'auto';
    sel.style.maxWidth = '280px';
    let opts = `<option value="">Все (${totalCount || 0})</option>`;
    if (unknownCount > 0) {
      opts += `<option value="unknown">Свои (${unknownCount})</option>`;
    }
    for (const s of (sources || [])) {
      opts += `<option value="${s.id}">${s.name} (${s.cnt})</option>`;
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
    return (Date.now() - new Date(failedSince).getTime()) / 3600000 < 24
      ? 'badge-orange' : 'badge-red';
  }
  return status === 'failed' ? 'badge-orange' : 'badge-muted';
}

// last_test_at из API хранится в UTC (naive) — добавляем 'Z' и форматируем локально
function fmtUtcTime(t) {
  if (!t) return '';
  const d = new Date(String(t).replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? String(t) : d.toLocaleString();
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
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
  if (!sec || sec === 'none') return ' <span class="badge badge-warn" title="без шифрования транспорта">без TLS</span>';
  return '';
}

function toggleSelect(id) {
  if (selected.has(id)) selected.delete(id); else selected.add(id);
  updateBatchButtons();
  const cb = $(`#cb-${id}`);
  if (cb) cb.checked = selected.has(id);
}

function toggleSelectAll() {
  const checked = $('#selectAll').checked;
  for (const p of allProxies) {
    if (checked) selected.add(p.id); else selected.delete(p.id);
    const cb = $(`#cb-${p.id}`);
    if (cb) cb.checked = checked;
  }
  updateBatchButtons();
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
  await api('POST', '/api/proxies/batch-delete', {ids});
  toast(`удалено прокси: ${ids.length}`, 'success');
  loadData();
}

async function batchTest() {
  const ids = Array.from(selected);
  toast(`тестируем ${ids.length} прокси…`);
  await api('POST', '/api/proxies/batch-test', {ids});
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
    const speedHtml = p.speed_kbps ? formatSpeed(p.speed_kbps) : '<span class="dim">—</span>';
    const vlessClass = p.latency_vless && p.latency_vless < 300 ? 'lat-good' : p.latency_vless >= 300 ? 'lat-bad' : 'dim';
    const vlessHtml = p.latency_vless ? `<span class="${vlessClass}">${p.latency_vless}мс</span>` : '<span class="dim">—</span>';
    tr.innerHTML = `
      <td class="chk"><input type="checkbox" class="chk-custom" id="cb-${p.id}" ${selected.has(p.id)?'checked':''} onchange="toggleSelect(${p.id})"></td>
      <td class="id">${p.id}</td>
      <td class="host-cell" title="${p.host}">${p.host}</td>
      <td>${p.port}</td>
      <td>${p.country || '—'}${securityBadge(p.security)}</td>
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
    const speedHtml = p.speed_kbps ? formatSpeed(p.speed_kbps) : '—';
    const vlessClass = p.latency_vless && p.latency_vless < 300 ? 'lat-good' : p.latency_vless >= 300 ? 'lat-bad' : 'dim';
    const card = document.createElement('div');
    card.className = 'mobile-card';
    card.innerHTML = `
      <div class="mc-chk"><input type="checkbox" class="chk-custom" id="cb-${p.id}" ${selected.has(p.id)?'checked':''} onchange="toggleSelect(${p.id})"></div>
      <div class="mc-host" title="${p.host}">${p.host}</div>
      <div class="mc-meta">
        <span>#${p.id}</span><span>${p.port}</span><span>${p.country || '—'}${securityBadge(p.security)}</span>
      </div>
      <div class="mc-actions">
        <button class="btn btn-sm" onclick="copyLink(${p.id})">копия</button>
        <button class="btn btn-sm" onclick="testOne(${p.id})">тест</button>
        <button class="btn btn-sm btn-danger" onclick="delOne(${p.id})">удалить</button>
      </div>
      <div class="mc-status">
        <span class="badge ${badgeCls}" title="${testTooltip(p)}">${statusText(p.status)}</span>
        ${errorHint(p)}
        <span class="${vlessClass}">VLESS: ${p.latency_vless ? p.latency_vless + 'мс' : '—'}</span>
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
  if (r.status === 'working') {
    const speedStr = r.speed ? ` · ${formatSpeed(r.speed)}` : '';
    toast(`прокси #${id} работает — ${r.latency}мс${speedStr}`, 'success');
  }
  else toast(`прокси #${id} не работает${r.error ? ' — ' + r.error : ''}`);
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
  toast('тестируем все прокси…');
  await api('POST','/api/test-all');
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
  await api('POST','/api/test-cancel');
  toast('тест отменён');
}

async function cleanupFailed() {
  if (!confirm('Удалить ВСЕ неработающие прокси? Рабочие можно восстановить повторным импортом из Источников.')) return;
  const r = await api('POST','/api/cleanup');
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
};

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
  try {
    const status = await api('GET', '/api/status');
    $('#statTotal').textContent = status.total;
    $('#statWorking').textContent = status.working;
    $('#statFailed').textContent = status.failed;
    $('#statTopSpeed').textContent = status.top_speed;
    const speedLabel = document.querySelector('.stat-card[data-filter="top_speed"] .label-s');
    if (speedLabel && status.top_speed_threshold) {
      const mbps = status.top_speed_threshold / 1000;
      speedLabel.textContent = mbps >= 1 ? `топ-скорость ≥${mbps}Mbps` : `топ-скорость ≥${status.top_speed_threshold}Kbps`;
    }
    renderReasonFilter(status.reasons || []);
  } catch (_) {}
}

function setStatUpdating(on) {
  $$('.stat-card').forEach(el => el.classList.toggle('updating', on));
}

function resetStatNumbers() {
  ['statTotal','statWorking','statFailed','statTopSpeed'].forEach(id => {
    $(`#${id}`).textContent = '—';
  });
}

function onProgressEvent(p) {
  const bar = $('#testProgressBar');
  const fill = $('#testProgressFill');
  const label = $('#testProgressLabel');
  const btns = ['testAllBtn', 'batchTestBtn', 'retestFailedBtn'];
  const cancelBtn = $('#cancelTestBtn');
  if (p.running && p.total > 0) {
    if (!_wasRunning) {
      if (_initialMetaLoaded) resetStatNumbers();
      setStatUpdating(true);
    }
    _wasRunning = true;
    bar.style.display = 'block';
    bar.style.height = '4px';
    bar.style.background = 'var(--border)';
    fill.style.width = (p.done / p.total * 100) + '%';
    fill.style.background = 'var(--green)';
    fill.style.height = '100%';
    const elapsed = p.started_at ? fmtElapsed((Date.now() / 1000) - p.started_at) : '';
    const failed = Math.max(0, p.done - p.ok);
    const rate = failed
      ? `работает ${p.ok} из ${p.done}, нет ${failed}`
      : `работает ${p.ok} из ${p.done}`;
    label.textContent = `${labelRu(p.label)}: ${p.done}/${p.total} (${rate}) · ${elapsed}`;
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
    bar.style.display = p.last_completed ? 'block' : 'none';
    bar.style.height = 'auto';
    bar.style.background = 'none';
    fill.style.width = '100%';
    fill.style.background = 'var(--text-muted)';
    fill.style.height = '2px';
    if (p.last_completed) {
      updateLastTestRow(`Последний прогон «${labelRu(p.last_label)}»: работает ${p.last_ok} из ${p.last_total} — ${p.last_completed}`);
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

let sseSource = connectSSE();

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
    const clients = data.clients || [];
    if (!clients.length) { el.innerHTML = ''; return; }
    const maxBytes = Math.max(...clients.map(c => c.bytes_down), 1);
    let html = '<table><thead><tr><th>Клиент</th><th>Соед.</th><th>↓</th><th>↑</th><th></th></tr></thead><tbody>';
    for (const c of clients) {
      const pct = (c.bytes_down / maxBytes) * 100;
      html += `<tr>
        <td class="ip">${c.ip}</td>
        <td>${c.connections}</td>
        <td class="bytes">${formatConnBytes(c.bytes_down)}</td>
        <td class="bytes">${formatConnBytes(c.bytes_up)}</td>
        <td><span class="bar" style="width:${pct}%"></span></td>
      </tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch (_) { /* silent */ }
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

async function loadConnections() {
  const wrap = $('#connTableWrap');
  if (!wrap) return;
  try {
    const data = await api('GET', '/api/connections/list');
    const conns = data.connections || [];
    if (!conns.length) {
      wrap.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:.8rem">// активных соединений нет</div>';
      return;
    }
    let html = `<table class="conn-table">
      <thead><tr><th>Процесс</th><th>PID</th><th>Локальный</th><th>Удалённый</th><th>Статус</th><th class="bytes">↓/↑</th><th></th></tr></thead>
      <tbody id="connTbody">`;
    for (const c of conns) {
      const remote = `${c.remote}:${c.remote_port}`;
      const local = `${c.local}:${c.local_port}`;
      const traffic = formatConnBytes(c.bytes_out || 0) + (c.bytes_in ? '/' + formatConnBytes(c.bytes_in) : '');
      html += `<tr>
        <td class="proc" title="${c.process || '—'}">${c.process || '—'}</td>
        <td>${c.pid || '—'}</td>
        <td>${local}</td>
        <td>${remote}</td>
        <td><span class="badge badge-green">${c.status}</span></td>
        <td class="bytes" title="вниз/вверх">${traffic}</td>
        <td><button class="btn btn-sm btn-danger" onclick="closeConn('${c.remote}',${c.remote_port})">закрыть</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
    // переприменяем активный фильтр
    filterConnTable();
  } catch (_) {
    wrap.innerHTML = '<div style="padding:20px;text-align:center;color:var(--red)">не удалось загрузить</div>';
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
  if (!confirm('Закрыть ВСЕ активные соединения? Это может прервать активные загрузки.')) return;
  const r = await api('POST', '/api/connections/flush');
  toast(`закрыто соединений: ${r.killed}`, 'success');
  loadConnections();
  loadPerIPTraffic();
}

// close modal on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeConnModal();
});
