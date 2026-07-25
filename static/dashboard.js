const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

let currentFilter = '';
let currentSource = '';
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
  $$('.stat-card').forEach(el => el.classList.toggle('active', el.dataset.filter === f));
  loadData();
}

function setSource(src) {
  currentSource = src;
  updateSourceButtons();
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
          ? '<span class="badge badge-green" style="margin-left:8px;font-size:0.62rem">healthy</span>'
          : '<span class="badge badge-red" style="margin-left:8px;font-size:0.62rem">unhealthy</span>';
      }
      $('#statTotal').textContent = status.total;
      $('#statWorking').textContent = status.working;
      $('#statFailedRecent').textContent = status.failed_recent;
      $('#statTopSpeed').textContent = status.top_speed;
      const speedLabel = document.querySelector('.stat-card[data-filter="top_speed"] .label-s');
      if (speedLabel && status.top_speed_threshold) {
        const mbps = status.top_speed_threshold / 1000;
        speedLabel.textContent = mbps >= 1 ? `top speed ≥${mbps}Mbps` : `top speed ≥${status.top_speed_threshold}Kbps`;
      }
      renderSourceButtons(status.sources, status.unknown_count, status.total);
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
    html += `<b>${nodes.length}</b> (${withTraffic.length} with traffic)`;
  } else {
    html += '—';
  }
  html += run
    ? ' <span class="badge badge-green" style="font-size:0.62rem">running</span>'
    : ' <span class="badge badge-red" style="font-size:0.62rem">stopped</span>';
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
      unknownBtn.textContent = 'Custom ' + unknownCount;
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
    // select dropdown — hide All button, show select with All option
    if (allBtn) allBtn.style.display = 'none';
    const sel = document.createElement('select');
    sel.className = 'input source-select';
    sel.style.width = 'auto';
    sel.style.maxWidth = '280px';
    let opts = `<option value="">All ${totalCount || 0}</option>`;
    if (unknownCount > 0) {
      opts += `<option value="unknown">Custom ${unknownCount}</option>`;
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
  btn.textContent = `Show next ${next} (${allProxies.length}/${totalCount})`;
  info.textContent = `${allProxies.length} of ${totalCount} shown`;
}

function statusBadge(status, failedSince) {
  if (status === 'working') return 'badge-green';
  if (status === 'failed' && failedSince) {
    return (Date.now() - new Date(failedSince).getTime()) / 3600000 < 24
      ? 'badge-orange' : 'badge-red';
  }
  return status === 'failed' ? 'badge-orange' : 'badge-muted';
}

function securityBadge(sec) {
  if (!sec || sec === 'none') return ' <span class="badge badge-warn" title="no transport encryption">no enc</span>';
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
  $('#cleanupBtn').style.display = hasSel ? 'none' : 'inline-flex';
  const bc = $('#batchCount');
  if (hasSel) { bc.textContent = `${cnt} selected`; bc.style.display = ''; }
  else { bc.textContent = ''; bc.style.display = 'none'; }
}

async function batchDelete() {
  if (!confirm(`Delete ${selected.size} selected proxies?`)) return;
  const ids = Array.from(selected);
  await api('POST', '/api/proxies/batch-delete', {ids});
  toast(`deleted ${ids.length} proxies`, 'success');
  loadData();
}

async function batchTest() {
  const ids = Array.from(selected);
  toast(`testing ${ids.length} proxies...`);
  await api('POST', '/api/proxies/batch-test', {ids});
  setTimeout(loadData, 3000);
}

function renderDesktop(proxies) {
  const tb = $('#tbodyDesktop');
  tb.innerHTML = '';
  if (!proxies.length) {
    tb.innerHTML = '<tr><td colspan="9" class="empty">// no proxies</td></tr>';
    return;
  }
  for (const p of proxies) {
    const tr = document.createElement('tr');
    const badgeCls = statusBadge(p.status, p.failed_since);
    const speedHtml = p.speed_kbps ? formatSpeed(p.speed_kbps) : '<span class="dim">—</span>';
    const vlessClass = p.latency_vless && p.latency_vless < 300 ? 'lat-good' : p.latency_vless >= 300 ? 'lat-bad' : 'dim';
    const vlessHtml = p.latency_vless ? `<span class="${vlessClass}">${p.latency_vless}ms</span>` : '<span class="dim">—</span>';
    tr.innerHTML = `
      <td class="chk"><input type="checkbox" class="chk-custom" id="cb-${p.id}" ${selected.has(p.id)?'checked':''} onchange="toggleSelect(${p.id})"></td>
      <td class="id">${p.id}</td>
      <td class="host-cell" title="${p.host}">${p.host}</td>
      <td>${p.port}</td>
      <td>${p.country || '—'}${securityBadge(p.security)}</td>
      <td><span class="badge ${badgeCls}">${p.status}</span></td>
      <td class="speed-cell">${speedHtml}</td>
      <td class="lat-cell">${vlessHtml}</td>
      <td class="actions-cell">
        <button class="btn btn-sm" onclick="copyLink(${p.id})">copy</button>
        <button class="btn btn-sm" onclick="testOne(${p.id})">test</button>
        <button class="btn btn-sm btn-danger" onclick="delOne(${p.id})">del</button>
      </td>
    `;
    tb.appendChild(tr);
  }
}

function renderMobile(proxies) {
  const list = $('#mobileList');
  list.innerHTML = '';
  if (!proxies.length) {
    list.innerHTML = '<div class="empty" style="margin:0">// no proxies</div>';
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
        <button class="btn btn-sm" onclick="copyLink(${p.id})">copy</button>
        <button class="btn btn-sm" onclick="testOne(${p.id})">test</button>
        <button class="btn btn-sm btn-danger" onclick="delOne(${p.id})">del</button>
      </div>
      <div class="mc-status">
        <span class="badge ${badgeCls}">${p.status}</span>
        <span class="${vlessClass}">VLESS: ${p.latency_vless ? p.latency_vless + 'ms' : '—'}</span>
        <span>Speed: ${speedHtml}</span>
      </div>
    `;
    list.appendChild(card);
  }
}



$$('.stat-card').forEach(el => {
  el.addEventListener('click', () => setFilter(el.dataset.filter));
});

async function testOne(id) {
  const r = await api('POST',`/api/test/${id}`);
  if (r.status === 'working') {
    const speedStr = r.speed ? ` · ${formatSpeed(r.speed)}` : '';
    toast(`proxy #${id} working — ${r.latency}ms${speedStr}`, 'success');
  }
  else toast(`proxy #${id} failed`);
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
    toast('copied');
  } catch (e) {
    toast('copy failed', 'error');
  }
  ta.remove();
}

async function delOne(id) {
  if (!confirm('Delete proxy #'+id+'?')) return;
  await api('DELETE',`/api/delete/${id}`);
  toast(`proxy #${id} deleted`);
  loadData();
}

async function testAll() {
  toast('testing all proxies VLESS...');
  await api('POST','/api/test-all');
  setTimeout(loadData, 3000);
}

async function cancelTest() {
  await api('POST','/api/test-cancel');
  toast('test cancelled');
}

async function cleanupFailed() {
  if (!confirm('Delete ALL failed proxies? You can re-import from Sources to restore working ones.')) return;
  const r = await api('POST','/api/cleanup');
  if (r.deleted > 0) toast(`cleaned up ${r.deleted} failed proxies`, 'success');
  else toast('no failed proxies to clean up');
  loadData();
}

window.addEventListener('resize', () => {
  renderMobile(allProxies);
  renderDesktop(allProxies);
});

loadData();

// ─── Last test row ───

function updateLastTestRow(text) {
  const el = $('#lastTestRow');
  if (el) el.textContent = text || '';
}

// ─── SSE for progress bar ───

let _wasRunning = false;
let _lastLoadDuringTest = 0;
let _lastStatsRefresh = 0;

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
    $('#statFailedRecent').textContent = status.failed_recent;
    $('#statTopSpeed').textContent = status.top_speed;
    const speedLabel = document.querySelector('.stat-card[data-filter="top_speed"] .label-s');
    if (speedLabel && status.top_speed_threshold) {
      const mbps = status.top_speed_threshold / 1000;
      speedLabel.textContent = mbps >= 1 ? `top speed ≥${mbps}Mbps` : `top speed ≥${status.top_speed_threshold}Kbps`;
    }
  } catch (_) {}
}

function setStatUpdating(on) {
  $$('.stat-card').forEach(el => el.classList.toggle('updating', on));
}

function resetStatNumbers() {
  ['statTotal','statWorking','statFailedRecent','statTopSpeed'].forEach(id => {
    $(`#${id}`).textContent = '—';
  });
}

function onProgressEvent(p) {
  const bar = $('#testProgressBar');
  const fill = $('#testProgressFill');
  const label = $('#testProgressLabel');
  const btns = ['testAllBtn', 'batchTestBtn'];
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
    label.textContent = `${p.label}: ${p.done}/${p.total} (${p.ok} ok) · ${elapsed}`;
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
      updateLastTestRow(`Last ${p.last_label}: ${p.last_ok}/${p.last_total} ok — ${p.last_completed}`);
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

// ─── Traffic & Connections Chart ───

let _trafficData = [];
let _connData = [];
let _chartWidths = {};

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function hexToRgba(hex, a) {
  const h = hex.replace('#', '');
  if (h.length === 6) {
    const r = parseInt(h.substring(0,2), 16);
    const g = parseInt(h.substring(2,4), 16);
    const b = parseInt(h.substring(4,6), 16);
    return `rgba(${r},${g},${b},${a})`;
  }
  return hex;
}

function drawMiniChart(canvasId, data, valueKey, hexColor, maxPoints=120) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  // cache width on first render to prevent layout shifts
  if (!_chartWidths[canvasId]) {
    const rect = canvas.parentElement.getBoundingClientRect();
    _chartWidths[canvasId] = Math.max(200, Math.min(600, rect.width - 24));
  }
  const w = _chartWidths[canvasId];
  const h = 80;
  const dpr = window.devicePixelRatio || 1;
  // skip canvas re-init if dimensions unchanged
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const muted = cssVar('--text-muted') || '#555';

  if (!data || data.length < 2) {
    return;
  }

  const slice = data.slice(-maxPoints);
  const values = slice.map(p => p[valueKey] || 0);
  const maxVal = Math.max(...values, 1);
  const pad = 4;

  ctx.strokeStyle = hexColor;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  for (let i = 0; i < slice.length; i++) {
    const x = pad + (i / (slice.length - 1)) * (w - pad * 2);
    const y = h - pad - (values[i] / maxVal) * (h - pad * 2);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }
  ctx.stroke();

  // fill
  ctx.lineTo(w - pad, h - pad);
  ctx.lineTo(pad, h - pad);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, hexToRgba(hexColor, 0.18));
  grad.addColorStop(1, hexToRgba(hexColor, 0.03));
  ctx.fillStyle = grad;
  ctx.fill();
}

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function formatBytesPerSec(b, sec) {
  if (!b || !sec) return '—';
  const rate = b / sec;
  return formatBytes(rate) + '/s';
}

let _lastTrafficFetch = 0;
let _lastTrafficValues = { nft_down_raw: 0 };
let _trafficTimer;

async function updateTrafficCharts() {
  try {
    const [current, history] = await Promise.all([
      api('GET', '/api/traffic/current'),
      api('GET', '/api/traffic/history?limit=900'),
    ]);

    const points = history.points || [];
    _trafficData = points;
    _connData = points;

    const colorDown = cssVar('--green') || '#4ade80';
    const colorConn = cssVar('--orange') || '#fb923c';
    drawMiniChart('trafficChart', _trafficData, 'down', colorDown, 900);
    drawMiniChart('connChart', _connData, 'conn', colorConn, 900);

    // live traffic rate (из nftables real-time counter)
    const now = Date.now() / 1000;
    const dt = now - _lastTrafficFetch;
    const rateEl = $('#trafficLive');
    if (rateEl) {
      if (_lastTrafficFetch > 0 && dt > 0 && current.nft_down_raw != null) {
        const dDown = current.nft_down_raw - _lastTrafficValues.nft_down_raw;
        rateEl.textContent = '↓' + formatBytesPerSec(Math.max(0, dDown), dt);
      } else {
        rateEl.textContent = '↓ —';
      }
    }
    _lastTrafficFetch = now;
    _lastTrafficValues = { nft_down_raw: current.nft_down_raw || 0 };

    // active connections
    const connEl = $('#connLive');
    if (connEl) {
      connEl.textContent = (current.active_connections != null ? current.active_connections : '—') + ' conn';
    }

  } catch (_) {}
}

function startTrafficPolling() {
  updateTrafficCharts();
  _trafficTimer = setInterval(updateTrafficCharts, 2000);
}

document.addEventListener('DOMContentLoaded', startTrafficPolling);

// ─── Connections Modal ───

let _connRefreshTimer = null;

function toggleConnModal() {
  const m = $('#connModal');
  if (!m) return;
  const open = m.classList.toggle('open');
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
  if (m) m.classList.remove('open');
  if (_connRefreshTimer) clearInterval(_connRefreshTimer);
  _connRefreshTimer = null;
}

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
    let html = '<table><thead><tr><th>Client</th><th>Conn</th><th>↓ Down</th><th>↑ Up</th><th></th></tr></thead><tbody>';
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
      wrap.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:.8rem">// no active connections</div>';
      return;
    }
    let html = `<table class="conn-table">
      <thead><tr><th>Process</th><th>PID</th><th>Local</th><th>Remote</th><th>Status</th><th class="bytes">↓/↑</th><th></th></tr></thead>
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
        <td class="bytes" title="down/up">${traffic}</td>
        <td><button class="btn btn-sm btn-danger" onclick="closeConn('${c.remote}',${c.remote_port})">close</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
    // переприменяем активный фильтр
    filterConnTable();
  } catch (_) {
    wrap.innerHTML = '<div style="padding:20px;text-align:center;color:var(--red)">failed to load</div>';
  }
}

async function closeConn(host, port) {
  if (!confirm(`Close connection to ${host}:${port}?`)) return;
  const r = await api('POST', '/api/connections/close', {remote_host: host, remote_port: port});
  if (r.success) toast(`closed ${host}:${port}`, 'success');
  else toast(`failed to close ${host}:${port}`, 'error');
  loadConnections();
  loadPerIPTraffic();
}

async function flushConns() {
  if (!confirm('Close ALL active connections? May disrupt active downloads.')) return;
  const r = await api('POST', '/api/connections/flush');
  toast(`closed ${r.killed} connections`, 'success');
  loadConnections();
  loadPerIPTraffic();
}

// close modal on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeConnModal();
});
