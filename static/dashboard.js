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

function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  return fetch(url, opts).then(r => r.json());
}

function formatSpeed(kbps) {
  if (!kbps) return '<span class="dim">—</span>';
  if (kbps >= 1000) return `${(kbps / 1000).toFixed(1)} Mbps`;
  return `${kbps} Kbps`;
}

function makeProxiesUrl(limit, offset) {
  let url = '/api/proxies?filter=' + currentFilter;
  if (currentSource) {
    url += '&source=' + currentSource;
  }
  if (limit != null) url += `&limit=${limit}&offset=${offset}`;
  return url;
}

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
  const [data, status, ob, xr] = await Promise.all([
    api('GET', makeProxiesUrl(PAGE_SIZE, offset)),
    api('GET', '/api/status'),
    api('GET', '/api/xray/outbounds').catch(() => ({nodes:[], traffic:{}})),
    api('GET', '/api/xray/status').catch(() => ({running:false}))
  ]);

  const proxies = data.proxies || data;
  totalCount = data.total != null ? data.total : proxies.length;

  proxies.forEach(p => linkMap[p.id] = p.link);

  if (reset) {
    allProxies = proxies;
  } else {
    proxies.forEach(p => { if (!linkMap[p.id]) linkMap[p.id] = p.link; });
    allProxies = [...allProxies, ...proxies];
  }

  $('#statTotal').textContent = status.total;
  $('#statWorking').textContent = status.working;

  $('#statFailedRecent').textContent = status.failed_recent;

  renderSourceButtons(status.sources, status.unknown_count, status.total);

  renderTraffic(ob, xr);

  if (window.innerWidth <= 768) renderMobile(allProxies);
  else renderDesktop(allProxies);

  updatePagination();
}

function renderTraffic(ob, xr) {
  const el = $('#activeInfo');
  if (!el) return;
  const nodes = ob.nodes || [];
  const run = xr.running;
  const badge = run
    ? '<span class="badge badge-green" style="margin-left:8px;font-size:0.62rem">running</span>'
    : '<span class="badge badge-red" style="margin-left:8px;font-size:0.62rem">stopped</span>';
  const traffic = ob.traffic || {};
  const withTraffic = nodes.filter(t => traffic[t]?.downlink);
  if (nodes.length) {
    el.innerHTML = `// outbounds: <b>${nodes.length}</b> (${withTraffic.length} with traffic)${badge}`;
  } else {
    el.innerHTML = `// outbounds: —${badge}`;
  }
}

function renderSourceButtons(sources, unknownCount, totalCount) {
  const bar = $('#sourceBar');
  if (!bar) return;
  const allBtn = $('#sourceAll');
  if (allBtn) allBtn.textContent = 'All ' + (totalCount || 0);

  const totalSrc = (sources || []).length + (unknownCount > 0 ? 1 : 0);
  $$('.source-btn-src, .source-select').forEach(el => el.remove());

  if (totalSrc <= 4) {
    // inline buttons
    let unknownBtn = $('#sourceUnknown');
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
    // select dropdown
    const sel = document.createElement('select');
    sel.className = 'input source-select';
    sel.style.width = 'auto';
    sel.style.maxWidth = '280px';
    sel.innerHTML = `<option value="">All ${totalCount || 0}</option>`;
    if (unknownCount > 0) {
      sel.innerHTML += `<option value="unknown">Custom ${unknownCount}</option>`;
    }
    for (const s of (sources || [])) {
      sel.innerHTML += `<option value="${s.id}">${s.name} (${s.cnt})</option>`;
    }
    sel.value = currentSource;
    sel.onchange = () => setSource(sel.value);
    bar.appendChild(sel);
    // hide inline unknown btn
    const unknownBtn = $('#sourceUnknown');
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
  $('#batchCount').textContent = hasSel ? `${cnt} selected` : '';
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
  if (r.status === 'working') toast(`proxy #${id} working — auto-applied`, 'success');
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

async function cleanupFailed() {
  if (!confirm('Delete ALL failed proxies? You can re-import from Sources to restore working ones.')) return;
  const r = await api('POST','/api/cleanup');
  if (r.deleted > 0) toast(`cleaned up ${r.deleted} failed proxies`, 'success');
  else toast('no failed proxies to clean up');
  loadData();
}

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(loadData, 200);
});

loadData();
setInterval(loadData, 30000);

// ─── Progress bar polling ───

let _wasRunning = false;
let _lastLoadDuringTest = 0;

async function pollTestProgress() {
  const p = await api('GET', '/api/test-progress');
  const bar = $('#testProgressBar');
  const fill = $('#testProgressFill');
  const label = $('#testProgressLabel');
  const btns = ['testAllBtn', 'batchTestBtn'];
  if (p.running && p.total > 0) {
    _wasRunning = true;
    bar.style.display = 'block';
    bar.style.height = '4px';
    bar.style.background = 'var(--border)';
    fill.style.width = (p.done / p.total * 100) + '%';
    fill.style.background = 'var(--green)';
    fill.style.height = '100%';
    label.textContent = `${p.label}: ${p.done}/${p.total} (${p.ok} ok)`;
    btns.forEach(id => { const b = $(`#${id}`); if (b) b.disabled = true; });
    if (Date.now() - _lastLoadDuringTest > 5000) {
      _lastLoadDuringTest = Date.now();
      loadData();
    }
  } else {
    bar.style.display = p.last_completed ? 'block' : 'none';
    bar.style.height = 'auto';
    bar.style.background = 'none';
    fill.style.width = '100%';
    fill.style.background = 'var(--text-muted)';
    fill.style.height = '2px';
    if (p.last_completed) {
      label.textContent = `Last ${p.last_label}: ${p.last_ok}/${p.last_total} ok — ${p.last_completed}`;
    }
    btns.forEach(id => { const b = $(`#${id}`); if (b) b.disabled = false; });
    if (_wasRunning) {
      _wasRunning = false;
      _lastLoadDuringTest = 0;
      loadData();
    }
  }
}
setInterval(pollTestProgress, 2000);
pollTestProgress();
