const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

let currentFilter = '';
let currentCountry = '';
let allProxies = [];
let totalCount = 0;
let isLoading = false;
const PAGE_SIZE = 50;
const linkMap = {};

function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  return fetch(url, opts).then(r => r.json());
}

function makeProxiesUrl(limit, offset) {
  let url = '/api/proxies?filter=' + currentFilter;
  if (currentCountry) {
    url += currentCountry === 'world' ? '&country=world' : '&country=RU';
  }
  if (limit != null) url += `&limit=${limit}&offset=${offset}`;
  return url;
}

function setFilter(f) {
  currentFilter = f;
  $$('.stat-card').forEach(el => el.classList.toggle('active', el.dataset.filter === f));
  loadData();
}

function setCountry(cc) {
  currentCountry = cc;
  updateCountryButtons();
  loadData();
}

function updateCountryButtons() {
  const allBtn = $('#countryAll');
  const worldBtn = $('#countryWorld');
  const ruBtn = $('#countryRu');
  [allBtn, worldBtn, ruBtn].forEach(el => {
    if (el) el.classList.toggle('btn-primary', el.dataset.country === currentCountry);
  });
}

async function loadData() {
  isLoading = true;
  allProxies = [];
  totalCount = 0;
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

  const allBtn = $('#countryAll');
  const worldBtn = $('#countryWorld');
  const ruBtn = $('#countryRu');
  if (allBtn) allBtn.textContent = 'All ' + (status.total || 0);
  if (worldBtn) worldBtn.textContent = 'World ' + (status.world || 0);
  if (ruBtn) ruBtn.textContent = 'RU ' + (status.ru || 0);
  updateCountryButtons();

  const activeInfo = $('#activeInfo');
  if (activeInfo) {
    const nodes = ob.nodes || [];
    const run = xr.running;
    const xrayBadge = run
      ? '<span class="badge badge-green" style="margin-left:8px;font-size:0.62rem">xray running</span>'
      : '<span class="badge badge-red" style="margin-left:8px;font-size:0.62rem">xray stopped</span>';
    if (nodes.length) {
      const traffic = ob.traffic || {};
      const withTraffic = nodes.filter(t => traffic[t]?.downlink);
      activeInfo.innerHTML = `// status: <b>${withTraffic.length ? withTraffic.join(', ') : nodes.join(', ')}</b> (${nodes.length} nodes)${xrayBadge}`;
    } else {
      activeInfo.innerHTML = `// status: —${xrayBadge}`;
    }
  }

  if (window.innerWidth <= 768) renderMobile(allProxies);
  else renderDesktop(allProxies);

  updatePagination();
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

function renderDesktop(proxies) {
  const tb = $('#tbodyDesktop');
  tb.innerHTML = '';
  if (!proxies.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">// no proxies</td></tr>';
    return;
  }
  for (const p of proxies) {
    const tr = document.createElement('tr');
    const badgeCls = statusBadge(p.status, p.failed_since);
    const latClass = p.latency && p.latency < 300 ? 'lat-good' : p.latency >= 300 ? 'lat-bad' : '';
    tr.innerHTML = `
      <td class="id">${p.id}</td>
      <td class="host-cell" title="${p.host}">${p.host}</td>
      <td>${p.port}</td>
      <td>${p.country || '—'}${securityBadge(p.security)}</td>
      <td><span class="badge ${badgeCls}">${p.status}</span></td>
      <td class="${latClass}">${p.latency ? p.latency + 'ms' : '—'}</td>
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
    const latClass = p.latency && p.latency < 300 ? 'lat-good' : p.latency >= 300 ? 'lat-bad' : '';
    const card = document.createElement('div');
    card.className = 'mobile-card';
    card.innerHTML = `
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
        <span class="${latClass}">${p.latency ? p.latency + 'ms' : '—'}</span>
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
  toast('testing all proxies, wait a minute...');
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
