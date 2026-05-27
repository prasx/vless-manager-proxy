const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

let currentFilter = '';
let currentCountry = '';
const linkMap = {};

function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  return fetch(url, opts).then(r => r.json());
}

function makeProxiesUrl() {
  let url = '/api/proxies?filter=' + currentFilter;
  if (currentCountry) {
    if (currentCountry === 'world') {
      url += '&country=world';
    } else {
      url += '&country=RU';
    }
  }
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
  const [proxies, status, ob] = await Promise.all([
    api('GET', makeProxiesUrl()),
    api('GET', '/api/status'),
    api('GET', '/api/xray/outbounds').catch(() => ({nodes:[], traffic:{}}))
  ]);
  proxies.forEach(p => linkMap[p.id] = p.link);
  $('#statTotal').textContent = status.total;
  $('#statWorking').textContent = status.working;
  $('#statFailedRecent').textContent = status.failed_recent;
  $('#statFailedOld').textContent = status.failed_old;

  const allBtn = $('#countryAll');
  const worldBtn = $('#countryWorld');
  const ruBtn = $('#countryRu');
  if (allBtn) allBtn.textContent = 'All ' + (status.total || 0);
  if (worldBtn) worldBtn.textContent = 'World ' + (status.world || 0);
  if (ruBtn) ruBtn.textContent = 'RU ' + (status.ru || 0);
  updateCountryButtons();

  const activeEl = $('#activeNode');
  if (activeEl) {
    const nodes = ob.nodes || [];
    if (nodes.length) {
      const traffic = ob.traffic || {};
      const withTraffic = nodes.filter(t => traffic[t]?.downlink);
      activeEl.innerHTML = `// active: <b>${withTraffic.length ? withTraffic.join(', ') : nodes.join(', ')}</b> (${nodes.length} nodes)`;
    } else {
      activeEl.innerHTML = '// active: —';
    }
  }

  if (window.innerWidth <= 768) renderMobile(proxies);
  else renderDesktop(proxies);
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

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(loadData, 200);
});

loadData();
setInterval(loadData, 30000);
