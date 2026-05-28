const $ = s => document.querySelector(s);

function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  return fetch(url, opts).then(r => r.json());
}

async function load() {
  const [sources, settings] = await Promise.all([
    api('GET','/api/sources'),
    api('GET','/api/settings'),
  ]);
  const list = $('#list');
  list.innerHTML = '';
  if (!sources.length) {
    list.innerHTML = '<div class="empty">// no sources yet</div>';
  } else {
    for (const s of sources) {
      const card = document.createElement('div');
      card.className = 'card';
      const imported = s.last_import
        ? new Date(s.last_import).toLocaleString()
        : 'never';
      card.innerHTML = `
        <div class="c-body">
          <div class="c-name">${s.name}</div>
          <div class="c-url" title="${s.url}">${s.url}</div>
          <div class="c-meta">last import: ${imported}</div>
        </div>
        <div class="c-actions">
          <button class="btn btn-sm" onclick="importOne(${s.id})">import</button>
          <button class="btn btn-sm btn-danger" onclick="delSource(${s.id})">del</button>
        </div>
      `;
      list.appendChild(card);
    }
  }
  const chk = $('#chkSafeOnly');
  if (chk && settings.safe_only_import === 'true') {
    chk.checked = true;
  }
}

async function toggleSafeOnly() {
  const val = $('#chkSafeOnly').checked ? 'true' : 'false';
  await api('POST','/api/settings', { safe_only_import: val });
  toast(`safe-only import ${val === 'true' ? 'ON' : 'OFF'}`);
}

async function addProxy() {
  const link = $('#inpProxy').value.trim();
  if (!link) return;
  const res = await api('POST','/api/add', {link});
  if (res.error) return toast(res.error, 'error');
  $('#inpProxy').value = '';
  toast('proxy added');
}

async function addSource() {
  const name = $('#inpName').value.trim();
  const url = $('#inpUrl').value.trim();
  if (!name || !url) return;
  const res = await api('POST','/api/sources', {name, url});
  if (res.error) return toast(res.error, 'error');
  $('#inpName').value = '';
  $('#inpUrl').value = '';
  toast('source added');
  load();
}

async function delSource(id) {
  if (!confirm('Delete source #'+id+'?')) return;
  await api('DELETE',`/api/sources/${id}`);
  toast('source deleted');
  load();
}

async function importOne(id) {
  const res = await api('POST',`/api/sources/${id}/import`);
  toast(`imported ${res.added} proxies`);
  load();
}

async function importAll() {
  toast('importing all sources...');
  const res = await api('POST','/api/sources/import-all');
  toast(`imported ${res.added} proxies total`);
  load();
}

load();
