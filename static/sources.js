const $ = s => document.querySelector(s);
let _editTxtId = null;

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
      const isTxt = (s.type || 'url') === 'txt';
      card.innerHTML = `
        <div class="c-body">
          <div class="c-name">
            <span class="c-type ${isTxt ? 'type-txt' : 'type-url'}">${isTxt ? 'TXT' : 'URL'}</span>
            ${s.name}
          </div>
          <div class="c-url" title="${isTxt ? 'TXT content source' : s.url}">${isTxt ? 'TXT source' : s.url}</div>
          <div class="c-meta">last import: ${imported}</div>
        </div>
        <div class="c-actions">
          ${isTxt ? `<button class="btn btn-sm" onclick="editTxtContent(${s.id})">edit</button>` : ''}
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

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-active'));
  document.querySelector(`.tab[data-tab="${tab}"]`).classList.add('tab-active');
  document.getElementById('urlSourceForm').style.display = tab === 'url' ? '' : 'none';
  document.getElementById('txtSourceForm').style.display = tab === 'txt' ? '' : 'none';
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

async function addTxtSource() {
  const name = $('#inpNameTxt').value.trim();
  const content = $('#inpTxtContent').value.trim();
  if (!name || !content) return;
  const res = await api('POST','/api/sources/txt', {name, content});
  if (res.error) return toast(res.error, 'error');
  $('#inpNameTxt').value = '';
  $('#inpTxtContent').value = '';
  toast('TXT source added');
  load();
}

async function editTxtContent(id) {
  const res = await api('GET',`/api/sources/${id}/content`);
  if (res.error) return toast(res.error, 'error');
  _editTxtId = id;
  $('#dlgTxtContent').value = res.content || '';
  document.getElementById('dlgEditTxt').showModal();
}

async function saveTxtContent() {
  if (_editTxtId === null) return;
  const content = $('#dlgTxtContent').value.trim();
  if (!content) return toast('content cannot be empty', 'error');
  await api('PUT',`/api/sources/${_editTxtId}/content`, {content});
  document.getElementById('dlgEditTxt').close();
  _editTxtId = null;
  toast('TXT content updated');
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
  if (res.error) return toast(`import failed: ${res.error}`, 'error');
  toast(`imported ${res.added} proxies`);
  load();
}

async function importAll() {
  toast('importing all sources...');
  const res = await api('POST','/api/sources/import-all');
  if (res.error) return toast(`import failed: ${res.error}`, 'error');
  if (res.errors && res.errors.length) {
    toast(`imported ${res.added} proxies — ${res.errors.length} source(s) failed: ${res.errors[0]}`, 'error');
  } else {
    toast(`imported ${res.added} proxies total`);
  }
  load();
}

load();
