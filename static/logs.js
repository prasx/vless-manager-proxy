const $ = s => document.querySelector(s);

let allLogs = [];
let totalLogs = 0;
let isLoading = false;
let currentLevel = '';
const PAGE_SIZE = 50;
let pollTimer = null;

function setLevel(level) {
  currentLevel = level;
  loadData();
}

async function loadData() {
  isLoading = true;
  allLogs = [];
  totalLogs = 0;
  setLoadingRow();
  await fetchPage(true);
  isLoading = false;
}

function setLoadingRow() {
  const tb = $('#logBody');
  if (tb) tb.innerHTML = '<tr><td colspan="4" class="empty">// загрузка логов…</td></tr>';
}

function renderLoadError() {
  const tb = $('#logBody');
  if (tb) tb.innerHTML = '<tr><td colspan="4" class="empty">// данные не загружены</td></tr>';
}

function showLoadError(cause) {
  const el = $('#logError');
  if (!el) return;
  el.hidden = false;
  el.innerHTML = `<span>Не удалось загрузить логи: ${escHtml(cause)}</span>
    <button class="btn btn-sm" onclick="loadData()">повторить</button>`;
}

function hideLoadError() {
  const el = $('#logError');
  if (!el) return;
  el.hidden = true;
  el.innerHTML = '';
}

async function loadMore() {
  if (isLoading) return;
  isLoading = true;
  await fetchPage(false);
  isLoading = false;
}

async function fetchPage(reset) {
  const offset = reset ? 0 : allLogs.length;
  let url = `/api/logs?limit=${PAGE_SIZE}&offset=${offset}`;
  if (currentLevel) url += `&level=${currentLevel}`;
  const data = await api('GET', url);
  if (data.error) {
    showLoadError(data.error);
    if (reset) {
      renderLoadError();
      updatePagination();
    }
    return;
  }
  hideLoadError();
  const logs = data.logs || [];
  totalLogs = data.total || logs.length;

  if (reset) {
    allLogs = logs;
  } else {
    allLogs = [...allLogs, ...logs];
  }

  render();
  updatePagination();
}

function render() {
  const tb = $('#logBody');
  tb.innerHTML = '';
  if (!allLogs.length) {
    tb.innerHTML = '<tr><td colspan="4" class="empty">// логов пока нет</td></tr>';
    return;
  }
  for (const row of allLogs) {
    const tr = document.createElement('tr');
    const cid = row.correlation_id || '';
    tr.innerHTML = `
      <td style="color:var(--text-muted);white-space:nowrap">${row.timestamp}</td>
      <td class="level-${row.level}">${row.level}</td>
      <td style="font-size:0.65rem;color:var(--text-muted);font-family:monospace">${cid ? cid.slice(0,8) : ''}</td>
      <td style="word-break:break-word">${escHtml(row.message)}</td>
    `;
    tb.appendChild(tr);
  }
}

function renderRow(row) {
  const tr = document.createElement('tr');
  const cid = row.correlation_id || '';
  tr.innerHTML = `
    <td style="color:var(--text-muted);white-space:nowrap">${row.timestamp}</td>
    <td class="level-${row.level}">${row.level}</td>
    <td style="font-size:0.65rem;color:var(--text-muted);font-family:monospace">${cid ? cid.slice(0,8) : ''}</td>
    <td style="word-break:break-word">${escHtml(row.message)}</td>
  `;
  return tr;
}

async function pollNew() {
  if (isLoading) return;
  let url = `/api/logs?limit=20&offset=0`;
  if (currentLevel) url += `&level=${currentLevel}`;
  const data = await api('GET', url);
  if (data.error) return;
  const hadError = $('#logError') ? !$('#logError').hidden : false;
  hideLoadError();
  const logs = data.logs || [];
  if (!logs.length) {
    if (!allLogs.length && hadError) render();
    return;
  }
  // timestamp имеет точность до секунды, id уникален
  const existingIds = new Set(allLogs.map(r => r.id));
  const fresh = logs.filter(r => !existingIds.has(r.id));
  if (!fresh.length) return;
  const tb = $('#logBody');
  const empty = tb.querySelector('.empty');
  if (empty) empty.remove();
  for (let i = fresh.length - 1; i >= 0; i--) {
    allLogs.unshift(fresh[i]);
    tb.prepend(renderRow(fresh[i]));
  }
  totalLogs = data.total || totalLogs;
  updatePagination();
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function updatePagination() {
  const bar = $('#logPagination');
  const btn = $('#logShowMoreBtn');
  const info = $('#logPaginationInfo');
  if (!bar || !btn || !info) return;

  if (allLogs.length >= totalLogs || totalLogs <= PAGE_SIZE) {
    bar.style.display = 'none';
    return;
  }

  bar.style.display = 'flex';
  const remaining = totalLogs - allLogs.length;
  const next = Math.min(PAGE_SIZE, remaining);
  btn.textContent = `Показать ещё ${next} (${allLogs.length}/${totalLogs})`;
  info.textContent = `Записей: ${allLogs.length} из ${totalLogs}`;
}

async function clearLogs() {
  if (!confirm('Очистить все логи?')) return;
  const res = await api('POST', '/api/logs/clear');
  if (res.error) return toast(res.error, 'error');
  toast('логи очищены', 'success');
  loadData();
}

loadData();
pollTimer = setInterval(pollNew, 1000);
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    clearInterval(pollTimer);
    pollTimer = null;
  } else if (!pollTimer) {
    pollTimer = setInterval(pollNew, 1000);
  }
});
