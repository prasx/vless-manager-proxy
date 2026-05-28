const $ = s => document.querySelector(s);

let allLogs = [];
let totalLogs = 0;
let isLoading = false;
const PAGE_SIZE = 50;

function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  return fetch(url, opts).then(r => r.json());
}

async function loadData() {
  isLoading = true;
  allLogs = [];
  totalLogs = 0;
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
  const offset = reset ? 0 : allLogs.length;
  const data = await api('GET', `/api/logs?limit=${PAGE_SIZE}&offset=${offset}`);
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
    tb.innerHTML = '<tr><td colspan="3" class="empty">no logs yet</td></tr>';
    return;
  }
  for (const row of allLogs) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="color:var(--text-muted);white-space:nowrap">${row.timestamp}</td>
      <td class="level-${row.level}">${row.level}</td>
      <td style="word-break:break-word">${escHtml(row.message)}</td>
    `;
    tb.appendChild(tr);
  }
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
  btn.textContent = `Show next ${next} (${allLogs.length}/${totalLogs})`;
  info.textContent = `${allLogs.length} of ${totalLogs} entries`;
}

async function clearLogs() {
  if (!confirm('Clear all logs?')) return;
  await api('POST', '/api/logs/clear');
  toast('logs cleared');
  loadData();
}

loadData();
