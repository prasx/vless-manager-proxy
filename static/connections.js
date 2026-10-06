/* Модалка «Соединения»: активные TCP-соединения через прокси и трафик по клиентам.

   Живёт в общей панели (подключается из base.html на каждой странице), потому
   что «Соединения» — раздел единой навигации: пункт меню должен работать
   одинаково везде, а не только на дашборде. Разметка модалки тоже в base.html.

   $ , esc(), api() и toast() приходят из api.js / toast.js. */
(function () {
  let refreshTimer = null;

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
      refreshTimer = setInterval(() => {
        loadConnections();
        loadPerIPTraffic();
      }, 3000);
    } else {
      if (refreshTimer) clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  function closeConnModal() {
    const m = $('#connModal');
    if (m) {
      m.classList.remove('open');
      setBodyModalLock(false);
    }
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = null;
  }

  function formatConnBytes(b) {
    if (b == null || b <= 0) return '0B';
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
    const r = await api('POST', '/api/connections/close', { remote_host: host, remote_port: port });
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

  // Модалка вызывается из разметки (base.html) и из inline-обработчиков внутри
  // неё, поэтому функции отдаём в глобальную область — как theme.js с toggleTheme.
  window.toggleConnModal = toggleConnModal;
  window.closeConnModal = closeConnModal;
  window.loadConnections = loadConnections;
  window.loadPerIPTraffic = loadPerIPTraffic;
  window.filterConnTable = filterConnTable;
  window.closeConn = closeConn;
  window.flushConns = flushConns;

  // Клик по подложке (вне окна) закрывает модалку
  document.addEventListener('click', (e) => {
    const m = $('#connModal');
    if (m && m.classList.contains('open') && e.target === m) {
      closeConnModal();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeConnModal();
  });
})();
