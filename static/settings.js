async function api(method, url, body) {
  const opts = { method, headers: {'Content-Type':'application/json'} };
  if (body !== undefined) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(url, opts);
    return r.json();
  } catch (e) {
    toast('Network error: ' + e.message, 'error');
    return {error: e.message};
  }
}

const $ = id => document.getElementById(id);

async function loadSettings() {
  const [s, status] = await Promise.all([
    api('GET', '/api/settings'),
    api('GET', '/api/xray/status'),
  ]);
  if (!s.error) {
    $('xrayBin').value = s.xray_bin || 'xray';
    $('xrayConfigPath').value = s.xray_config_path || '';
    $('proxyListen').value = s.proxy_listen || '0.0.0.0';
  }
  renderXrayStatus(status);
}

async function saveSettings() {
  $('xrayBin').disabled = true;
  $('xrayConfigPath').disabled = true;
  $('proxyListen').disabled = true;
  const data = {
    xray_bin: $('xrayBin').value.trim(),
    xray_config_path: $('xrayConfigPath').value.trim(),
    proxy_listen: $('proxyListen').value.trim() || '0.0.0.0',
  };
  const r = await api('POST', '/api/settings', data);
  $('xrayBin').disabled = false;
  $('xrayConfigPath').disabled = false;
  $('proxyListen').disabled = false;
  if (r.error) { toast(r.error, 'error'); return; }
  toast('Settings saved', 'success');
  if (r.restart_hint) {
    toast(r.restart_hint, 'success');
  } else if (data.proxy_listen || data.xray_config_path) {
    toast('Restarting Xray...');
    const rr = await api('POST', '/api/xray-restart');
    if (rr.error) toast(rr.error, 'error');
    else toast(rr.message || 'Xray restarted', 'success');
  }
  loadSettings();
}

async function restartXray() {
  toast('restarting xray...');
  const r = await api('POST', '/api/xray-restart');
  if (r.error) { toast(r.error, 'error'); return; }
  toast('xray restarted', 'success');
}

// ─── Xray Daemon ───

function renderXrayStatus(s) {
  const el = $('xrayStatus');
  if (!el) return;
  const run = s.running ? '<span class="badge badge-green">running</span>' : '<span class="badge badge-muted">stopped</span>';
  const api_ok = s.api_accessible ? 'API ✓' : 'API ✗';
  const sd = s.systemd_active ? 'systemd ✓' : '';
  const active = s.active_outbounds && s.active_outbounds.length
    ? `nodes: ${s.active_outbounds.filter(t => t.startsWith('node')).join(', ')}` : '';
  el.innerHTML = `${run} &nbsp;${api_ok} &nbsp;${sd}<br><span style="color:var(--green);font-size:11px">${active}</span>`;
  const btnStart = $('btnXrayStart');
  const btnStop = $('btnXrayStop');
  if (btnStart) btnStart.style.display = s.running ? 'none' : '';
  if (btnStop) btnStop.style.display = s.running ? '' : 'none';
}

async function startXrayDaemon() {
  const r = await api('POST', '/api/xray/start');
  if (r.error) { toast(r.error, 'error'); return; }
  toast(r.message || 'started', 'success');
  loadSettings();
}

async function stopXrayDaemon() {
  await api('POST', '/api/xray/stop');
  toast('xray stopped', 'success');
  loadSettings();
}

loadSettings();
setInterval(() => {
  api('GET', '/api/xray/status').then(renderXrayStatus).catch(() => {});
}, 5000);
