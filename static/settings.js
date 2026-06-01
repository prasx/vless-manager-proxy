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
    $('maxActiveProxies').value = s.max_active_proxies || '30';
    $('probeUrl').value = s.probe_url || 'https://www.gstatic.com/generate_204';
    $('checkInterval').value = s.check_interval || '600';
    $('tcpInterval').value = s.tcp_interval || '3600';
    $('vlessInterval').value = s.vless_interval || '10800';
    $('testWorkers').value = s.test_workers || '20';
    $('vlessPerProxyTimeout').value = s.vless_per_proxy_timeout || '5';
    $('logTrimEvery').value = s.log_trim_every || '500';
    $('logKeep').value = s.log_keep || '2000';
  }
  renderXrayStatus(status);
  loadCountries();
}

async function saveSettings() {
  $('xrayBin').disabled = true;
  $('xrayConfigPath').disabled = true;
  $('proxyListen').disabled = true;
  const data = {
    xray_bin: $('xrayBin').value.trim(),
    xray_config_path: $('xrayConfigPath').value.trim(),
    proxy_listen: $('proxyListen').value.trim() || '0.0.0.0',
    max_active_proxies: $('maxActiveProxies').value.trim() || '30',
    probe_url: $('probeUrl').value.trim() || 'https://www.gstatic.com/generate_204',
    check_interval: $('checkInterval').value.trim() || '600',
    tcp_interval: $('tcpInterval').value.trim() || '3600',
    vless_interval: $('vlessInterval').value.trim() || '10800',
    test_workers: $('testWorkers').value.trim() || '20',
    vless_per_proxy_timeout: $('vlessPerProxyTimeout').value.trim() || '5',
    log_trim_every: $('logTrimEvery').value.trim() || '500',
    log_keep: $('logKeep').value.trim() || '2000',
  };
  const r = await api('POST', '/api/settings', data);
  $('xrayBin').disabled = false;
  $('xrayConfigPath').disabled = false;
  $('proxyListen').disabled = false;
  if (r.error) { toast(r.error, 'error'); return; }
  if (r.restart_hint) {
    toast(r.restart_hint, 'success');
  } else if (data.proxy_listen || data.xray_config_path) {
    const rr = await api('POST', '/api/xray-restart');
    if (rr.error) toast(rr.error, 'error');
    else toast(rr.message || 'Xray restarted', 'success');
  } else {
    toast('Settings saved', 'success');
  }
  loadSettings();
}

function resetTuning() {
  $('checkInterval').value = '600';
  $('tcpInterval').value = '3600';
  $('vlessInterval').value = '10800';
  $('testWorkers').value = '20';
  $('vlessPerProxyTimeout').value = '5';
  $('logTrimEvery').value = '500';
  $('logKeep').value = '2000';
  toast('Tuning values reset to defaults — click Save to apply');
}

async function restartXray() {
  toast('restarting xray ...');
  const r = await api('POST', '/api/xray-restart');
  if (r && r.error) toast(r.error, 'error');
}

function resetProbeUrl() {
  $('probeUrl').value = 'https://www.gstatic.com/generate_204';
  toast('Probe URL reset to default');
}

// ─── Country Filter ───

let countryData = [];

async function loadCountries() {
  const data = await api('GET', '/api/countries');
  if (data.error) return;
  countryData = data.countries || [];
  renderCountryFilter(data.allowed);
}

function renderCountryFilter(allowedRaw) {
  const tb = $('countryFilterBody');
  if (!tb) return;
  tb.innerHTML = '';
  if (!countryData.length) {
    tb.innerHTML = '<tr><td colspan="3" class="empty">no countries detected yet — import some proxies</td></tr>';
    return;
  }
  const allowedSet = new Set(allowedRaw.split(',').map(s => s.trim()).filter(Boolean));
  for (const c of countryData) {
    const checked = !allowedRaw ? true : allowedSet.has(c.code);
    const tr = document.createElement('tr');
    tr.style.cssText = 'border-bottom:1px solid var(--border)';
    tr.innerHTML = `
      <td style="padding:4px 12px;width:40px">
        <input type="checkbox" class="chk-custom" data-code="${c.code}" ${checked ? 'checked' : ''}>
      </td>
      <td style="padding:4px 6px;font-weight:bold;color:var(--text-primary)">${c.code}</td>
      <td style="padding:4px 6px;color:var(--text-muted);font-size:0.72rem">
        ${c.working} working / ${c.total} total
      </td>
    `;
    tb.appendChild(tr);
  }
}

function selectAllCountries(checked) {
  const boxes = document.querySelectorAll('#countryFilterBody input[type="checkbox"]');
  boxes.forEach(cb => cb.checked = checked);
}

async function saveCountryFilter() {
  const checked = [];
  document.querySelectorAll('#countryFilterBody input[type="checkbox"]:checked').forEach(cb => {
    checked.push(cb.dataset.code);
  });
  const val = checked.join(',');
  const r = await api('POST', '/api/settings', { allowed_countries: val });
  if (r.error) { toast(r.error, 'error'); return; }
  toast('Country filter saved — rebuilding config...', 'success');
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
