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
    $('checkInterval').value = s.check_interval || '3600';
    $('vlessPerProxyTimeout').value = s.vless_per_proxy_timeout || '5';
    $('logTrimEvery').value = s.log_trim_every || '500';
    $('logKeep').value = s.log_keep || '2000';
    $('observatoryProbeInterval').value = s.observatory_probe_interval || '120s';
    $('speedTestEnabled').checked = s.speed_test_enabled !== 'false';
    $('speedTestMax').value = s.speed_test_max || '20';
    $('speedTestUrl').value = s.speed_test_url || 'http://proof.ovh.net/files/100Kb.dat';
  }
  renderXrayStatus(status);
  loadCountries();
  loadGeositeRules();
  $('geoEnabled').checked = s.geo_enabled !== 'false';
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
    check_interval: $('checkInterval').value.trim() || '3600',
    vless_per_proxy_timeout: $('vlessPerProxyTimeout').value.trim() || '5',
    log_trim_every: $('logTrimEvery').value.trim() || '500',
    log_keep: $('logKeep').value.trim() || '2000',
    speed_test_enabled: $('speedTestEnabled').checked ? 'true' : 'false',
    speed_test_max: $('speedTestMax').value.trim() || '20',
    speed_test_url: $('speedTestUrl').value.trim() || 'http://proof.ovh.net/files/100Kb.dat',
    observatory_probe_interval: $('observatoryProbeInterval').value.trim() || '120s',
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
  $('checkInterval').value = '3600';
  $('vlessPerProxyTimeout').value = '5';
  $('observatoryProbeInterval').value = '120s';
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

async function toggleGeo() {
  const val = $('geoEnabled').checked ? 'true' : 'false';
  const r = await api('POST', '/api/settings', { geo_enabled: val });
  if (r.error) { toast(r.error, 'error'); $('geoEnabled').checked = val === 'true'; return; }
  toast(`Geo routing ${val === 'true' ? 'enabled' : 'disabled'}`, 'success');
}

// ─── GeoSite Rules ───

let geositeRules = [];

async function loadGeositeRules() {
  const r = await api('GET', '/api/geosite-rules');
  if (r.error) return;
  geositeRules = r.rules || [];
  renderGeositeRules();
}

function renderGeositeRules() {
  const wrap = $('geositeRulesWrap');
  if (!wrap) return;
  wrap.innerHTML = '';
  if (!geositeRules.length) {
    wrap.innerHTML = '<div class="tuning-item" style="justify-content:center;color:var(--text-muted);font-size:0.82rem;padding:12px 0">no rules — all domains go through balancer</div>';
    return;
  }
  geositeRules.forEach((rule, i) => {
    const item = document.createElement('div');
    item.className = 'tuning-item';
    item.innerHTML = `
      <input type="text" class="input geosite-domain" value="${rule.domain}" style="flex:1;font-family:monospace;max-width:360px" placeholder="geosite:google">
      <select class="input geosite-outbound" style="width:auto;min-width:110px">
        <option value="direct" ${rule.outboundTag === 'direct' ? 'selected' : ''}>direct</option>
        <option value="proxy" ${rule.outboundTag === 'proxy' ? 'selected' : ''}>proxy (balancer)</option>
      </select>
      <button class="btn btn-danger" onclick="removeGeositeRule(${i})" style="padding:2px 10px;font-size:12px;line-height:1.6">✕</button>
    `;
    wrap.appendChild(item);
  });
}

function addGeositeRule() {
  syncGeositeDomToArray();
  geositeRules.push({ domain: 'geosite:google', outboundTag: 'direct' });
  renderGeositeRules();
}

function syncGeositeDomToArray() {
  const items = document.querySelectorAll('#geositeRulesWrap .tuning-item');
  const rules = [];
  items.forEach(item => {
    const domain = item.querySelector('.geosite-domain');
    const outbound = item.querySelector('.geosite-outbound');
    if (domain && outbound && domain.value.trim()) {
      rules.push({ domain: domain.value.trim(), outboundTag: outbound.value });
    }
  });
  if (rules.length) geositeRules = rules;
}

function removeGeositeRule(idx) {
  geositeRules.splice(idx, 1);
  renderGeositeRules();
}

async function saveGeositeRules() {
  syncGeositeDomToArray();
  const rules = geositeRules;
  const r = await api('POST', '/api/geosite-rules', { rules });
  if (r.error) { toast(r.error, 'error'); return; }
  toast(`Saved ${r.count} GeoSite rules — config rebuilding...`, 'success');
  loadGeositeRules();
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

// ─── Backup ───

async function exportBackup() {
  const r = await api('GET', '/api/backup');
  if (r.error) { toast(r.error, 'error'); return; }
  const blob = new Blob([JSON.stringify(r, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vless-backup-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('Backup downloaded', 'success');
}

async function importBackup(event) {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const r = await api('POST', '/api/backup/import', data);
    if (r.error) { toast(r.error, 'error'); return; }
    toast(`Imported: ${r.imported.settings} settings, ${r.imported.sources} sources`, 'success');
    loadSettings();
  } catch (e) {
    toast('Invalid JSON file: ' + e.message, 'error');
  }
  event.target.value = '';
}

loadSettings();
setInterval(() => {
  api('GET', '/api/xray/status').then(renderXrayStatus).catch(() => {});
}, 5000);
