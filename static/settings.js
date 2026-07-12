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

function fmtHours(v) {
  const h = Math.floor(v);
  const m = Math.round((v - h) * 60);
  return m ? `${h}h ${m}m` : `${h}h`;
}

let _rangeDb, _rangeImport;

function setupRange(id, labelId) {
  const el = $(id);
  const label = $(labelId);
  if (!el || !label) return null;
  const update = () => { label.textContent = fmtHours(parseFloat(el.value)); };
  el.addEventListener('input', update);
  return { el, update };
}

function setRangeValue(range, val) {
  if (!range) return;
  if (isNaN(val)) return;
  range.el.value = val;
  range.update();
}

// ─── Dirty flag ───
let _dirty = false;
let _initialSnapshot = null;
let _watching = false;

function takeSnapshot() {
  const s = {};
  document.querySelectorAll('.settings-section input, .settings-section select').forEach(el => {
    if (el.type === 'checkbox' || el.type === 'radio') {
      s[el.id || el.name] = el.checked;
    } else {
      s[el.id || el.name] = el.value;
    }
  });
  return s;
}

function markDirty() {
  if (!_dirty) {
    _dirty = true;
    updateDirtyUI();
  }
}

function markClean() {
  _dirty = false;
  _initialSnapshot = takeSnapshot();
  updateDirtyUI();
}

function updateDirtyUI() {
  const el = $('dirtyIndicator');
  if (!el) return;
  if (_dirty) {
    el.textContent = '⚠ unsaved changes';
    el.className = 'settings-dirty-indicator dirty';
  } else {
    el.textContent = '';
    el.className = 'settings-dirty-indicator';
  }
}

function isDirty() { return _dirty; }

function watchDirty() {
  if (_watching) return;
  _watching = true;
  document.querySelectorAll('.settings-section input, .settings-section select').forEach(el => {
    el.addEventListener('change', () => {
      if (!_initialSnapshot) return;
      const id = el.id || el.name;
      const cur = el.type === 'checkbox' ? el.checked : el.value;
      if (_initialSnapshot[id] !== cur) {
        markDirty();
      }
    });
    el.addEventListener('input', () => {
      if (!_initialSnapshot) return;
      const id = el.id || el.name;
      const cur = el.type === 'checkbox' ? el.checked : el.value;
      if (_initialSnapshot[id] !== cur) {
        markDirty();
      }
    });
  });
}

window.addEventListener('beforeunload', e => {
  if (isDirty()) {
    e.preventDefault();
    e.returnValue = '';
  }
});

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
    item.querySelector('input, select').addEventListener('change', markDirty);
    wrap.appendChild(item);
  });
}

function addGeositeRule() {
  syncGeositeDomToArray();
  geositeRules.push({ domain: 'geosite:google', outboundTag: 'direct' });
  renderGeositeRules();
  markDirty();
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
  markDirty();
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
    const cnt = $('countryFilterCount');
    if (cnt) cnt.textContent = '';
    return;
  }
  const allowedSet = new Set(allowedRaw.split(',').map(s => s.trim()).filter(Boolean));
  let selected = 0;
  for (const c of countryData) {
    const checked = !allowedRaw ? true : allowedSet.has(c.code);
    if (checked) selected++;
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
    tr.querySelector('input[type="checkbox"]').addEventListener('change', markDirty);
    tb.appendChild(tr);
  }
  const cnt = $('countryFilterCount');
  if (cnt) cnt.textContent = `${selected} / ${countryData.length} selected`;
}

function selectAllCountries(checked) {
  const boxes = document.querySelectorAll('#countryFilterBody input[type="checkbox"]');
  boxes.forEach(cb => { cb.checked = checked; });
  markDirty();
}

function collectAllowedCountries() {
  const checked = [];
  document.querySelectorAll('#countryFilterBody input[type="checkbox"]:checked').forEach(cb => {
    checked.push(cb.dataset.code);
  });
  return checked.join(',');
}

// ─── Load ───
async function loadSettings() {
  const [s, status] = await Promise.all([
    api('GET', '/api/settings'),
    api('GET', '/api/xray/status'),
  ]);
  if (s.error) return;
  $('xrayBin').value = s.xray_bin || 'xray';
  $('xrayConfigPath').value = s.xray_config_path || '';
  $('proxyListen').value = s.proxy_listen || '0.0.0.0';
  $('maxActiveProxies').value = s.max_active_proxies || '30';
  $('probeUrl').value = s.probe_url || 'https://www.gstatic.com/generate_204';
  const oldVal = s.check_interval || '3600';
  const dbRaw = s.check_interval_db || oldVal;
  const impRaw = s.check_interval_import || '10800';
  setRangeValue(_rangeDb, Math.round(parseInt(dbRaw) / 1800) / 2);
  setRangeValue(_rangeImport, Math.round(parseInt(impRaw) / 1800) / 2);
  $('vlessPerProxyTimeout').value = s.vless_per_proxy_timeout || '5';
  $('logTrimEvery').value = s.log_trim_every || '500';
  $('logKeep').value = s.log_keep || '2000';
  $('observatoryProbeInterval').value = s.observatory_probe_interval || '15s';
  $('balancerStrategy').value = s.balancer_strategy || 'random';
  $('handshakeTimeout').value = s.handshake_timeout || '8';
  $('connIdle').value = s.conn_idle || '300';
  $('dbCheckAutoCleanup').checked = s.db_check_auto_cleanup === 'true';
  $('speedTestEnabled').checked = s.speed_test_enabled !== 'false';
  $('speedTestMax').value = s.speed_test_max || '30';
  $('speedTestUrl').value = s.speed_test_url || 'http://speedtest.selectel.ru/10MB';
  $('applyAfterTest').checked = s.apply_after_test !== 'false';
  $('minSpeedMbps').value = s.min_speed_mbps || '0';
  $('speedTestAdaptiveSec').value = s.speed_test_adaptive_sec || '2';
  $('safeOnlyImport').checked = s.safe_only_import === 'true';
  $('sniffingEnabled').checked = s.sniffing_enabled !== 'false';
  $('sniffingRouteOnly').checked = s.sniffing_route_only !== 'false';
  const destOverride = (s.sniffing_dest_override || 'http,tls').split(',').map(x => x.trim());
  $('sniffHttp').checked = destOverride.includes('http');
  $('sniffTls').checked = destOverride.includes('tls');
  $('sniffQuic').checked = destOverride.includes('quic');
  $('sniffFtp').checked = destOverride.includes('ftp');
  $('geoEnabled').checked = s.geo_enabled !== 'false';
  $('maxWorkers').value = s.max_workers || '10';
  $('probeTimeout').value = s.probe_timeout || '5';
  $('xrayStartupRetries').value = s.xray_startup_retries || '30';
  updateConfigStatus(status);
  updateSpeedTestDependants();
  loadPerfEstimate();
  markClean();
  watchDirty();
}

function updateConfigStatus(status) {
  const el = $('configStatus');
  if (!el) return;
  if (status.error) { el.textContent = '—'; return; }
  const active = status.nodes_in_config || 0;
  const candidates = status.config_candidates || 0;
  const api = status.api_accessible;
  if (!api) {
    el.textContent = `${candidates} candidates (API unavailable)`;
    el.style.color = 'var(--text-muted)';
    return;
  }
  el.textContent = `${active} nodes in config · ${candidates} eligible`;
  el.style.color = 'var(--green)';
}

function updateSpeedTestDependants() {
  const enabled = $('speedTestEnabled').checked;
  const body = $('speedTestBody');
  if (!body) return;
  const inputs = body.querySelectorAll('input');
  inputs.forEach(inp => {
    if (inp.id !== 'speedTestEnabled') {
      inp.disabled = !enabled;
    }
  });
  body.style.opacity = enabled ? '1' : '0.45';
}

async function rebuildConfig() {
  const btn = document.querySelector('button[onclick*="rebuildConfig"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Rebuilding...'; }
  const r = await api('POST', '/api/xray/rebuild');
  if (r.error) { toast(r.error, 'error'); }
  else { toast('Config rebuild triggered', 'success'); }
  if (btn) { btn.disabled = false; btn.textContent = 'Rebuild'; }
  setTimeout(() => loadSettings(), 2000);
}

async function loadPerfEstimate() {
  const estVal = $('perfEstValue');
  const estDetail = $('perfEstDetail');
  const r = await api('GET', '/api/performance/recommendations');
  if (r.error) return;
  const c = r.current;
  if (estVal) estVal.textContent = c.estimated_label;
  if (estDetail) estDetail.textContent = `${c.total} profiles, ${c.workers} workers`;
}

// ─── Validation ───
function validateSettings() {
  const errors = [];
  const numFields = [
    { id: 'maxActiveProxies', label: 'Max active' },
    { id: 'maxWorkers', label: 'Max workers' },
    { id: 'probeTimeout', label: 'Probe timeout' },
    { id: 'vlessPerProxyTimeout', label: 'VLESS timeout' },
    { id: 'handshakeTimeout', label: 'Handshake timeout' },
    { id: 'connIdle', label: 'Idle timeout' },
    { id: 'speedTestMax', label: 'Speed test max' },
    { id: 'speedTestAdaptiveSec', label: 'Adaptive check' },
    { id: 'logTrimEvery', label: 'Trim every' },
    { id: 'logKeep', label: 'Keep last' },
    { id: 'xrayStartupRetries', label: 'Startup retries' },
  ];
  for (const f of numFields) {
    const el = $(f.id);
    if (!el) continue;
    const val = parseInt(el.value);
    if (el.value.trim() && (isNaN(val) || val < 0)) {
      errors.push(`${f.label}: must be a positive number`);
    }
    const min = parseInt(el.getAttribute('min'));
    if (min !== null && !isNaN(min) && !isNaN(val) && val < min) {
      errors.push(`${f.label}: minimum is ${min}`);
    }
    const max = parseInt(el.getAttribute('max'));
    if (max !== null && !isNaN(max) && !isNaN(val) && val > max) {
      errors.push(`${f.label}: maximum is ${max}`);
    }
  }
  const probeUrl = $('probeUrl').value.trim();
  if (probeUrl && !probeUrl.startsWith('http')) {
    errors.push('Probe URL must start with http:// or https://');
  }
  return errors;
}

async function saveSettings() {
  const errors = validateSettings();
  if (errors.length) {
    toast('Validation errors:\n• ' + errors.join('\n• '), 'error');
    return;
  }

  syncGeositeDomToArray();

  $('xrayBin').disabled = true;
  $('xrayConfigPath').disabled = true;
  $('proxyListen').disabled = true;
  const data = {
    xray_bin: $('xrayBin').value.trim(),
    xray_config_path: $('xrayConfigPath').value.trim(),
    proxy_listen: $('proxyListen').value.trim() || '0.0.0.0',
    max_active_proxies: $('maxActiveProxies').value.trim() || '30',
    probe_url: $('probeUrl').value.trim() || 'https://www.gstatic.com/generate_204',
    check_interval_db: String(Math.round(parseFloat($('checkIntervalDb').value || '0.5') * 3600)),
    check_interval_import: String(Math.round(parseFloat($('checkIntervalImport').value || '3') * 3600)),
    vless_per_proxy_timeout: $('vlessPerProxyTimeout').value.trim() || '5',
    log_trim_every: $('logTrimEvery').value.trim() || '500',
    log_keep: $('logKeep').value.trim() || '2000',
    speed_test_enabled: $('speedTestEnabled').checked ? 'true' : 'false',
    speed_test_max: $('speedTestMax').value.trim() || '30',
    speed_test_url: $('speedTestUrl').value.trim() || 'http://speedtest.selectel.ru/10MB',
    db_check_auto_cleanup: $('dbCheckAutoCleanup').checked ? 'true' : 'false',
    apply_after_test: $('applyAfterTest').checked ? 'true' : 'false',
    min_speed_mbps: $('minSpeedMbps').value.trim() || '0',
    speed_test_adaptive_sec: $('speedTestAdaptiveSec').value.trim() || '2',
    observatory_probe_interval: $('observatoryProbeInterval').value.trim() || '15s',
    balancer_strategy: $('balancerStrategy').value,
    safe_only_import: $('safeOnlyImport').checked ? 'true' : 'false',
    handshake_timeout: $('handshakeTimeout').value.trim() || '8',
    conn_idle: $('connIdle').value.trim() || '300',
    // Sniffing
    sniffing_enabled: $('sniffingEnabled').checked ? 'true' : 'false',
    sniffing_route_only: $('sniffingRouteOnly').checked ? 'true' : 'false',
    sniffing_dest_override: (() => {
      const parts = [];
      if ($('sniffHttp').checked) parts.push('http');
      if ($('sniffTls').checked) parts.push('tls');
      if ($('sniffQuic').checked) parts.push('quic');
      if ($('sniffFtp').checked) parts.push('ftp');
      return parts.join(',');
    })(),
    // Geo
    geo_enabled: $('geoEnabled').checked ? 'true' : 'false',
    allowed_countries: collectAllowedCountries(),
    geosite_rules: JSON.stringify(geositeRules),
    // Performance
    max_workers: $('maxWorkers').value.trim() || '10',
    probe_timeout: $('probeTimeout').value.trim() || '5',
    xray_startup_retries: $('xrayStartupRetries').value.trim() || '30',
  };
  const r = await api('POST', '/api/settings', data);
  $('xrayBin').disabled = false;
  $('xrayConfigPath').disabled = false;
  $('proxyListen').disabled = false;
  if (r.error) { toast(r.error, 'error'); return; }
  toast(r.restart_hint || 'Settings saved', 'success');
  loadSettings();
}

function resetTuning() {
  setRangeValue(_rangeDb, 0.5);
  setRangeValue(_rangeImport, 3);
  $('vlessPerProxyTimeout').value = '5';
  $('observatoryProbeInterval').value = '15s';
  $('logTrimEvery').value = '500';
  $('logKeep').value = '2000';
  $('handshakeTimeout').value = '8';
  $('connIdle').value = '300';
  $('speedTestMax').value = '30';
  $('speedTestUrl').value = 'http://speedtest.selectel.ru/10MB';
  $('minSpeedMbps').value = '0';
  $('speedTestAdaptiveSec').value = '2';
  $('safeOnlyImport').checked = false;
  $('balancerStrategy').value = 'random';
  $('maxWorkers').value = '20';
  $('probeTimeout').value = '5';
  $('xrayStartupRetries').value = '15';
  markDirty();
  toast('Tuning values reset to defaults — click Save to apply');
}

async function restartXray() {
  toast('restarting xray ...');
  const r = await api('POST', '/api/xray-restart');
  if (r && r.error) toast(r.error, 'error');
}

function resetProbeUrl() {
  $('probeUrl').value = 'https://www.gstatic.com/generate_204';
  markDirty();
  toast('Probe URL reset to default');
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

function confirmImportBackup() {
  if (confirm('Import backup? This will overwrite all current settings and sources.')) {
    document.getElementById('backupFile').click();
  }
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

_rangeDb = setupRange('checkIntervalDb', 'checkIntervalDbLabel');
_rangeImport = setupRange('checkIntervalImport', 'checkIntervalImportLabel');
$('speedTestEnabled').addEventListener('change', updateSpeedTestDependants);

function updatePerfEstimate() {
  const workers = parseInt($('maxWorkers').value) || 20;
  const probeT = parseInt($('probeTimeout').value) || 5;
  const retries = parseInt($('xrayStartupRetries').value) || 30;
  const startup = retries * 0.05;
  const perProxy = startup + probeT;
  const est = 681 / workers * perProxy;
  const estMin = (est / 60).toFixed(1);
  const estVal = $('perfEstValue');
  const estDetail = $('perfEstDetail');
  if (estVal) estVal.textContent = `~${estMin} min`;
  if (estDetail) estDetail.textContent = `681 profiles, ${workers} workers`;
}
$('maxWorkers').addEventListener('input', updatePerfEstimate);
$('probeTimeout').addEventListener('input', updatePerfEstimate);
$('xrayStartupRetries').addEventListener('input', updatePerfEstimate);

loadSettings();
loadCountries();
loadGeositeRules();
setInterval(() => {
  api('GET', '/api/xray/status').then(renderXrayStatus).catch(() => {});
}, 5000);
