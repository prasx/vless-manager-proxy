async function api(method, url, body) {
  const opts = { method, headers: {'Content-Type':'application/json'} };
  if (body !== undefined) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(url, opts);
    return r.json();
  } catch (e) {
    toast('Сетевая ошибка: ' + e.message, 'error');
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
let _profileCount = 0;

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
    el.textContent = '⚠ есть несохранённые изменения';
    el.className = 'settings-dirty-indicator dirty';
  } else {
    el.textContent = '';
    el.className = 'settings-dirty-indicator';
  }
}

function isDirty() { return _dirty; }

function clearInputError(el) {
  if (!el) return;
  el.classList.remove('input-invalid');
  const panel = $('validationPanel');
  if (panel && panel.style.display === 'block') {
    panel.style.display = 'none';
    panel.innerHTML = '';
  }
}

function watchDirty() {
  if (_watching) return;
  _watching = true;
  document.querySelectorAll('.settings-section input, .settings-section select').forEach(el => {
    const onChange = () => {
      clearInputError(el);
      if (!_initialSnapshot) return;
      const id = el.id || el.name;
      const cur = el.type === 'checkbox' ? el.checked : el.value;
      if (_initialSnapshot[id] !== cur) {
        markDirty();
      }
    };
    el.addEventListener('change', onChange);
    el.addEventListener('input', onChange);
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
    wrap.innerHTML = '<div class="tuning-item" style="justify-content:center;color:var(--text-muted);font-size:0.82rem;padding:12px 0">правил нет — весь трафик идёт через балансер</div>';
    return;
  }
  geositeRules.forEach((rule, i) => {
    const item = document.createElement('div');
    item.className = 'tuning-item';
    item.innerHTML = `
      <input type="text" class="input geosite-domain" value="${rule.domain}" style="flex:1;font-family:monospace;max-width:360px" placeholder="geosite:google">
      <select class="input geosite-outbound" style="width:auto;min-width:150px">
        <option value="direct" ${rule.outboundTag === 'direct' ? 'selected' : ''}>direct — напрямую</option>
        <option value="proxy" ${rule.outboundTag === 'proxy' ? 'selected' : ''}>proxy — через балансер</option>
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
let countrySearchValue = '';
let _blockedRaw = '';

async function loadCountries() {
  const data = await api('GET', '/api/countries');
  if (data.error) return;
  countryData = data.countries || [];
  _blockedRaw = data.blocked || '';
  const badge = $('countryVerifyBadge');
  if (badge && data.last_verify) {
    badge.textContent = `проверено ip-api · последняя проверка ${data.last_verify.slice(0, 10)}`;
  } else if (badge) {
    badge.textContent = countryData.length ? 'ожидание определения стран…' : '';
  }
  renderCountryFilter();
}

function renderCountryFilter() {
  const tb = $('countryFilterBody');
  if (!tb) return;
  tb.innerHTML = '';
  if (!countryData.length) {
    tb.innerHTML = '<tr><td colspan="4" class="empty">стран пока нет — импортируйте прокси</td></tr>';
    const cnt = $('countryFilterCount');
    if (cnt) cnt.textContent = '';
    return;
  }
  const blockedSet = new Set(_blockedRaw ? _blockedRaw.split(',').map(s => s.trim()).filter(Boolean) : []);
  const search = countrySearchValue.trim().toUpperCase();
  let selected = 0;
  let shown = 0;
  for (const c of countryData) {
    if (search && !c.code.includes(search)) continue;
    shown++;
    const blocked = blockedSet.has(c.code);
    if (blocked) selected++;
    const tr = document.createElement('tr');
    tr.style.cssText = 'border-bottom:1px solid var(--border)';
    const allVerified = c.verified === c.total;
    const verifiedLabel = allVerified ? 'ip-api' : (c.verified === 0 ? 'fragment' : 'mixed');
    tr.innerHTML = `
      <td style="padding:4px 10px;width:32px">
        <input type="checkbox" class="chk-custom" data-code="${c.code}" ${blocked ? 'checked' : ''}>
      </td>
      <td style="padding:4px 6px;font-weight:bold;color:var(--text-primary)">
        <span style="font-size:0.65rem;color:var(--text-muted);cursor:default" title="source: ${verifiedLabel} (${c.verified}/${c.total} verified)">[${verifiedLabel}]</span>
        ${c.code}
      </td>
      <td style="padding:4px 6px;color:var(--text-muted);font-size:0.72rem">
        ${c.working}/${c.total} работают
      </td>
      <td style="padding:4px 6px;color:var(--text-muted);font-size:0.7rem;text-align:right;white-space:nowrap">
        ${blocked ? '<span style="color:var(--red)">excluded</span>' : ''}
      </td>
    `;
    tr.querySelector('input[type="checkbox"]').addEventListener('change', markDirty);
    tb.appendChild(tr);
  }
  const cnt = $('countryFilterCount');
  if (cnt) cnt.textContent = `заблокировано: ${selected} из ${shown}`;
}

function selectAllCountries(blocked) {
  const boxes = document.querySelectorAll('#countryFilterBody input[type="checkbox"]');
  boxes.forEach(cb => { cb.checked = blocked; });
  markDirty();
}

function blockCountry(code) {
  const boxes = document.querySelectorAll('#countryFilterBody input[type="checkbox"]');
  boxes.forEach(cb => { cb.checked = cb.dataset.code === code || cb.checked; });
  markDirty();
}

function collectBlockedCountries() {
  const checked = [];
  document.querySelectorAll('#countryFilterBody input[type="checkbox"]:checked').forEach(cb => {
    checked.push(cb.dataset.code);
  });
  return checked.join(',');
}

{
  const searchInput = $('countryFilterSearch');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      countrySearchValue = this.value;
      renderCountryFilter();
    });
  }
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
  $('vlessPerProxyTimeout').value = s.vless_per_proxy_timeout || '3';
  $('logTrimEvery').value = s.log_trim_every || '500';
  $('logKeep').value = s.log_keep || '2000';
  $('observatoryProbeInterval').value = s.observatory_probe_interval || '10s';
  $('balancerStrategy').value = s.balancer_strategy || 'random';
  $('handshakeTimeout').value = s.handshake_timeout || '5';
  $('connIdle').value = s.conn_idle || '300';
  $('dbCheckAutoCleanup').checked = s.db_check_auto_cleanup === 'true';
  $('speedTestEnabled').checked = s.speed_test_enabled !== 'false';
  $('speedTestMax').value = s.speed_test_max || '15';
  $('speedTestUrl').value = s.speed_test_url || 'http://speedtest.selectel.ru/10MB';
  $('speedTestMinSec').value = s.speed_test_min_sec || '10';
  $('applyAfterTest').checked = s.apply_after_test !== 'false';
  $('minSpeedMbps').value = s.min_speed_mbps || '0';
  $('speedTestAdaptiveSec').value = s.speed_test_adaptive_sec || '2';
  $('safeOnlyImport').checked = s.safe_only_import === 'true';
  $('importProxy').value = s.import_proxy || '';
  $('sniffingEnabled').checked = s.sniffing_enabled !== 'false';
  $('sniffingRouteOnly').checked = s.sniffing_route_only !== 'false';
  const destOverride = (s.sniffing_dest_override || 'http,tls').split(',').map(x => x.trim());
  $('sniffHttp').checked = destOverride.includes('http');
  $('sniffTls').checked = destOverride.includes('tls');
  $('sniffQuic').checked = destOverride.includes('quic');
  $('sniffFtp').checked = destOverride.includes('ftp');
  $('geoEnabled').checked = s.geo_enabled !== 'false';
  $('maxWorkers').value = s.max_workers || '15';
  $('probeTimeout').value = s.probe_timeout || '3';
  $('xrayStartupRetries').value = s.xray_startup_retries || '15';
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
    el.textContent = `кандидатов: ${candidates} (API недоступен)`;
    el.style.color = 'var(--text-muted)';
    return;
  }
  el.textContent = `узлов в конфиге: ${active} · кандидатов: ${candidates}`;
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
  if (btn) { btn.disabled = true; btn.textContent = 'Пересобираем…'; }
  const r = await api('POST', '/api/xray/rebuild');
  if (r.error) { toast(r.error, 'error'); }
  else { toast('Конфиг пересобирается', 'success'); }
  if (btn) { btn.disabled = false; btn.textContent = 'Пересобрать'; }
  setTimeout(() => loadSettings(), 2000);
}

async function loadPerfEstimate() {
  // реальное число профилей берём из /api/status, расчёт ведём локально при изменении полей
  try {
    const st = await api('GET', '/api/status');
    if (st && st.total != null) _profileCount = st.total;
  } catch (_) {}
  updatePerfEstimate();
}

// ─── Validation ───
const FIELD_LABELS = {
  maxActiveProxies: 'Макс. активных прокси',
  maxWorkers: 'Кол-во воркеров',
  probeTimeout: 'Таймаут пробы',
  vlessPerProxyTimeout: 'Таймаут VLESS-теста',
  handshakeTimeout: 'Таймаут handshake',
  connIdle: 'Таймаут простоя',
  speedTestMax: 'Топ-N для speed test',
  speedTestMinSec: 'Мин. длительность замера',
  speedTestAdaptiveSec: 'Adaptive check',
  logTrimEvery: 'Чистка логов',
  logKeep: 'Хранение логов',
  xrayStartupRetries: 'Ожидание старта Xray',
  minSpeedMbps: 'Минимальная скорость',
};

function fieldLabel(id) {
  return FIELD_LABELS[id] || id;
}

function clearValidationUI() {
  const panel = $('validationPanel');
  if (panel) { panel.innerHTML = ''; panel.style.display = 'none'; }
  document.querySelectorAll('.input-invalid').forEach(el => el.classList.remove('input-invalid'));
}

function showValidationErrors(errors) {
  const panel = $('validationPanel');
  if (!panel) return;
  panel.innerHTML = '<div class="validation-errors">' +
    errors.map(e => '<div class="validation-item">• ' + e + '</div>').join('') +
    '</div>';
  panel.style.display = 'block';
  panel.scrollIntoView({ block: 'nearest' });
}

function markInvalid(id) {
  const el = $(id);
  if (el) el.classList.add('input-invalid');
}

function validateSettings() {
  const errors = [];
  const numFields = [
    { id: 'maxActiveProxies', min: 1, max: 500 },
    { id: 'maxWorkers', min: 1, max: 30 },
    { id: 'probeTimeout', min: 1, max: 15 },
    { id: 'vlessPerProxyTimeout', min: 2, max: 30 },
    { id: 'handshakeTimeout', min: 1, max: 30 },
    { id: 'connIdle', min: 30, max: 3600 },
    { id: 'speedTestMax', min: 1, max: 100 },
    { id: 'speedTestAdaptiveSec', min: 1, max: 10 },
    { id: 'speedTestMinSec', min: 1, max: 300 },
    { id: 'logTrimEvery', min: 10, max: 99999 },
    { id: 'logKeep', min: 100, max: 99999 },
    { id: 'xrayStartupRetries', min: 5, max: 50 },
    { id: 'minSpeedMbps', min: 0, max: 1000 },
  ];
  for (const f of numFields) {
    const el = $(f.id);
    if (!el) continue;
    const val = parseFloat(el.value);
    if (el.value.trim() === '') {
      errors.push(`${fieldLabel(f.id)}: не может быть пустым`);
      markInvalid(f.id);
      continue;
    }
    if (isNaN(val) || val < 0) {
      errors.push(`${fieldLabel(f.id)}: должно быть числом`);
      markInvalid(f.id);
      continue;
    }
    if (val < f.min || val > f.max) {
      errors.push(`${fieldLabel(f.id)}: допустимый диапазон ${f.min}–${f.max}`);
      markInvalid(f.id);
    }
  }
  const probeUrl = $('probeUrl').value.trim();
  if (probeUrl && !/^https?:\/\//i.test(probeUrl)) {
    errors.push('URL проверки: должен начинаться с http:// или https://');
    markInvalid('probeUrl');
  }
  const speedUrl = $('speedTestUrl').value.trim();
  if (speedUrl && !/^https?:\/\//i.test(speedUrl)) {
    errors.push('Файл замера: должен начинаться с http:// или https://');
    markInvalid('speedTestUrl');
  }
  const importProxy = $('importProxy').value.trim();
  if (importProxy && !/^(socks5|socks4|http|https):\/\//i.test(importProxy)) {
    errors.push('Прокси для импорта: ожидается формат socks5://… или http://…');
    markInvalid('importProxy');
  }
  const obsInterval = $('observatoryProbeInterval').value.trim();
  if (obsInterval && !/^\d+(s|ms|m|h)?$/i.test(obsInterval)) {
    errors.push('Интервал пинга: ожидается число с суффиксом, например 10s, 15, 1m');
    markInvalid('observatoryProbeInterval');
  }
  return errors;
}

async function saveSettings() {
  const errors = validateSettings();
  if (errors.length) {
    showValidationErrors(errors);
    toast('Проверьте настройки: ошибки валидации', 'error');
    return;
  }
  clearValidationUI();

  syncGeositeDomToArray();

  const btn = $('saveSettingsBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Сохранение…'; }
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
    vless_per_proxy_timeout: $('vlessPerProxyTimeout').value.trim() || '3',
    log_trim_every: $('logTrimEvery').value.trim() || '500',
    log_keep: $('logKeep').value.trim() || '2000',
    speed_test_enabled: $('speedTestEnabled').checked ? 'true' : 'false',
    speed_test_max: $('speedTestMax').value.trim() || '15',
    speed_test_url: $('speedTestUrl').value.trim() || 'http://speedtest.selectel.ru/10MB',
    speed_test_min_sec: $('speedTestMinSec').value.trim() || '10',
    db_check_auto_cleanup: $('dbCheckAutoCleanup').checked ? 'true' : 'false',
    apply_after_test: $('applyAfterTest').checked ? 'true' : 'false',
    min_speed_mbps: $('minSpeedMbps').value.trim() || '0',
    speed_test_adaptive_sec: $('speedTestAdaptiveSec').value.trim() || '2',
    observatory_probe_interval: $('observatoryProbeInterval').value.trim() || '10s',
    balancer_strategy: $('balancerStrategy').value,
    safe_only_import: $('safeOnlyImport').checked ? 'true' : 'false',
    import_proxy: $('importProxy').value.trim(),
    handshake_timeout: $('handshakeTimeout').value.trim() || '5',
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
    blocked_countries: collectBlockedCountries(),
    geosite_rules: JSON.stringify(geositeRules),
    // Performance
    max_workers: $('maxWorkers').value.trim() || '15',
    probe_timeout: $('probeTimeout').value.trim() || '3',
    xray_startup_retries: $('xrayStartupRetries').value.trim() || '15',
  };
  const r = await api('POST', '/api/settings', data);
  $('xrayBin').disabled = false;
  $('xrayConfigPath').disabled = false;
  $('proxyListen').disabled = false;
  if (btn) { btn.disabled = false; btn.textContent = 'Сохранить настройки'; }
  if (r.error) { toast(r.error, 'error'); return; }
  toast(r.restart_hint || 'Настройки сохранены', 'success');
  loadSettings();
  loadCountries();
}

function resetTuning() {
  setRangeValue(_rangeDb, 0.5);
  setRangeValue(_rangeImport, 3);
  $('vlessPerProxyTimeout').value = '3';
  $('observatoryProbeInterval').value = '10s';
  $('logTrimEvery').value = '500';
  $('logKeep').value = '2000';
  $('handshakeTimeout').value = '5';
  $('connIdle').value = '300';
  $('speedTestMax').value = '15';
  $('speedTestUrl').value = 'http://speedtest.selectel.ru/10MB';
  $('speedTestMinSec').value = '10';
  $('minSpeedMbps').value = '0';
  $('speedTestAdaptiveSec').value = '2';
  $('safeOnlyImport').checked = false;
  $('balancerStrategy').value = 'random';
  $('maxWorkers').value = '15';
  $('probeTimeout').value = '3';
  $('xrayStartupRetries').value = '15';
  markDirty();
  toast('Значения сброшены к заводским — нажмите «Сохранить настройки»');
}

async function restartXray() {
  toast('перезапускаем Xray…');
  const r = await api('POST', '/api/xray-restart');
  if (r && r.error) toast(r.error, 'error');
}

function resetProbeUrl() {
  $('probeUrl').value = 'https://www.gstatic.com/generate_204';
  markDirty();
  toast('URL проверки сброшен к значению по умолчанию');
}

// ─── Xray Daemon ───
function renderXrayStatus(s) {
  const el = $('xrayStatus');
  if (!el) return;
  const run = s.running ? '<span class="badge badge-green">работает</span>' : '<span class="badge badge-muted">остановлен</span>';
  const api_ok = s.api_accessible ? 'API ✓' : 'API ✗';
  const sd = s.systemd_active ? 'systemd ✓' : '';
  const active = s.active_outbounds && s.active_outbounds.length
    ? `узлы: ${s.active_outbounds.filter(t => t.startsWith('node')).join(', ')}` : '';
  el.innerHTML = `${run} &nbsp;${api_ok} &nbsp;${sd}<br><span style="color:var(--green);font-size:11px">${active}</span>`;
  const btnStart = $('btnXrayStart');
  const btnStop = $('btnXrayStop');
  if (btnStart) btnStart.style.display = s.running ? 'none' : '';
  if (btnStop) btnStop.style.display = s.running ? '' : 'none';
}

async function startXrayDaemon() {
  const r = await api('POST', '/api/xray/start');
  if (r.error) { toast(r.error, 'error'); return; }
  toast('Xray запущен', 'success');
  loadSettings();
}

async function stopXrayDaemon() {
  await api('POST', '/api/xray/stop');
  toast('Xray остановлен', 'success');
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
  toast('Резервная копия скачана', 'success');
}

function confirmImportBackup() {
  if (confirm('Импортировать резервную копию? Текущие настройки и источники будут перезаписаны.')) {
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
    toast(`Импортировано: настроек ${r.imported.settings}, источников ${r.imported.sources}`, 'success');
    loadSettings();
  } catch (e) {
    toast('Некорректный JSON-файл: ' + e.message, 'error');
  }
  event.target.value = '';
}

_rangeDb = setupRange('checkIntervalDb', 'checkIntervalDbLabel');
_rangeImport = setupRange('checkIntervalImport', 'checkIntervalImportLabel');
$('speedTestEnabled').addEventListener('change', updateSpeedTestDependants);

function updatePerfEstimate() {
  const estVal = $('perfEstValue');
  const estDetail = $('perfEstDetail');
  if (!estVal || !estDetail) return;
  const workers = Math.max(1, parseInt($('maxWorkers').value) || 1);
  const retries = Math.max(1, parseInt($('xrayStartupRetries').value) || 15);
  const vlessT = Math.max(2, parseInt($('vlessPerProxyTimeout').value) || 10);
  if (_profileCount <= 0) {
    estVal.textContent = '—';
    estDetail.textContent = 'загрузка данных…';
    return;
  }
  // На практике прогон упирается в таймаут VLESS-теста (прокси почти все отвечают
  // "не работают" и висят до таймаута), а не в отдельный probe-таймаут.
  const startup = retries * 0.05;
  const perProxy = startup + vlessT;
  const batches = Math.ceil(_profileCount / workers);
  const estSec = batches * perProxy;
  estVal.textContent = `~${(estSec / 60).toFixed(1)} мин`;
  estVal.title = 'оценка сверху: как будто все прокси отвечают до таймаута';
  estDetail.textContent = `${_profileCount} профилей · ${workers} воркеров · таймаут ${vlessT} с`;
}
$('maxWorkers').addEventListener('input', updatePerfEstimate);
$('vlessPerProxyTimeout').addEventListener('input', updatePerfEstimate);
$('probeTimeout').addEventListener('input', updatePerfEstimate);
$('xrayStartupRetries').addEventListener('input', updatePerfEstimate);

loadSettings();
loadCountries();
loadGeositeRules();
setInterval(() => {
  api('GET', '/api/xray/status').then(renderXrayStatus).catch(() => {});
}, 5000);
