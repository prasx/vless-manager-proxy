/* Страница настроек: загрузка, валидация, сохранение, сброс.

   $ и api() приходят из api.js (подключается до этого файла в base.html). */

// ─── Ошибки загрузки ───
const _loadErrors = {};

// Номер последнего запроса по каждому источнику. Долгий запрос может завершиться
// после более нового, и тогда устаревший ответ затирал актуальное состояние, в том
// числе снимал баннер ошибки, который поставил свежий запрос.
const _loadSeq = {};

function nextSeq(source) {
  _loadSeq[source] = (_loadSeq[source] || 0) + 1;
  return _loadSeq[source];
}

function isStale(source, seq) {
  return _loadSeq[source] !== seq;
}

function setLoadError(source, msg) {
  if (msg) _loadErrors[source] = msg; else delete _loadErrors[source];
  const box = $('settingsError');
  if (!box) return;
  const text = $('settingsErrorText');
  if (text) text.textContent = Object.values(_loadErrors).join(' · ');
  box.hidden = Object.keys(_loadErrors).length === 0;
}

function fmtHours(v) {
  const h = Math.floor(v);
  const m = Math.round((v - h) * 60);
  return m ? `${h}h ${m}m` : `${h}h`;
}

// ─── Диапазоны-слайдеры ───
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
  if (!range || isNaN(val)) return;
  range.el.value = val;
  range.update();
}

// ─── Отметка несохранённых изменений ───
//
// Источник истины — снимок всех полей настроек. Изменение сравнивается со
// снимком целиком, поэтому возврат поля к исходному значению снимает отметку,
// а динамически отрисованные элементы (страны, правила GeoSite) учитываются
// через data-key — у них нет id.
let _dirty = false;
let _initialSnapshot = null;
let _profileCount = 0;

function fieldKey(el) {
  return el.id || el.dataset.key || el.name || '';
}

/** Поля-фильтры (поиск, выбор файла) не настройки: они не считаются изменениями. */
function isTrackedField(el) {
  return el.dataset.nodirty === undefined && el.type !== 'file';
}

function takeSnapshot() {
  const snap = {};
  $$('.settings-section input, .settings-section select, .settings-section textarea').forEach(el => {
    const key = fieldKey(el);
    if (!key || !isTrackedField(el)) return;
    snap[key] = el.type === 'checkbox' || el.type === 'radio' ? el.checked : el.value;
  });
  return snap;
}

function recomputeDirty() {
  if (!_initialSnapshot) return;
  const cur = takeSnapshot();
  const keys = new Set([...Object.keys(_initialSnapshot), ...Object.keys(cur)]);
  let dirty = false;
  for (const k of keys) {
    if (_initialSnapshot[k] !== cur[k]) { dirty = true; break; }
  }
  if (dirty === _dirty) return;
  _dirty = dirty;
  updateDirtyUI();
}

function markClean() {
  _dirty = false;
  _initialSnapshot = takeSnapshot();
  updateDirtyUI();
}

function updateDirtyUI() {
  const el = $('dirtyIndicator');
  if (!el) return;
  el.textContent = _dirty ? 'есть несохранённые изменения' : '';
  el.className = _dirty ? 'settings-dirty-indicator dirty' : 'settings-dirty-indicator';
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

// Делегирование: слушатели живут на документе, поэтому поля, отрисованные позже
// (страны, правила GeoSite), отслеживаются без повторной подписки.
document.addEventListener('input', onFieldChanged);
document.addEventListener('change', onFieldChanged);

function onFieldChanged(e) {
  const el = e.target;
  if (!el || typeof el.closest !== 'function') return;
  if (!el.closest('.settings-section')) return;
  clearInputError(el);
  recomputeDirty();
}

window.addEventListener('beforeunload', e => {
  if (isDirty()) {
    e.preventDefault();
    e.returnValue = '';
  }
});

// ─── Правила GeoSite ───
let geositeRules = [];

async function loadGeositeRules() {
  const seq = nextSeq('geosite');
  const r = await api('GET', '/api/geosite-rules');
  if (isStale('geosite', seq)) return;
  if (r.error) { setLoadError('geosite', 'не удалось загрузить правила GeoSite: ' + r.error); return; }
  setLoadError('geosite', '');
  geositeRules = r.rules || [];
  renderGeositeRules();
}

function renderGeositeRules() {
  const wrap = $('geositeRulesWrap');
  if (!wrap) return;
  wrap.innerHTML = '';
  if (!geositeRules.length) {
    const empty = document.createElement('div');
    empty.className = 'tuning-item geosite-empty';
    empty.textContent = 'правил нет: весь трафик идёт через балансер';
    wrap.appendChild(empty);
    return;
  }
  geositeRules.forEach((rule, i) => {
    const item = document.createElement('div');
    item.className = 'tuning-item';

    const domain = document.createElement('input');
    domain.type = 'text';
    domain.className = 'input geosite-domain';
    domain.value = rule.domain || '';
    domain.placeholder = 'geosite:google';
    domain.spellcheck = false;
    domain.dataset.key = `geosite:${i}:domain`;

    const outbound = document.createElement('select');
    outbound.className = 'input geosite-outbound';
    outbound.dataset.key = `geosite:${i}:outbound`;
    for (const [value, label] of [['direct', 'direct: напрямую'], ['proxy', 'proxy: через балансер']]) {
      const opt = document.createElement('option');
      opt.value = value;
      opt.textContent = label;
      if (rule.outboundTag === value) opt.selected = true;
      outbound.appendChild(opt);
    }

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'btn btn-danger btn-sm geosite-remove';
    remove.textContent = '✕';
    remove.title = 'Удалить правило';
    remove.setAttribute('aria-label', 'Удалить правило');
    remove.addEventListener('click', () => removeGeositeRule(i));

    item.append(domain, outbound, remove);
    wrap.appendChild(item);
  });
}

function addGeositeRule() {
  syncGeositeDomToArray();
  geositeRules.push({ domain: 'geosite:google', outboundTag: 'direct' });
  renderGeositeRules();
  recomputeDirty();
}

function syncGeositeDomToArray() {
  const items = $$('#geositeRulesWrap .tuning-item');
  const rules = [];
  items.forEach(item => {
    const domain = item.querySelector('.geosite-domain');
    const outbound = item.querySelector('.geosite-outbound');
    if (domain && outbound && domain.value.trim()) {
      rules.push({ domain: domain.value.trim(), outboundTag: outbound.value });
    }
  });
  geositeRules = rules;
}

function removeGeositeRule(idx) {
  syncGeositeDomToArray();
  geositeRules.splice(idx, 1);
  renderGeositeRules();
  recomputeDirty();
}

// ─── Фильтр стран ───
//
// blockedCodes — источник истины. Поиск только фильтрует отрисовку, поэтому
// сохранение берёт все отметки, а не только попавшие в найденное подмножество
// (раньше поиск + сохранение молча снимали блокировку с остальных стран).
let countryData = [];
let blockedCodes = new Set();
let countrySearch = '';

async function loadCountries() {
  const seq = nextSeq('countries');
  const data = await api('GET', '/api/countries');
  if (isStale('countries', seq)) return;
  if (data.error) { setLoadError('countries', 'не удалось загрузить страны: ' + data.error); return; }
  setLoadError('countries', '');
  countryData = data.countries || [];
  blockedCodes = new Set((data.blocked || '').split(',').map(s => s.trim()).filter(Boolean));
  const badge = $('countryVerifyBadge');
  if (badge) {
    badge.textContent = data.last_verify
      ? `проверено ip-api · последняя проверка ${data.last_verify.slice(0, 10)}`
      : (countryData.length ? 'ожидание определения стран…' : '');
  }
  renderCountryFilter();
}

function renderCountryFilter() {
  const tb = $('countryFilterBody');
  if (!tb) return;
  tb.innerHTML = '';
  if (!countryData.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'empty';
    td.textContent = 'стран пока нет: импортируйте прокси';
    tr.appendChild(td);
    tb.appendChild(tr);
    updateCountryCount();
    return;
  }
  const search = countrySearch.trim().toUpperCase();
  for (const c of countryData) {
    if (search && !c.code.includes(search)) continue;
    tb.appendChild(countryRow(c));
  }
  updateCountryCount();
}

function countryRow(c) {
  const tr = document.createElement('tr');
  tr.className = 'country-row';

  const tdChk = document.createElement('td');
  tdChk.className = 'country-cell-chk';
  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.className = 'chk-custom';
  cb.dataset.code = c.code;
  cb.dataset.key = `country:${c.code}`;
  cb.checked = blockedCodes.has(c.code);
  cb.addEventListener('change', () => {
    if (cb.checked) blockedCodes.add(c.code); else blockedCodes.delete(c.code);
    markCell(tr, cb.checked);
    updateCountryCount();
    recomputeDirty();
  });
  tdChk.appendChild(cb);

  const tdCode = document.createElement('td');
  tdCode.className = 'country-cell-code';
  const src = document.createElement('span');
  src.className = 'country-source';
  const verifiedLabel = c.verified === c.total ? 'ip-api' : (c.verified === 0 ? 'fragment' : 'mixed');
  src.textContent = `[${verifiedLabel}]`;
  src.title = `source: ${verifiedLabel} (${c.verified}/${c.total} verified)`;
  tdCode.append(src, document.createTextNode(' ' + c.code));

  const tdStat = document.createElement('td');
  tdStat.className = 'country-cell-stat';
  tdStat.textContent = `${c.working}/${c.total} работают`;

  const tdMark = document.createElement('td');
  tdMark.className = 'country-cell-mark';
  markCell(tr, cb.checked, tdMark);

  tr.append(tdChk, tdCode, tdStat, tdMark);
  return tr;
}

function markCell(tr, blocked, cell) {
  const td = cell || tr.querySelector('.country-cell-mark');
  if (!td) return;
  td.textContent = blocked ? 'excluded' : '';
}

function updateCountryCount() {
  const cnt = $('countryFilterCount');
  if (!cnt) return;
  if (!countryData.length) { cnt.textContent = ''; return; }
  const inList = countryData.filter(c => blockedCodes.has(c.code)).length;
  const extra = blockedCodes.size - inList;
  cnt.textContent = `исключено ${blockedCodes.size} из ${countryData.length}`
    + (extra > 0 ? ` · вне списка: ${extra}` : '');
}

function selectAllCountries(blocked) {
  if (!countryData.length) return;
  const msg = blocked
    ? `Исключить все страны (${countryData.length}) из конфига и подписки?`
    : 'Снять отметки со всех стран? После сохранения ни одна страна не будет исключена из конфига и подписки.';
  if (!confirm(msg)) return;
  for (const c of countryData) {
    if (blocked) blockedCodes.add(c.code); else blockedCodes.delete(c.code);
  }
  renderCountryFilter();
  recomputeDirty();
}

function blockCountry(code) {
  blockedCodes.add(code);
  renderCountryFilter();
  recomputeDirty();
}

function collectBlockedCountries() {
  return [...blockedCodes].sort().join(',');
}

{
  const searchInput = $('countryFilterSearch');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      countrySearch = this.value;
      renderCountryFilter();
    });
  }
}

// ─── Загрузка ───

async function loadSettings() {
  const seq = nextSeq('settings');
  const [s, status] = await Promise.all([
    api('GET', '/api/settings'),
    api('GET', '/api/xray/status'),
  ]);
  if (isStale('settings', seq)) return;
  if (s.error) { setLoadError('settings', 'не удалось загрузить настройки: ' + s.error); return; }
  setLoadError('settings', '');

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

  setLoadError('xray', status.error ? `не удалось получить статус Xray: ${status.error}` : '');
  if (!status.error) renderXrayStatus(status);
  updateConfigStatus(status);
  updateSpeedTestDependants();
  loadPerfEstimate();
}

/** Полная синхронизация страницы с сервером: после неё снимок «чистый». */
async function refreshAll() {
  await Promise.all([loadSettings(), loadCountries(), loadGeositeRules()]);
  markClean();
}

function updateConfigStatus(status) {
  const el = $('configStatus');
  if (!el) return;
  if (status.error) { el.textContent = '…'; return; }
  const active = status.nodes_in_config || 0;
  const candidates = status.config_candidates || 0;
  if (!status.api_accessible) {
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
  body.querySelectorAll('input').forEach(inp => {
    if (inp.id !== 'speedTestEnabled') inp.disabled = !enabled;
  });
  body.style.opacity = enabled ? '1' : '0.45';
}

// ─── Валидация ───
const FIELD_LABELS = {
  maxActiveProxies: 'Макс. активных прокси',
  maxWorkers: 'Кол-во воркеров',
  probeTimeout: 'Таймаут пробы',
  vlessPerProxyTimeout: 'Таймаут одной пробы',
  handshakeTimeout: 'Таймаут рукопожатия',
  connIdle: 'Таймаут простоя',
  speedTestMax: 'Топ-N для теста скорости',
  speedTestMinSec: 'Длительность одного профиля',
  speedTestAdaptiveSec: 'Адаптивная проверка',
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
  $$('.input-invalid').forEach(el => el.classList.remove('input-invalid'));
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
    if (el.value.trim() === '') {
      errors.push(`${fieldLabel(f.id)}: не может быть пустым`);
      markInvalid(f.id);
      continue;
    }
    const val = parseFloat(el.value);
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
  const requiredFields = [
    { id: 'xrayBin', msg: 'Путь к бинарнику Xray не может быть пустым' },
    { id: 'xrayConfigPath', msg: 'Путь к файлу конфига не может быть пустым' },
    { id: 'proxyListen', msg: 'Адрес прослушивания не может быть пустым' },
  ];
  for (const f of requiredFields) {
    const el = $(f.id);
    if (el && !el.value.trim()) {
      errors.push(f.msg);
      markInvalid(f.id);
    }
  }
  const urlFields = [
    { id: 'probeUrl', label: 'URL проверки' },
    { id: 'speedTestUrl', label: 'Файл замера' },
  ];
  for (const f of urlFields) {
    const value = $(f.id).value.trim();
    if (value && !/^https?:\/\//i.test(value)) {
      errors.push(`${f.label}: должен начинаться с http:// или https://`);
      markInvalid(f.id);
    }
  }
  const importProxy = $('importProxy').value.trim();
  if (importProxy && !/^(socks5|socks4|http|https):\/\//i.test(importProxy)) {
    errors.push('Прокси для импорта: ожидается формат socks5://… или http://…');
    markInvalid('importProxy');
  }
  const obsInterval = $('observatoryProbeInterval').value.trim();
  // Xray принимает Go-duration: целое или дробное число с суффиксом s/ms/m/h.
  if (obsInterval && !/^\d+(\.\d+)?(s|ms|m|h)?$/i.test(obsInterval)) {
    errors.push('Интервал пинга: ожидается число с суффиксом, например 10s, 15, 1.5s, 1m');
    markInvalid('observatoryProbeInterval');
  }
  return errors;
}

// ─── Сохранение ───

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

  let r;
  try {
    r = await api('POST', '/api/settings', data);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Сохранить настройки'; }
  }
  if (r.error) { toast(r.error, 'error'); return; }
  toast(r.restart_hint || 'Настройки сохранены', 'success');
  await refreshAll();
}

// ─── Сброс тюнинга к заводским значениям ───
//
// Пути Xray, адрес прослушивания, URL проверки, прокси импорта, страны и
// правила GeoSite не сбрасываются: это привязка к окружению и содержимое,
// а не тюнинг. Список совпадает со значениями по умолчанию в app/db.py.
const RESET_NUMBERS = {
  maxActiveProxies: '30',
  minSpeedMbps: '0',
  vlessPerProxyTimeout: '3',
  observatoryProbeInterval: '10s',
  handshakeTimeout: '5',
  connIdle: '300',
  speedTestMax: '15',
  speedTestMinSec: '10',
  speedTestAdaptiveSec: '2',
  maxWorkers: '15',
  probeTimeout: '3',
  xrayStartupRetries: '15',
  logTrimEvery: '500',
  logKeep: '2000',
};

const RESET_CHECKBOXES = {
  dbCheckAutoCleanup: false,
  speedTestEnabled: true,
  applyAfterTest: true,
  safeOnlyImport: false,
  sniffingEnabled: true,
  sniffingRouteOnly: true,
  sniffHttp: true,
  sniffTls: true,
  sniffQuic: false,
  sniffFtp: false,
};

function resetSettings() {
  if (!confirm(
    'Вернуть тюнинг-параметры к значениям по умолчанию?\n\n' +
    'Затронуты: интервалы проверок, таймауты, воркеры, тест скорости, ' +
    'балансировщик, сниффинг, чистка логов.\n' +
    'Пути Xray, адрес прослушивания, URL проверки, прокси импорта, страны и ' +
    'правила GeoSite не меняются.')) return;

  for (const [id, value] of Object.entries(RESET_NUMBERS)) {
    const el = $(id);
    if (el) el.value = value;
  }
  for (const [id, value] of Object.entries(RESET_CHECKBOXES)) {
    const el = $(id);
    if (el) el.checked = value;
  }
  $('speedTestUrl').value = 'http://speedtest.selectel.ru/10MB';
  $('balancerStrategy').value = 'random';
  setRangeValue(_rangeDb, 0.5);
  setRangeValue(_rangeImport, 3);

  updateSpeedTestDependants();
  updatePerfEstimate();
  recomputeDirty();
  toast('Значения сброшены к заводским, нажмите «Сохранить настройки»');
}

function resetProbeUrl() {
  $('probeUrl').value = 'https://www.gstatic.com/generate_204';
  recomputeDirty();
  toast('URL проверки сброшен к значению по умолчанию');
}

// ─── Демон Xray ───

function renderXrayStatus(s) {
  const el = $('xrayStatus');
  if (!el) return;
  const run = s.running ? '<span class="badge badge-green">работает</span>' : '<span class="badge badge-muted">остановлен</span>';
  const apiOk = s.api_accessible ? 'API ✓' : 'API ✗';
  const sd = s.systemd_active ? 'systemd ✓' : '';
  const nodes = s.active_outbounds && s.active_outbounds.length
    ? `узлы: ${s.active_outbounds.filter(t => t.startsWith('node')).join(', ')}` : '';
  el.innerHTML = `${run} &nbsp;${apiOk} &nbsp;${sd}<br><span class="xray-nodes">${nodes}</span>`;
  const btnStart = $('btnXrayStart');
  const btnStop = $('btnXrayStop');
  if (btnStart) btnStart.style.display = s.running ? 'none' : '';
  if (btnStop) btnStop.style.display = s.running ? '' : 'none';
}

async function startXrayDaemon() {
  if (!confirm('Запустить Xray?')) return;
  const r = await api('POST', '/api/xray/start');
  if (r.error) { toast(r.error, 'error'); return; }
  toast('Xray запущен', 'success');
  loadSettings();
}

async function stopXrayDaemon() {
  if (!confirm('Остановить Xray? Прокси перестанет работать.')) return;
  const r = await api('POST', '/api/xray/stop');
  if (r.error) { toast(r.error, 'error'); return; }
  toast('Xray остановлен', 'success');
  loadSettings();
}

async function restartXray() {
  if (!confirm('Перезапустить Xray?')) return;
  toast('перезапускаем Xray…');
  const r = await api('POST', '/api/xray-restart');
  if (r.error) toast(r.error, 'error');
}

async function rebuildConfig() {
  if (!confirm('Пересобрать конфиг сейчас?')) return;
  const btn = $('rebuildConfigBtn');
  const label = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = 'Пересобираем…'; }
  try {
    const r = await api('POST', '/api/xray/rebuild');
    if (r.error) toast(r.error, 'error');
    else toast('Конфиг пересобирается', 'success');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = label; }
  }
  setTimeout(loadSettings, 2000);
}

// ─── Оценка длительности прогона ───

async function loadPerfEstimate() {
  // реальное число профилей берём из /api/status, расчёт ведём локально при изменении полей
  const st = await api('GET', '/api/status');
  if (st && st.total != null) _profileCount = st.total;
  updatePerfEstimate();
}

function updatePerfEstimate() {
  const estVal = $('perfEstValue');
  const estDetail = $('perfEstDetail');
  if (!estVal || !estDetail) return;
  const workers = Math.max(1, parseInt($('maxWorkers').value) || 1);
  const retries = Math.max(1, parseInt($('xrayStartupRetries').value) || 15);
  const vlessT = Math.max(2, parseInt($('vlessPerProxyTimeout').value) || 10);
  if (_profileCount <= 0) {
    estVal.textContent = '…';
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

// ─── Резервная копия ───

async function exportBackup() {
  const r = await api('GET', '/api/backup');
  if (r.error) { toast(r.error, 'error'); return; }
  const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vless-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('Резервная копия скачана', 'success');
}

function confirmImportBackup() {
  if (confirm('Импортировать резервную копию? Текущие настройки и источники будут перезаписаны.')) {
    $('backupFile').click();
  }
}

async function importBackup(event) {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    const r = await api('POST', '/api/backup/import', data);
    if (r.error) { toast(r.error, 'error'); return; }
    toast(`Импортировано: настроек ${r.imported.settings}, источников ${r.imported.sources}`, 'success');
    await refreshAll();
  } catch (e) {
    toast('Некорректный JSON-файл: ' + e.message, 'error');
  }
  event.target.value = '';
}

// ─── Подсветка активного раздела в залипающем меню ───
function initSettingsNav() {
  const nav = $('settingsNav');
  if (!nav) return;
  const links = $$('#settingsNav a[href^="#"]');
  const targets = links
    .map(a => document.querySelector(a.getAttribute('href')))
    .filter(Boolean);
  if (!targets.length) return;
  const OFFSET = 88;

  function update() {
    const pos = window.scrollY + OFFSET;
    let current = targets[0].id;
    for (const section of targets) {
      if (section.getBoundingClientRect().top + window.scrollY <= pos) current = section.id;
    }
    // Последний раздел может быть короче экрана — у самого низа страницы
    // подсвечиваем его, иначе он не подсвечивается никогда.
    const atBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
    if (atBottom) current = targets[targets.length - 1].id;
    links.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + current));
  }

  window.addEventListener('scroll', update, { passive: true });
  window.addEventListener('resize', update);
  update();
}

// ─── Инициализация ───
_rangeDb = setupRange('checkIntervalDb', 'checkIntervalDbLabel');
_rangeImport = setupRange('checkIntervalImport', 'checkIntervalImportLabel');
$('speedTestEnabled').addEventListener('change', updateSpeedTestDependants);
['maxWorkers', 'vlessPerProxyTimeout', 'xrayStartupRetries'].forEach(id => {
  $(id).addEventListener('input', updatePerfEstimate);
});

initSettingsNav();
refreshAll();
setInterval(() => {
  api('GET', '/api/xray/status').then(s => { if (!s.error) renderXrayStatus(s); });
}, 5000);
