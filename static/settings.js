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
  if (text) text.textContent = Object.values(_loadErrors).join('; ');
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
  const bar = $('settingsSaveBar');
  if (bar) bar.hidden = !_dirty;
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
let noCountry = 0;

// Названия стран не хранятся в БД: Intl.DisplayNames даёт их из кода без
// дополнительного источника. Если браузер не умеет — остаётся код.
let regionNames = null;
try { regionNames = new Intl.DisplayNames(['ru'], { type: 'region' }); } catch (e) { regionNames = null; }
function countryName(code) {
  if (!regionNames) return code;
  try { return regionNames.of(code) || code; } catch (e) { return code; }
}

async function loadCountries() {
  const seq = nextSeq('countries');
  const data = await api('GET', '/api/countries');
  if (isStale('countries', seq)) return;
  if (data.error) { setLoadError('countries', 'не удалось загрузить страны: ' + data.error); return; }
  setLoadError('countries', '');
  countryData = data.countries || [];
  noCountry = data.no_country || 0;
  blockedCodes = new Set((data.blocked || '').split(',').map(s => s.trim()).filter(Boolean));
  const badge = $('countryVerifyBadge');
  if (badge) {
    badge.textContent = data.last_verify
      ? `страны определены через ip-api, последняя проверка ${data.last_verify.slice(0, 10)}`
      : (countryData.length ? 'определение стран ещё не проходило, используются метки из ссылок' : '');
  }
  renderCountryFilter();
}

function renderCountryFilter() {
  const box = $('countryFilterBody');
  if (!box) return;
  box.innerHTML = '';
  if (!countryData.length) {
    box.innerHTML = '<p class="settings-muted-label">Стран пока нет: импортируйте прокси.</p>';
    updateCountryCount();
    return;
  }
  const search = countrySearch.trim().toLowerCase();
  const visible = countryData.filter(c => {
    if (!search) return true;
    return c.code.toLowerCase().includes(search)
      || countryName(c.code).toLowerCase().includes(search);
  });
  if (!visible.length) {
    box.innerHTML = '<p class="settings-muted-label">Ничего не найдено.</p>';
  } else {
    for (const c of visible) box.appendChild(countryChip(c));
  }
  updateCountryCount();
}

function countryChip(c) {
  const chip = document.createElement('label');
  chip.className = 'country-chip' + (blockedCodes.has(c.code) ? ' is-blocked' : '');

  const cb = document.createElement('input');
  cb.type = 'checkbox';
  cb.className = 'chk-custom';
  cb.dataset.code = c.code;
  cb.dataset.key = `country:${c.code}`;
  cb.checked = blockedCodes.has(c.code);
  cb.addEventListener('change', () => {
    if (cb.checked) blockedCodes.add(c.code); else blockedCodes.delete(c.code);
    chip.classList.toggle('is-blocked', cb.checked);
    updateCountryCount();
    recomputeDirty();
  });

  const code = document.createElement('span');
  code.className = 'cc-code';
  code.textContent = c.code;

  const name = document.createElement('span');
  name.className = 'cc-name';
  name.textContent = countryName(c.code);
  name.title = `${countryName(c.code)} (${c.code}), рабочих ${c.working} из ${c.total}`;

  const count = document.createElement('span');
  count.className = 'cc-count';
  count.textContent = `${c.working}/${c.total}`;

  chip.append(cb, code, name, count);
  return chip;
}

function updateCountryCount() {
  const cnt = $('countryFilterCount');
  if (!cnt) return;
  if (!countryData.length) { cnt.textContent = ''; return; }
  const inList = countryData.filter(c => blockedCodes.has(c.code)).length;
  const extra = blockedCodes.size - inList;
  let text = `исключено ${blockedCodes.size} из ${countryData.length}`;
  if (extra > 0) text += `, вне списка ${extra}`;
  if (noCountry > 0) text += `; без страны ${noCountry} профилей, они не фильтруются`;
  cnt.textContent = text;
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
  $('socksPort').value = s.socks_port || '1080';
  $('httpPort').value = s.http_port || '1081';
  $('apiPort').value = s.api_port || '10085';
  $('maxActiveProxies').value = s.max_active_proxies || '30';
  $('probeUrl').value = s.probe_url || 'http://cp.cloudflare.com/generate_204';
  $('probeUrlAuto').checked = s.probe_url_auto !== 'false';
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
  $('speedUseProfiles').checked = s.speed_use_profiles !== 'false';
  $('speedTestMax').value = s.speed_test_max || '15';
  $('speedTestUrl').value = s.speed_test_url || 'https://speed.cloudflare.com/__down?bytes=10000000';
  $('speedTestMinSec').value = s.speed_test_min_sec || '10';
  let directLast = {};
  try { directLast = JSON.parse(s.speed_direct_last || '{}'); } catch (e) { directLast = {}; }
  renderDirectSpeed(directLast);
  $('applyAfterTest').checked = s.apply_after_test !== 'false';
  $('minSpeedMbps').value = s.min_speed_mbps || '0';
  $('profileMaxAgeMin').value = s.profile_max_age_min || '0';
  $('requireSpeed').checked = s.require_speed === 'true';
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
  $('checkBatchSize').value = s.check_batch_size || '128';
  $('tcpPrefilterWorkers').value = s.tcp_prefilter_workers || '128';
  $('probeTimeout').value = s.probe_timeout || '8';
  $('probeRetries').value = s.probe_retries != null ? s.probe_retries : '1';
  $('xrayStartupRetries').value = s.xray_startup_retries || '15';
  $('tcpPrefilter').checked = s.tcp_prefilter !== 'false';
  $('tcpPrefilterTimeout').value = s.tcp_prefilter_timeout || '3';
  $('tcpPrefilterRetries').value = s.tcp_prefilter_retries != null ? s.tcp_prefilter_retries : '1';
  $('speedStageBudget').value = s.speed_stage_budget_sec || '1200';

  setLoadError('xray', status.error ? `не удалось получить статус Xray: ${status.error}` : '');
  if (!status.error) {
    renderXrayStatus(status);
  } else {
    const el = $('xrayStatus');
    if (el) el.innerHTML = '<span class="badge badge-red">нет связи с API</span>';
  }
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
  const working = status.config_working || 0;
  const measured = status.config_measured || 0;
  const fallback = status.config_fallback === 'unmeasured'
    ? ', fallback: без замера'
    : (status.config_fallback === 'stale'
      ? ', fallback: устаревшие'
      : (status.config_fallback === 'slow' ? ', fallback: ниже порога' : ''));
  if (!status.api_accessible) {
    el.textContent = `кандидатов: ${candidates} (рабочих ${working}, замерено ${measured}; API недоступен)${fallback}`;
    el.style.color = 'var(--text-muted)';
    return;
  }
  const live = status.nodes_live != null ? status.nodes_live : active;
  const setsState = status.config_on_disk_newer
    ? ' · конфиг на диске новее Xray'
    : (status.nodes_mismatch ? ' · наборы не совпадают' : '');
  el.textContent = `узлов в конфиге: ${active} (живых ${live}), кандидатов: ${candidates} (рабочих ${working}, замерено ${measured})${fallback}${setsState}`;
  el.style.color = status.config_on_disk_newer
    ? 'var(--red)'
    : (status.nodes_mismatch || status.config_fallback ? 'var(--orange)' : 'var(--green)');
}

function updateSpeedTestDependants() {
  const enabled = $('speedTestEnabled').checked;
  const useProfiles = $('speedUseProfiles').checked;
  const body = $('speedTestBody');
  if (!body) return;
  body.querySelectorAll('input').forEach(inp => {
    if (inp.id !== 'speedTestEnabled') inp.disabled = !enabled;
  });
  $('speedTestMax').disabled = !enabled || !useProfiles;
  $('speedTestAdaptiveSec').disabled = !enabled || !useProfiles;
  const directBtn = $('speedDirectBtn');
  if (directBtn) directBtn.disabled = !enabled;
  body.style.opacity = enabled ? '1' : '0.45';
}

// ─── Валидация ───
const FIELD_LABELS = {
  maxActiveProxies: 'Макс. активных прокси',
  checkBatchSize: 'Профилей за раз',
  probeTimeout: 'Таймаут массовой проверки',
  probeRetries: 'Повторы пробы',
  tcpPrefilterTimeout: 'Таймаут TCP-префильтра',
  tcpPrefilterRetries: 'Повторы TCP-префильтра',
  tcpPrefilterWorkers: 'Параллельных TCP-проверок',
  socksPort: 'Порт SOCKS',
  httpPort: 'Порт HTTP',
  apiPort: 'Порт API Xray',
  vlessPerProxyTimeout: 'Таймаут ручного теста',
  handshakeTimeout: 'Таймаут рукопожатия',
  connIdle: 'Таймаут простоя',
  speedTestMax: 'Топ-N для теста скорости',
  speedTestMinSec: 'Длительность одного профиля',
  speedTestAdaptiveSec: 'Адаптивная проверка',
  speedStageBudget: 'Бюджет стадии скорости',
  logTrimEvery: 'Чистка логов',
  logKeep: 'Хранение логов',
  xrayStartupRetries: 'Ожидание старта Xray',
  minSpeedMbps: 'Минимальная скорость',
  profileMaxAgeMin: 'Свежесть профиля',
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
    { id: 'checkBatchSize', min: 4, max: 256 },
    { id: 'tcpPrefilterWorkers', min: 4, max: 512 },
    { id: 'probeTimeout', min: 1, max: 60 },
    { id: 'probeRetries', min: 0, max: 3 },
    { id: 'tcpPrefilterTimeout', min: 0.5, max: 10 },
    { id: 'tcpPrefilterRetries', min: 0, max: 3 },
    { id: 'socksPort', min: 1, max: 65535 },
    { id: 'httpPort', min: 1, max: 65535 },
    { id: 'apiPort', min: 1, max: 65535 },
    { id: 'vlessPerProxyTimeout', min: 2, max: 30 },
    { id: 'handshakeTimeout', min: 1, max: 30 },
    { id: 'connIdle', min: 30, max: 3600 },
    { id: 'speedTestMax', min: 1, max: 100 },
    { id: 'speedTestAdaptiveSec', min: 1, max: 10 },
    { id: 'speedTestMinSec', min: 1, max: 300 },
    { id: 'speedStageBudget', min: 0, max: 7200 },
    { id: 'logTrimEvery', min: 10, max: 99999 },
    { id: 'logKeep', min: 100, max: 99999 },
    { id: 'xrayStartupRetries', min: 5, max: 200 },
    { id: 'minSpeedMbps', min: 0, max: 1000 },
    { id: 'profileMaxAgeMin', min: 0, max: 10080 },
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
      errors.push(`${fieldLabel(f.id)}: допустимый диапазон ${f.min}-${f.max}`);
      markInvalid(f.id);
    }
  }
  // Порты SOCKS/HTTP/API должны различаться: иначе Xray не поднимется,
  // а панель будет стучаться в чужой порт.
  const portIds = ['socksPort', 'httpPort', 'apiPort'];
  const portVals = portIds.map(id => parseInt($(id).value, 10));
  if (portVals.every(v => v >= 1 && v <= 65535)) {
    const seen = new Map();
    portIds.forEach((id, i) => {
      const val = portVals[i];
      if (seen.has(val)) {
        errors.push(
          `Порты должны различаться: ${fieldLabel(seen.get(val))} и ${fieldLabel(id)} ` +
          `совпадают (${val})`
        );
        markInvalid(id);
      } else {
        seen.set(val, id);
      }
    });
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
    socks_port: $('socksPort').value.trim() || '1080',
    http_port: $('httpPort').value.trim() || '1081',
    api_port: $('apiPort').value.trim() || '10085',
    max_active_proxies: $('maxActiveProxies').value.trim() || '30',
    probe_url: $('probeUrl').value.trim() || 'http://cp.cloudflare.com/generate_204',
    probe_url_auto: $('probeUrlAuto').checked ? 'true' : 'false',
    check_interval_db: String(Math.round(parseFloat($('checkIntervalDb').value || '0.5') * 3600)),
    check_interval_import: String(Math.round(parseFloat($('checkIntervalImport').value || '3') * 3600)),
    vless_per_proxy_timeout: $('vlessPerProxyTimeout').value.trim() || '3',
    log_trim_every: $('logTrimEvery').value.trim() || '500',
    log_keep: $('logKeep').value.trim() || '2000',
    speed_test_enabled: $('speedTestEnabled').checked ? 'true' : 'false',
    speed_use_profiles: $('speedUseProfiles').checked ? 'true' : 'false',
    speed_test_max: $('speedTestMax').value.trim() || '15',
    speed_test_url: $('speedTestUrl').value.trim() || 'https://speed.cloudflare.com/__down?bytes=10000000',
    speed_test_min_sec: $('speedTestMinSec').value.trim() || '10',
    db_check_auto_cleanup: $('dbCheckAutoCleanup').checked ? 'true' : 'false',
    apply_after_test: $('applyAfterTest').checked ? 'true' : 'false',
    min_speed_mbps: $('minSpeedMbps').value.trim() || '0',
    profile_max_age_min: $('profileMaxAgeMin').value.trim() || '0',
    require_speed: $('requireSpeed').checked ? 'true' : 'false',
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
    check_batch_size: $('checkBatchSize').value.trim() || '128',
    probe_timeout: $('probeTimeout').value.trim() || '8',
    probe_retries: $('probeRetries').value.trim() || '1',
    xray_startup_retries: $('xrayStartupRetries').value.trim() || '15',
    tcp_prefilter: $('tcpPrefilter').checked ? 'true' : 'false',
    tcp_prefilter_timeout: $('tcpPrefilterTimeout').value.trim() || '3',
    tcp_prefilter_retries: $('tcpPrefilterRetries').value.trim() || '1',
    tcp_prefilter_workers: $('tcpPrefilterWorkers').value.trim() || '128',
    speed_stage_budget_sec: $('speedStageBudget').value.trim() || '1200',
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
// Пути Xray, адрес прослушивания, порты, URL проверки, прокси импорта, страны и
// правила GeoSite не сбрасываются: это привязка к окружению и содержимое,
// а не тюнинг. Список совпадает со значениями по умолчанию в app/db.py.
const RESET_NUMBERS = {
  maxActiveProxies: '30',
  minSpeedMbps: '0',
  vlessPerProxyTimeout: '3',
  observatoryProbeInterval: '10s',
  handshakeTimeout: '5',
  connIdle: '300',
  speedTestMax: '8',
  speedTestMinSec: '10',
  speedTestAdaptiveSec: '2',
  speedStageBudget: '1200',
  checkBatchSize: '128',
  tcpPrefilterWorkers: '128',
  tcpPrefilterTimeout: '3',
  tcpPrefilterRetries: '1',
  probeTimeout: '8',
  probeRetries: '1',
  xrayStartupRetries: '15',
  logTrimEvery: '500',
  logKeep: '2000',
};

const RESET_CHECKBOXES = {
  dbCheckAutoCleanup: false,
  speedTestEnabled: true,
  speedUseProfiles: true,
  applyAfterTest: true,
  safeOnlyImport: false,
  requireSpeed: false,
  probeUrlAuto: true,
  tcpPrefilter: true,
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
    'Затронуты: интервалы проверок, таймауты, пачка и воркеры проверки, тест ' +
    'скорости, балансировщик, сниффинг, чистка логов.\n' +
    'Пути Xray, адрес прослушивания, порты, URL проверки, прокси импорта, ' +
    'страны и правила GeoSite не меняются.')) return;

  for (const [id, value] of Object.entries(RESET_NUMBERS)) {
    const el = $(id);
    if (el) el.value = value;
  }
  for (const [id, value] of Object.entries(RESET_CHECKBOXES)) {
    const el = $(id);
    if (el) el.checked = value;
  }
  $('speedTestUrl').value = 'https://speed.cloudflare.com/__down?bytes=10000000';
  renderDirectSpeed({});
  $('balancerStrategy').value = 'random';
  setRangeValue(_rangeDb, 0.5);
  setRangeValue(_rangeImport, 3);

  updateSpeedTestDependants();
  updatePerfEstimate();
  recomputeDirty();
  toast('Значения сброшены к заводским, нажмите «Сохранить настройки»');
}

function resetProbeUrl() {
  $('probeUrl').value = 'http://cp.cloudflare.com/generate_204';
  recomputeDirty();
  toast('URL проверки сброшен к значению по умолчанию');
}

// ─── Тест URL проверки и файла замера ───
//
// «Тест лучших ссылок для остальных проверок»: прогоняем кандидатов напрямую
// из панели, лучшего применяем в настройки и пересобираем конфиг Xray. Если
// своя строка в поле не пуста, она тоже участвует в тесте.

function urlTestButtonBusy(btn, busy, label) {
  if (!btn) return;
  btn.disabled = busy;
  btn.textContent = busy ? 'Проверяем…' : (label || 'Тест URL');
}

function renderUrlTestResult(elId, report, kind) {
  const el = $(elId);
  if (!el) return;
  const rows = report.results || [];
  if (!rows.length) {
    el.hidden = false;
    el.innerHTML = '<div class="url-test-note warn">Кандидатов нет: проверьте поле URL или список кандидатов.</div>';
    return;
  }
  const body = rows.map(r => {
    const dead = !r.ok;
    const chosen = !dead && r.url === report.best;
    const meta = [];
    if (r.status) meta.push('HTTP ' + r.status);
    if (r.ms != null) meta.push(r.ms + ' мс');
    if (kind === 'speed' && r.kbps) meta.push(r.kbps + ' kbps');
    const cls = ['url-test-row', dead ? 'dead' : 'alive', chosen ? 'chosen' : '']
      .filter(Boolean).join(' ');
    const badge = chosen ? ' <span class="badge badge-green">выбран</span>' : '';
    const verdict = dead ? 'недоступен' : 'доступен';
    let html = `<div class="${cls}">` +
      `<span class="url-test-mark" aria-hidden="true">${dead ? '✕' : '✓'}</span>` +
      `<span class="sr-only">${verdict}</span>` +
      `<span class="url-test-url">${escapeHtml(r.url)}</span>` +
      `<span class="url-test-meta">${escapeHtml(meta.join(' · '))}${badge}</span>`;
    if (dead && r.error) {
      html += `<span class="url-test-err">${escapeHtml(String(r.error).slice(0, 180))}</span>`;
    }
    return html + '</div>';
  }).join('');

  let note = '';
  if (report.applied) {
    note = `<div class="url-test-note ok">Применено: ${escapeHtml(report.applied)}</div>`;
  } else if (report.best && report.best === report.current) {
    note = `<div class="url-test-note ok">Оставлен текущий URL: ${escapeHtml(report.current)}</div>`;
  } else if (report.best) {
    note = `<div class="url-test-note warn">Лучший: ${escapeHtml(report.best)} — нажмите «Сохранить настройки»</div>`;
  } else {
    note = '<div class="url-test-note dead">Живых кандидатов нет — проверьте сеть сервера</div>';
  }
  el.hidden = false;
  el.innerHTML = body + note;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function testProbeUrls(btn) {
  urlTestButtonBusy(btn, true);
  try {
    const typed = $('probeUrl').value.trim();
    const body = { kind: 'probe', apply: true, timeout: 8 };
    if (typed) body.urls = [typed];
    const r = await api('POST', '/api/urls/test', body);
    if (r.error) { toast(r.error, 'error'); return; }
    renderUrlTestResult('probeUrlTestResult', r, 'probe');
    if (r.applied) {
      $('probeUrl').value = r.applied;
      toast('URL проверки: выбран лучший из кандидатов', 'success');
      markClean();
      setTimeout(loadSettings, 1500);
    } else if (r.best && r.best === r.current) {
      toast('Текущий URL проверки отвечает — оставляем его', 'success');
    } else if (r.best) {
      $('probeUrl').value = r.best;
      toast('Живой URL найден, нажмите «Сохранить настройки»', 'success');
      recomputeDirty();
    } else {
      toast('Ни один кандидат не ответил — проверьте сеть сервера', 'error');
    }
  } finally {
    urlTestButtonBusy(btn, false);
  }
}

async function testSpeedUrls(btn) {
  urlTestButtonBusy(btn, true);
  try {
    const typed = $('speedTestUrl').value.trim();
    const body = { kind: 'speed', apply: true, timeout: 12 };
    if (typed) body.urls = [typed];
    const r = await api('POST', '/api/urls/test', body);
    if (r.error) { toast(r.error, 'error'); return; }
    renderUrlTestResult('speedUrlTestResult', r, 'speed');
    if (r.applied) {
      $('speedTestUrl').value = r.applied;
      toast('Файл замера: выбран лучший из кандидатов', 'success');
      markClean();
      setTimeout(loadSettings, 1500);
    } else if (r.best && r.best === r.current) {
      toast('Текущий файл замера отвечает — оставляем его', 'success');
    } else if (r.best) {
      $('speedTestUrl').value = r.best;
      toast('Живой файл замера найден, нажмите «Сохранить настройки»', 'success');
      recomputeDirty();
    } else {
      toast('Ни один файл замера не ответил — проверьте сеть сервера', 'error');
    }
  } finally {
    urlTestButtonBusy(btn, false, 'Тест URL');
  }
}

function fmtKbps(kbps) {
  const n = Number(kbps) || 0;
  return n >= 1000 ? `${(n / 1000).toFixed(1)} Mbps` : `${n} kbps`;
}

function renderDirectSpeed(res) {
  const el = $('speedDirectResult');
  if (!el) return;
  if (!res || !res.ok) {
    const err = res && res.error ? `: ${res.error}` : '';
    el.textContent = res && (res.ts || res.url) ? `ошибка${err}` : 'ещё не было';
    el.classList.toggle('text-bad', Boolean(res && res.error));
    return;
  }
  const when = res.ts ? new Date(res.ts * 1000).toLocaleTimeString() : '';
  el.innerHTML = `прямой: <b>${fmtKbps(res.avg_kbps)}</b> / макс ${fmtKbps(res.max_kbps)}`
    + ` · ${res.bytes || 0} байт за ${res.elapsed || 0} с`
    + (when ? ` · ${escapeHtml(when)}` : '');
  el.classList.remove('text-bad');
}

async function testDirectSpeed(btn) {
  urlTestButtonBusy(btn, true);
  btn.textContent = 'Замеряю…';
  try {
    const url = $('speedTestUrl').value.trim();
    const r = await api('POST', '/api/speedtest/direct', { url });
    if (r.error) {
      renderDirectSpeed({ ok: false, error: r.error });
      toast(r.error, 'error');
      return;
    }
    renderDirectSpeed(r);
    if (r.ok) {
      toast(`Прямой замер: ${fmtKbps(r.avg_kbps)} / макс ${fmtKbps(r.max_kbps)}`, 'success');
    } else {
      toast(`Прямой замер не удался: ${r.error || 'нет данных'}`, 'error');
    }
  } finally {
    urlTestButtonBusy(btn, false);
    btn.textContent = 'Замерить напрямую';
  }
}

// ─── Демон Xray ───

function renderXrayStatus(s) {
  const el = $('xrayStatus');
  if (!el) return;
  const run = s.running
    ? '<span class="badge badge-green">работает</span>'
    : '<span class="badge badge-red">остановлен</span>';
  const api = s.api_accessible
    ? '<span class="badge badge-green">API доступен</span>'
    : '<span class="badge badge-muted">API недоступен</span>';
  const sd = s.systemd_active ? '<span class="badge badge-muted">systemd активен</span>' : '';

  const desired = s.desired_nodes || [];
  const live = s.live_nodes || [];
  const disk = s.disk_nodes || [];
  const onlyDesired = s.desired_only || [];
  const onlyLive = s.live_only || [];
  const newer = Boolean(s.config_on_disk_newer);
  const mismatch = Boolean(s.nodes_mismatch);
  const liveKnown = Boolean(s.live_known);

  let setsBadge = '';
  if (newer) {
    setsBadge = `<span class="badge badge-red" title="${escapeHtml(s.apply_message || '')}">диск новее Xray: желаемых ${desired.length}, живых ${live.length}</span>`;
  } else if (mismatch) {
    setsBadge = `<span class="badge badge-orange">расхождение +${onlyDesired.length} / -${onlyLive.length}</span>`;
  } else if (liveKnown) {
    setsBadge = `<span class="badge badge-muted">желаемых ${desired.length}, живых ${live.length}</span>`;
  } else {
    setsBadge = '<span class="badge badge-muted">живой набор: нет счётчиков</span>';
  }
  const applyStatus = s.apply_status
    ? `<span class="badge ${newer || mismatch ? 'badge-orange' : 'badge-muted'}" title="${escapeHtml(s.apply_message || '')}">apply: ${escapeHtml(s.apply_status)}</span>`
    : '';
  el.innerHTML = `<span class="status-chips">${run}${api}${sd}${setsBadge}${applyStatus}</span>`;

  const sets = $('xraySets');
  if (sets) {
    const hasSets = desired.length || live.length || disk.length;
    sets.hidden = !hasSets;
    if (hasSets) {
      const tags = arr => arr.length ? arr.map(escapeHtml).join(', ') : '—';
      const diff = (onlyDesired.length || onlyLive.length)
        ? `<div class="daemon-set-row"><span>только в желаемых</span><span class="daemon-set-tags">${tags(onlyDesired)}</span></div>`
          + `<div class="daemon-set-row"><span>только в живых</span><span class="daemon-set-tags">${tags(onlyLive)}</span></div>`
        : '';
      sets.innerHTML = `<details ${newer || mismatch ? 'open' : ''}>
        <summary>Наборы outbound: желаемые ${desired.length}, живые ${live.length}, на диске ${disk.length}</summary>
        <div class="daemon-set-row"><span>желаемые</span><span class="daemon-set-tags">${tags(desired)}</span></div>
        <div class="daemon-set-row"><span>живые</span><span class="daemon-set-tags">${liveKnown ? tags(live) : 'неизвестны (statsquery пуст)'}</span></div>
        <div class="daemon-set-row"><span>на диске</span><span class="daemon-set-tags">${tags(disk)}</span></div>
        ${diff}
      </details>`;
    }
  }

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
  const batch = Math.max(1, parseInt($('checkBatchSize').value) || 128);
  const workers = Math.max(1, parseInt($('tcpPrefilterWorkers').value) || 128);
  const probeT = Math.max(1, parseInt($('probeTimeout').value) || 8);
  const probeR = Math.max(0, parseInt($('probeRetries').value) || 0);
  const prefilter = $('tcpPrefilter').checked;
  const tcpT = Math.max(0.5, parseFloat($('tcpPrefilterTimeout').value) || 3);
  const tcpR = Math.max(0, parseInt($('tcpPrefilterRetries').value) || 0);
  if (_profileCount <= 0) {
    estVal.textContent = '…';
    estDetail.textContent = 'загрузка данных…';
    return;
  }
  // Худший случай: каждая попытка выжидает таймаут, повторы идут с шагом ×1.5.
  // Префильтр работает своим пулом сокетов, проверка — волнами по batch.
  const tcpWorst = prefilter ? tcpT * (1 + 0.5 * tcpR) : 0;
  const probeWorst = probeT * (1 + 0.5 * probeR);
  const prefilterWaves = Math.ceil(_profileCount / workers);
  const probeWaves = Math.ceil(_profileCount / batch);
  const estSec = prefilterWaves * tcpWorst + probeWaves * probeWorst;
  estVal.textContent = `~${(estSec / 60).toFixed(1)} мин`;
  estVal.title = 'оценка сверху: все профили отвечают только по таймауту, с учётом повторов';
  estDetail.textContent = `${_profileCount} профилей: префильтр ${prefilterWaves} волн × ${workers}, ` +
    `проверка ${probeWaves} волн × ${batch}; таймауты ${probeT}с (+${probeR}) и ${tcpT}с (+${tcpR})`;
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

// ─── Инициализация ───
_rangeDb = setupRange('checkIntervalDb', 'checkIntervalDbLabel');
_rangeImport = setupRange('checkIntervalImport', 'checkIntervalImportLabel');
$('speedTestEnabled').addEventListener('change', updateSpeedTestDependants);
$('speedUseProfiles').addEventListener('change', updateSpeedTestDependants);
['checkBatchSize', 'tcpPrefilterWorkers', 'probeTimeout', 'probeRetries',
 'tcpPrefilterTimeout', 'tcpPrefilterRetries'].forEach(id => {
  const el = $(id);
  if (el) el.addEventListener('input', updatePerfEstimate);
});
$('tcpPrefilter').addEventListener('change', updatePerfEstimate);

refreshAll();
setInterval(() => {
  api('GET', '/api/xray/status').then(s => { if (!s.error) renderXrayStatus(s); });
}, 5000);
