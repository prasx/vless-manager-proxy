/* Общие клиентские утилиты.

   Подключается на каждой странице (templates/base.html) до скриптов страниц:
   единственные в проекте определения $, $$ и api() живут здесь. Скрипты
   страниц их не переопределяют — раньше в проекте было четыре разных $ и два
   api(), которые расходились в поведении и затирали друг друга в глобальной
   области видимости. */

/**
 * Возвращает элемент по id или по CSS-селектору.
 *
 * Строка, начинающаяся с «#», «.» или «[», трактуется как селектор, любая
 * другая — как id. Так один хелпер покрывает оба исторических стиля вызова
 * ($('tbodyDesktop') и $('#tbodyDesktop')) без правки сотни мест.
 *
 * @param {string|Element} sel id или CSS-селектор
 * @returns {Element|null}
 */
function $(sel) {
  if (typeof sel !== 'string') return sel || null;
  return /^[#.[]/.test(sel) ? document.querySelector(sel) : document.getElementById(sel);
}

/**
 * Все совпадения CSS-селектора как массив (а не NodeList).
 *
 * @param {string} sel CSS-селектор
 * @returns {Element[]}
 */
function $$(sel) {
  return Array.from(document.querySelectorAll(sel));
}

/**
 * Экранирует HTML-спецсимволы для вставки текста в разметку.
 *
 * @param {*} value значение (null/undefined → пустая строка)
 * @returns {string}
 */
function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Разбирает метку времени из API как UTC.
 * Бэкенд отдаёт naive-строку «2026-10-05 10:00:00» в UTC, поэтому без
 * суффикса 'Z' браузер истолковал бы её как локальное время и сдвинул
 * результат на часовой пояс.
 *
 * @param {string} t метка времени
 * @returns {Date|null}
 */
function utcDate(t) {
  if (!t) return null;
  const d = new Date(String(t).replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Форматирует UTC-метку из API в локальное время.
 *
 * @param {string} t метка времени
 * @returns {string}
 */
function fmtUtcTime(t) {
  const d = utcDate(t);
  return d ? d.toLocaleString() : (t ? String(t) : '');
}

/**
 * fetch + разбор JSON с единой обработкой ошибок: всегда возвращает объект,
 * при сетевой ошибке — {error}. Вызывающий код сам решает, как показать
 * ошибку (toast, баннер раздела, inline-сообщение).
 *
 * @param {string} method HTTP-метод
 * @param {string} url адрес
 * @param {*} [body] тело запроса (сериализуется в JSON)
 * @returns {Promise<object>}
 */
async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(url, opts);
    const data = await r.json();
    if (!r.ok && !data.error) data.error = `HTTP ${r.status}`;
    return data;
  } catch (e) {
    return { error: e.message };
  }
}
