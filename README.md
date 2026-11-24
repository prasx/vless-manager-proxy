<p align="center">
  <img src="docs/icon.png" width="88" height="88" alt="VLESS Manager">
</p>

<h1 align="center">VLESS Manager</h1>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Flask-3.1%2B-green" alt="Flask">
  <img src="https://img.shields.io/badge/Xray-26.3%2B-orange" alt="Xray">
</p>

> **v4.2.1** — таблицы: ячейки статуса и действий больше не ломают табличную раскладку, поэтому линии строк идут через всю ширину, а кнопки стоят в одних колонках. В 4.2.0: замер скорости с максимумом (Google 10MB), счётчики импорта, иконка репозитория и сокращённый README.

Самостоятельная панель для VLESS-прокси. Проверяет узлы реальным запуском Xray, замеряет скорость, собирает конфиг Xray и `subscribe.txt` по одному правилу и применяет его через Xray API. Без облака и внешнего биллинга: SQLite, Flask, один процесс.

![Дашборд VLESS Manager](docs/dashboard.png)

## Возможности

- **Один батч на пачку** — профили проверяются одним процессом Xray со своим inbound на каждый; мёртвые адреса отсекает TCP-префильтр. Пинг снимается сразу, скорость — только у прошедших.
- **Замер скорости** — файл `10MB` с Google, фиксированное окно и два числа: **средняя** и **максимальная** скорость за 0.5 с. В таблице видно пик, а не только размазанное среднее. URL и запасные файлы настраиваются.
- **Единая политика допуска** — конфиг и подписка собираются одним модулем `app/selection.py` и не могут разойтись.
- **Оценка источников** — 0–100, вердикты «основной», «мало рабочих», «все дубли», «нет ссылок» и рекомендация. Счётчики импорта показывают, сколько профилей новых, а сколько уже было в других источниках.
- **Актуализация** — перепроверяет только устаревшие и незамеренные профили, а не всю базу.
- **Наблюдаемость** — статусы Xray, логи, SSE-прогресс, уведомления, мобильные карточки и тёмная/светлая тема.

## Как выбираются профили

Профиль попадает в конфиг и подписку, если:

1. `status=working` и `latency_vless > 0`;
2. ссылка валидна (UUID, порт, транспорт, reality publicKey);
3. страна не в блок-листе;
4. последний успешный тест не старше `profile_max_age_min`;
5. при `min_speed_mbps > 0` скорость замерена и не ниже порога;
6. при включённом «Только замеренные» (`require_speed`) обязателен `speed_kbps > 0`.

Сначала идут замеренные (по средней скорости), затем незамеренные — по качеству источника и пингу. Лимит — `max_active_proxies`.

Если строгий отбор не дал никого, включается явный fallback: медленные-но-замеренные → незамеренные → устаревшие. В режиме «Только замеренные» откат на незамеренные отключён: пустой конфиг лучше непроверенного. Fallback пишется в лог и виден в UI.

**Почему профиль не в конфиге** — блок «Состав конфига и подписки» на странице «Источники» или `GET /api/config/preview`: там есть `selected` и `excluded` с причинами.

## Быстрый старт

Нужны Linux, Python 3.10+ и Xray. Полная установка с systemd — в [docs/INSTALL.md](docs/INSTALL.md).

```bash
git clone https://github.com/prasx/vless-manager-proxy.git
cd vless-manager-proxy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Открыть `http://<ip>:5000`. База `proxies.db` и кеш подписки создаются автоматически.

Для боевого запуска:

```bash
sudo cp vless-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xray vless-manager
```

Если импорт источников работает только через прокси, задайте `IMPORT_PROXY=socks5://127.0.0.1:1080` в окружении сервиса.

## Настройки

Основные параметры — в разделе «Настройки»:

| Ключ | По умолчанию | Что делает |
|------|--------------|------------|
| `xray_config_path` | `/etc/xray/config.json` | Куда панель пишет конфиг Xray |
| `max_active_proxies` | `30` | Сколько лучших попадает в конфиг и подписку |
| `min_speed_mbps` | `0` | Минимальная скорость; незамеренный порог не подтверждает |
| `require_speed` | `false` | Только замеренные, без fallback на незамеренные |
| `profile_max_age_min` | `0` (авто) | Свежесть успешного теста: 2 интервала проверки, 3 ч–сутки |
| `speed_test_url` | Google 10MB | Файл замера скорости |
| `safe_only_import` | `false` | Пропускать `security=none` при импорте |
| `blocked_countries` | пусто | Страны, исключённые из конфига и подписки |

Полный список и значения по умолчанию — в `app/db.py` (`SETTING_DEFAULTS`).

## API и устройство

- REST API: [docs/API.md](docs/API.md). Для подписки — `GET /api/subscribe.txt`, для проверки состава — `GET /api/config/preview`.
- Точка входа — `app.py`; создание Flask-приложения — `app/__init__.py`; БД и миграции — `app/db.py`.
- Проверка и замеры — `app/proxy_manager.py` и `app/checker.py`; политика отбора — `app/selection.py`; оценка источников — `app/source_quality.py`.
- Генерация конфига и Xray API — `app/xray_configurator.py`; импорт — `app/importer.py`; подписка — `app/subscribe.py`.
- Весь UI — `templates/` и `static/` (`style.css` — один файл токенов и компонентов).

## Тесты

Тесты не требуют Xray и сети: вместо процесса используется фейковый launcher, БД подменяется временным файлом.

```bash
python -m unittest discover -s tests -v
```

Покрыты батч-чекер, TCP-префильтр, backoff и due-выборка, политика допуска, подписка, качество источников и API-смоук.

## Лицензия

MIT. См. [LICENSE](LICENSE).
