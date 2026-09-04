# VLESS Manager Proxy

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![Xray](https://img.shields.io/badge/Xray-26.3+-orange)](https://github.com/XTLS/Xray-core)


<img width="1862" height="1098" alt="" src="https://github.com/user-attachments/assets/ddc23a63-8cab-4f81-88c4-ba2459040003" />


Веб-панель для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель проверяет каждый прокси через реальный запуск Xray по строгим этапам (**работоспособность → пинг → скорость**, по одному профилю на замер скорости), собирает конфиг с рабочими узлами и применяет через Xray API. **Observatory + Balancer** (random, leastLoad, leastPing) автоматически выбирают лучший узел.

## Особенности

- **Два фоновых таймера** — DB-only Check (только тест из БД) и Import+Check (импорт + enrich стран + тест). Import+Check имеет приоритет, не запускаются одновременно.
- **Строго поэтапный прогон** — Бизнес-логика импорта и замера разделена. Каждый прогон идёт по стадиям: **проверка работоспособности → замер пинга → замер скорости**. В UI видно, какая стадия идёт сейчас (степпер этапов).
- **Эксклюзивность замеров** — Никогда не выполняется больше одного прогона/замера одновременно (общая блокировка): ручной тест одного прокси, «Тест всех», фоновые цепочки сериализуются. Это исключает параллельные замеры скорости, которые дают недостоверные данные.
- **Стадия 1 — работоспособность** — Каждый прокси проверяется через временный Xray с HTTP-пробой (`generate_204`), параллельно до `max_workers` воркеров. Есть ответ — профиль помечается `working`, нет — `failed` с причиной.
- **Стадия 2 — пинг** — Для рабочих профилей отдельно меряется медиана из 3 проб через туннель (устойчивый пинг для ранжирования).
- **Стадия 3 — speed test** — Топ-N рабочих (по пингу) замеряют пропускную способность **строго по одному профилю за раз**, каждый ровно фиксированное окно из настроек (`speed_test_min_sec`, по умолчанию 10 с). Результат — primary сортировка в конфиге.
- **Импорт не запускает замер автоматически** — кнопки импорта только добавляют/обновляют профили; тест запускается отдельно («Тест всех» / «Перетест failed» / фоновая Import+Check).
- **Failover checker** — Фоновая проверка каждые 30 сек: если часть нод пропала из Xray, автоматически пересобирает конфиг.
- **Auto-delete failed** — Автоудаление нерабочих прокси после проверки (опционально).
- **Автоопределение страны** — Из фрагмента ссылки (`#RU`) или через ip-api.com.
- **GeoSite-роутинг** — Настраиваемые правила (`geosite:ru-blocked`, `geoip:telegram`, ...) с направлениями direct/proxy.
- **Sniffing** — Настройка определения протоколов (HTTP, TLS, QUIC, FTP) с режимом route-only.
- **Фильтр по странам** — Выбор заблокированных стран; конфиг и подписка собираются только из разрешённых.
- **Import proxy** — Прокси для загрузки подписок (SOCKS5/HTTP) для обхода DPI/блокировок. Автоматический fallback на curl при ошибке urllib.
- **ETag caching** — Пропуск неизменённых источников (HTTP 304) для ускорения повторных импортов.
- **Stale cleanup** — При повторном импорте из источника удаляются прокси, которых больше нет в свежей подписке.
- **TXT-источники** — Импорт vless:// ссылок напрямую из текста (без URL).
- **Subscription URL** — `/api/subscribe.txt` для внешних клиентов (v2rayNG, Streisand, Hiddify).
- **Тест с отменой** — Фоновый тест можно отменить через UI.
- **SSE streaming** — Real-time прогресс тестов через Server-Sent Events.
- **Массовые операции** — Чекбоксы, выбор всех, удалить/протестировать выбранные.
- **Понятные причины отказов** — Для каждого failed-прокси хранится причина (timeout, connection refused, TLS и т.д.) и время последнего теста; отображаются прямо в списке.
- **Фильтр по причине отказа** — На дашборде можно отфильтровать failed-прокси по причине (включая «без причины») и карточки failed/failed<24h.
- **Перетест failed** — Кнопка «Перетест failed» запускает полный поэтапный прогон только для нерабочих прокси (без перепроверки рабочих).
- **Backup** — Экспорт/импорт настроек и источников в JSON.
- **Traffic stats** — Активные outbound и узлы с трафиком (без графиков).
- **Connections monitor** — Модалка со списком активных TCP-соединений через прокси (кто, куда, сколько байт, закрытие по одному или всех).
- **Анализатор соединений** — Per-IP группировка трафика, conntrack для per-connection байтов.
- **Прогресс тестов** — Прогресс-бар в реальном времени.
- **Performance recommendations** — API с рекомендациями по тюнингу (воркеры, таймауты, время теста).

## Конфигурация

Базовые параметры в `config.py`:

| Параметр | Значение | Описание |
|----------|---------|----------|
| `SOCKS_PORT` | 1080 | SOCKS5 inbound |
| `HTTP_PORT` | 1081 | HTTP inbound |
| `API_PORT` | 10085 | gRPC API Xray |
| `API_LISTEN` | 127.0.0.1 | gRPC API listen address |
| `DATABASE` | `proxies.db` | SQLite |
| `SUBSCRIBE_FILE` | `subscribe.txt` | Кеш подписки |
| `PROBE_INTERVAL` | 10s | Интервал Observatory |

Настройки через UI (Settings):

### Xray

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| xray_bin | `/usr/local/bin/xray` | Путь к бинарнику Xray |
| xray_config_path | auto-detected | Путь к конфигу Xray |
| proxy_listen | `0.0.0.0` | Адрес для SOCKS/HTTP inbounds |

### Sniffing

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| sniffing_enabled | true | Включить sniffing |
| sniffing_dest_override | http,tls | Какие протоколы sniffить |
| sniffing_route_only | true | Не менять destination, только маршрутизация |

### Config & Filter

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| max_active_proxies | 30 | Макс. активных прокси в конфиге |
| probe_url | `https://www.gstatic.com/generate_204` | URL для проверки прокси |
| safe_only_import | false | Только TLS/Reality прокси |
| min_speed_mbps | 0 | Мин. скорость (Mbps, 0 = фильтр откл.) |

### Proxy Check

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| check_interval_db | 1800 сек (0.5 ч) | Интервал DB-only проверки |
| check_interval_import | 10800 сек (3 ч) | Интервал Import+Check |
| vless_per_proxy_timeout | 3 сек | Таймаут одной пробы (стадия проверки и каждый пинг) |
| apply_after_test | true | Пересобрать конфиг после теста |
| db_check_auto_cleanup | false | Удалять failed-прокси после проверки |

### Speed Test

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| speed_test_enabled | true | Замер скорости после проверки и пинга |
| speed_test_max | 15 | Топ-N рабочих (по пингу) для замера |
| speed_test_url | `http://speedtest.selectel.ru/10MB` | Файл для скачивания (крупные fallback-файлы) |
| speed_test_min_sec | 10 | Длительность замера ОДНОГО профиля — фиксированное окно (сек) |
| speed_test_adaptive_sec | 2 | Ранний выход при превышении порога (только при min_speed_mbps > 0) |

> Замеры скорости выполняются строго по одному профилю за раз (последовательно):
> параллельные замеры делят канал и дают недостоверные данные.

### Balancer

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| balancer_strategy | random | random / leastLoad / leastPing |
| observatory_probe_interval | 10s | Как часто Xray пингует узлы |
| handshake_timeout | 5 сек | Таймаут рукопожатия |
| conn_idle | 300 сек | Таймаут бездействия |

### Performance

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| max_workers | 15 | Параллельных воркеров для стадий проверки и пинга (1-30). Замер скорости всегда последовательный |
| probe_timeout | 3 сек | Таймаут проверки прокси |
| xray_startup_retries | 15 | Попыток дождаться старта Xray |

### Network

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| import_proxy | (пусто) | Прокси для импорта подписок (socks5:// или http://) |

### Logging

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| log_trim_every | 500 | Чистить логи каждые N записей |
| log_keep | 2000 | Оставлять последние N записей |

## Быстрая установка

### 1. Подготовка системы

```bash
sudo apt update
sudo apt install -y unzip wget git python3 python3-pip python3-venv conntrack
```

> **`conntrack`** (conntrack-tools) — требуется для per-connection байтов (колонка ↓/↑ в модалке Connections).
> Всё остальное работает и без conntrack.

### 2. Установка Xray

```bash
cd /tmp
arch=$(uname -m)
case "$arch" in
  x86_64) f="Xray-linux-64.zip" ;;
  aarch64) f="Xray-linux-arm64-v8a.zip" ;;
  *) echo "Unsupported arch: $arch"; exit 1 ;;
esac
wget -q --show-progress "https://github.com/XTLS/Xray-core/releases/latest/download/$f"
sudo mkdir -p /usr/local/share/xray
sudo unzip -o "$f" -d /usr/local/share/xray
sudo ln -sf /usr/local/share/xray/xray /usr/local/bin/xray
rm "$f"
# geosite.dat с категориями стран (включая ru-blocked):
sudo wget -qO /usr/local/share/xray/geosite.dat \
  "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
sudo wget -qO /usr/local/share/xray/geoip.dat \
  "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"
```

### 3. Базовый конфиг Xray

```bash
sudo mkdir -p /etc/xray
sudo tee /etc/xray/config.json << 'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
```

### 4. Установка VLESS Manager

```bash
sudo mkdir -p /opt/vless-manager
sudo chown $USER:$USER /opt/vless-manager
cd /opt/vless-manager
git clone https://github.com/prasx/vless-manager-proxy.git .
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
```

### 5. systemd сервисы

**Xray:**
```bash
sudo tee /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
After=network.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Environment="XRAY_LOCATION_ASSET=/usr/local/share/xray"
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=4096
[Install]
WantedBy=multi-user.target
EOF
```

**VLESS Manager:**
```bash
sudo tee /etc/systemd/system/vless-manager.service << 'EOF'
[Unit]
Description=VLESS Manager
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=/opt/vless-manager
ExecStart=/opt/vless-manager/venv/bin/python app.py
Restart=on-failure
RestartSec=5
# Если нужен прокси для импорта подписок:
# Environment=IMPORT_PROXY=socks5://127.0.0.1:1080
[Install]
WantedBy=multi-user.target
EOF
```

### 6. Запуск

```bash
sudo systemctl daemon-reload
sudo systemctl enable xray vless-manager
sudo systemctl start xray vless-manager
```

### 7. Проверка

```bash
systemctl status xray vless-manager
journalctl -u xray -f
journalctl -u vless-manager -f
```

Открой `http://<ip>:5000`.

## Структура

```
vless-manager/
├── app.py                   # Entry point
├── config.py                # Централизованная конфигурация
├── proxies.db               # SQLite (создаётся автоматически)
├── requirements.txt
├── vless-manager.service    # systemd unit (эталонный)
├── app/
│   ├── __init__.py          # Фабрика Flask
│   ├── db.py                # SQLite + Settings класс + миграции
│   ├── vless.py             # Парсинг VLESS
│   ├── utils.py             # Время, логи, geo enrichment
│   ├── proxy_manager.py     # Тестирование, фоновый чекер, failover, трафик
│   ├── xray_configurator.py # Генерация конфига + Xray API + диагностика
│   ├── importer.py          # Импорт подписок (urllib + curl fallback + прокси)
│   ├── subscribe.py         # Генерация subscribe.txt
│   └── routes/
│       ├── pages.py         # HTML-роуты
│       └── api.py           # REST API
├── static/
│   ├── style.css / dashboard.css / sources.css / logs.css
│   ├── dashboard.js / sources.js / settings.js / logs.js
│   ├── theme.js / toast.js
└── templates/
    ├── base.html / index.html / sources.html / settings.html / logs.html
```

## API

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/proxies?filter=&source=&search=&reason=&limit=&offset=` | Список прокси с пагинацией и фильтрами (`reason` — причина отказа failed) |
| GET | `/api/status` | Статистика (total, working, failed, top_speed, sources, reasons) |
| GET | `/api/countries` | Список стран с количеством, верификацией и blocked-статусом |
| GET | `/api/test-progress` | Статус поэтапного прогона (`stages`, `phase`, счётчики) |
| GET | `/api/test-progress/stream` | SSE-поток обновлений test-progress |
| POST | `/api/test-cancel` | Отменить текущий фоновый тест |
| POST | `/api/add` | Добавить `{"link": "vless://..."}`; тест стартует, если нет другого замера |
| POST | `/api/test/<id>` | Полный поэтапный тест одного прокси (работоспособность → пинг → скорость); 409 если идёт другой замер |
| POST | `/api/test-all` | Поэтапный конвейер для всех прокси (409 при занятости) |
| DELETE | `/api/delete/<id>` | Удалить прокси |
| POST | `/api/cleanup` | Удалить все failed |
| POST | `/api/proxies/batch-delete` | Удалить выбранные `{"ids": [1,2,3]}` |
| POST | `/api/proxies/batch-test` | Поэтапный конвейер для выбранных (409 при занятости) |
| POST | `/api/test-failed` | Перетест только failed-прокси, полный конвейер (409 при занятости) |
| GET | `/api/sources` | Список источников (со счётчиками прокси и рабочих) |
| POST | `/api/sources` | Добавить URL-источник `{"name":"...","url":"..."}` |
| POST | `/api/sources/txt` | Добавить TXT-источник `{"name":"...","content":"vless://..."}` |
| DELETE | `/api/sources/<id>` | Удалить источник |
| GET | `/api/sources/<id>/content` | Получить TXT-контент источника |
| PUT | `/api/sources/<id>/content` | Обновить TXT-контент `{"content":"..."}` |
| POST | `/api/sources/<id>/import` | Только импорт из источника (замер запускается отдельно) |
| POST | `/api/sources/import-all` | Только импорт из всех источников (замер запускается отдельно) |
| GET | `/api/settings` | Все настройки |
| POST | `/api/settings` | Сохранить настройки (с валидацией) |
| GET | `/api/backup` | Экспорт настроек + источников |
| POST | `/api/backup/import` | Импорт настроек + источников |
| GET | `/api/geosite-rules` | Список geosite-правил |
| POST | `/api/geosite-rules` | Сохранить geosite-правила |
| GET | `/api/xray/status` | Статус Xray (running, API, systemd, outbounds) |
| GET | `/api/xray/outbounds` | Outbound + трафик по узлам |
| POST | `/api/xray/start` | `systemctl start xray` |
| POST | `/api/xray/stop` | `systemctl stop xray` |
| POST | `/api/xray-restart` | `systemctl restart xray` |
| POST | `/api/xray/rebuild` | Пересобрать конфиг и применить |
| POST | `/api/import` | Импорт по URL `{"url":"..."}` |
| GET | `/api/subscribe.txt` | Subscription URL для клиентов |
| GET | `/api/logs?limit=&offset=&level=` | Логи с фильтрацией |
| POST | `/api/logs/clear` | Очистить логи |
| GET | `/api/connections/list` | Активные TCP-соединения через прокси |
| GET | `/api/connections/traffic` | Трафик сгруппированный по IP клиента |
| POST | `/api/connections/close` | Закрыть соединение `{"remote_host","remote_port"}` |
| POST | `/api/connections/flush` | Закрыть все активные соединения |
| GET | `/api/performance/recommendations` | Рекомендации по настройкам производительности |
| GET | `/api/health` | Health check для systemd/monitoring |

## Лицензия

MIT
