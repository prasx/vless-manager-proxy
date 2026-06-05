# VLESS Manager Proxy

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![Xray](https://img.shields.io/badge/Xray-26.3+-orange)](https://github.com/XTLS/Xray-core)

Веб-панель для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель параллельно тестирует каждый прокси через реальный запуск Xray, собирает конфиг с рабочими узлами и применяет через Xray API. **Observatory + Balancer** (random, leastLoad, leastPing) автоматически выбирают лучший узел.

## Особенности

- **Два фоновых таймера** — DB-only Check (только тест из БД) и Import+Check (импорт + enrich стран + тест). Import+Check имеет приоритет, не запускаются одновременно.
- **Реальный VLESS-тест** — Каждый прокси проверяется через временный Xray с HTTP-пробой (`generate_204`).
- **Speed test** — После VLESS-теста топ-N рабочих прокси замеряют пропускную способность. Результат — primary сортировка в конфиге.
- **Параллельное тестирование** — До 5 прокси одновременно.
- **Автоопределение страны** — Из фрагмента ссылки (`#RU`) или через ip-api.com.
- **GeoSite-роутинг** — Настраиваемые правила (`geosite:ru-blocked`, `geoip:telegram`, ...) с направлениями direct/proxy.
- **Фильтр по странам** — Выбор разрешённых стран; конфиг и подписка собираются только из них.
- **Subscription URL** — `/api/subscribe.txt` для внешних клиентов (v2rayNG, Streisand, Hiddify).
- **Массовые операции** — Чекбоксы, выбор всех, удалить/протестировать выбранные.
- **Backup** — Экспорт/импорт настроек и источников в JSON.
- **Traffic stats** — Активные outbound и узлы с трафиком.
- **Прогресс тестов** — Прогресс-бар в реальном времени.

## Конфигурация

Базовые параметры в `config.py`. Интервалы и тюнинг — через UI (Settings → Check Intervals & Tuning):

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `SOCKS_PORT` | 1080 | SOCKS5 inbound |
| `HTTP_PORT` | 1081 | HTTP inbound |
| `API_PORT` | 10085 | gRPC API Xray |
| `DATABASE` | `proxies.db` | SQLite |
| `SUBSCRIBE_FILE` | `subscribe.txt` | Кеш подписки |

Параметры UI (Settings → Check Intervals & Tuning):

| UI-поле | По умолчанию | Описание |
|---------|-------------|----------|
| DB-only Check | 0.5 ч | Интервал VLESS-теста прокси из БД |
| Import+Check | 3 ч | Интервал импорта + enrich стран + тест |
| Per-proxy timeout | 5 сек | Таймаут VLESS-теста одного прокси |
| Speed test enabled | true | Замер скорости после VLESS |
| Speed test Top-N | 30 | Сколько прокси тестировать на скорость |
| Speed test URL | `http://speedtest.selectel.ru/10MB` | Файл для скачивания (HTTP) |
| Balancer | random | Стратегия балансировки (random/leastLoad/leastPing) |
| Observatory probe | 15s | Как часто Xray пингует узлы |
| Handshake | 8 сек | Таймаут рукопожатия |
| Idle timeout | 300 сек | Таймаут бездействия |

## Быстрая установка

### 1. Подготовка системы

```bash
sudo apt update
sudo apt install -y unzip wget git python3 python3-pip python3-venv
```

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
├── proxies.db               # SQLite (создаётся automatic)
├── requirements.txt
├── app/
│   ├── __init__.py          # Фабрика Flask
│   ├── db.py                # SQLite + Settings класс
│   ├── vless.py             # Парсинг VLESS
│   ├── utils.py             # Время, логи, geo
│   ├── proxy_manager.py     # Тестирование, фоновый чекер
│   ├── xray_configurator.py # Генерация конфига + Xray API
│   ├── importer.py          # Импорт подписок
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
| GET | `/api/proxies?filter=&source=&limit=&offset=` | Список прокси с пагинацией |
| GET | `/api/status` | Статистика (total, working, failed, sources) |
| GET | `/api/test-progress` | Статус фонового теста |
| POST | `/api/add` | Добавить `{"link": "vless://..."}` + тест |
| POST | `/api/test/<id>` | VLESS-тест одного прокси |
| POST | `/api/test-all` | VLESS-тест всех прокси |
| DELETE | `/api/delete/<id>` | Удалить прокси |
| POST | `/api/cleanup` | Удалить все failed |
| POST | `/api/proxies/batch-delete` | Удалить выбранные `{"ids": [1,2,3]}` |
| POST | `/api/proxies/batch-test` | Тест выбранных |
| GET | `/api/sources` | Список источников |
| POST | `/api/sources` | Добавить `{"name":"...","url":"..."}` |
| DELETE | `/api/sources/<id>` | Удалить источник |
| POST | `/api/sources/<id>/import` | Импорт из источника + тест |
| POST | `/api/sources/import-all` | Импорт из всех + тест |
| GET | `/api/settings` | Все настройки |
| POST | `/api/settings` | Сохранить настройки (с валидацией) |
| GET | `/api/backup` | Экспорт настроек + источников |
| POST | `/api/backup/import` | Импорт настроек + источников |
| GET | `/api/geosite-rules` | Список geosite-правил |
| POST | `/api/geosite-rules` | Сохранить geosite-правила |
| GET | `/api/countries` | Список стран с enabled |
| GET | `/api/xray/status` | Статус Xray |
| GET | `/api/xray/outbounds` | Outbound + трафик |
| POST | `/api/xray/start` | `systemctl start xray` |
| POST | `/api/xray/stop` | `systemctl stop xray` |
| POST | `/api/xray-restart` | `systemctl restart xray` |
| POST | `/api/import` | Импорт по URL `{"url":"..."}` |
| GET | `/api/subscribe.txt` | Subscription URL |
| GET | `/api/logs?limit=&offset=&level=` | Логи |
| POST | `/api/logs/clear` | Очистить логи |

## Лицензия

MIT
