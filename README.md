# VLESS Manager Proxy

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![Xray](https://img.shields.io/badge/Xray-26.3+-orange)](https://github.com/XTLS/Xray-core)

Веб-панель для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель сама параллельно тестирует каждый прокси через реальный запуск Xray, собирает конфиг со всеми рабочими узлами и применяет через `apply_all()`. Встроенный **Observatory + Balancer** (leastPing) автоматически выбирают лучший узел.

<img width="1898" height="936" alt="roll_compress" src="https://github.com/user-attachments/assets/78d3e424-8f98-4bda-8326-19473129fcac" />

## 🌟 Особенности

*   **🎯 Observatory + Balancer** — Xray сам проверяет задержки узлов каждые 30 секунд и выбирает лучший по leastPing. В Observatory попадают только VLESS-верифицированные прокси.
*   **🧪 Реальный VLESS-тест** — Каждый прокси проверяется через запуск временного Xray с его конфигом и HTTP-запрос через него.
*   **⚡ Параллельное тестирование** — До 5 прокси одновременно. 50 прокси за 15–30 секунд (таймаут 3с).
*   **📡 Фоновое тестирование + реимпорт** — По расписанию: реимпорт из всех источников → enrich стран → VLESS-тест source-only → всех рабочих. Устаревшие прокси источника автоматически удаляются.
*   **🌍 Автоопределение страны профиля** — Из фрагмента ссылки (`#RU`, `#NL`) или через ip-api.com.
*   **➕ Импорт** — Вручную (вставка `vless://...` ссылки), по URL подписки, или массовый из источников. После импорта сразу enrich стран + VLESS-тест.
*   **🛡 Safe-only import** — Флаг при импорте: пропускать прокси с `security=none`.
*   **🧹 Автоочистка при реимпорте** — Прокси, пропавшие из подписки источника, удаляются при следующем импорте.
*   **🌐 Фильтр по странам** — Выбор разрешённых стран в Settings, конфиг и подписка собираются только из них.
*   **🌍 GeoSite-роутинг** — Настраиваемые правила geosite из Settings: доменные категории (<code>geosite:ru</code>, <code>geosite:youtube</code>, <code>geosite:netflix</code>, ...) направляются напрямую или через прокси-балансер.
*   **📄 Пагинация** — На Dashboard и Logs: показаны первые 50 записей, кнопка "Show next 50".
*   **🔗 Subscription URL** — `/api/subscribe.txt` для v2rayNG, Streisand, Hiddify, Nekobox. Только VLESS-верифицированные узлы, on-demand сборка.
*   **💾 Backup** — Экспорт/импорт настроек и источников в JSON через UI Settings.
*   **🧹 Массовые операции** — Чекбоксы, выбор всех, удалить/протестировать выбранные.
*   **🎨 Тема** — Светлая/тёмная тема.
*   **📊 Фильтры** — All / Working / Failed. Логи фильтруются по уровню.
*   **📈 Traffic stats** — Количество активных outbound и узлов с трафиком.
*   **⏱ Прогресс тестов** — Прогресс-бар, таблица и статистика обновляются в реальном времени.

## ⚙️ Конфигурация

Базовые параметры в `config.py`. Интервалы и тюнинг переопределяются через UI (Settings → Check Intervals & Tuning):

| Параметр | Значение по умолчанию | Описание |
|----------|----------------------|----------|
| `SOCKS_PORT` | 1080 | SOCKS5 inbound |
| `HTTP_PORT` | 1081 | HTTP inbound |
| `API_PORT` | 10085 | gRPC API Xray |
| `DATABASE` | `proxies.db` | Файл SQLite |
| `SUBSCRIBE_FILE` | `subscribe.txt` | Кеш подписки |

Параметры, доступные через UI Settings → Check Intervals & Tuning:

| UI-поле | По умолчанию | Описание |
|---------|-------------|----------|
| Base interval | 600 (10 мин) | Как часто просыпается фоновый процесс, пересборка конфига |
| VLESS interval | 10800 (3 часа) | Реимпорт из всех источников → enrich → VLESS-тест source-only → всех рабочих |
| Per-proxy timeout | 5 | Таймаут VLESS-теста одного прокси |
| Trim every | 500 | Чистить логи каждые N записей |
| Keep last | 2000 | Оставлять последние N записей

## 🚀 Быстрая установка

## 1. Подготовка системы

```bash
sudo apt update
sudo apt install -y unzip wget git python3 python3-pip python3-venv
```

---

## 2. Установка Xray

```bash
cd /tmp

arch=$(uname -m)
case "$arch" in
  x86_64) f="Xray-linux-64.zip" ;;
  aarch64) f="Xray-linux-arm64-v8a.zip" ;;
  *) echo "Unsupported arch: $arch"; exit 1 ;;
esac

wget -q --show-progress "https://github.com/XTLS/Xray-core/releases/latest/download/$f"

# директория под xray
sudo mkdir -p /usr/local/share/xray

# распаковка (включает xray, geoip.dat, geosite.dat)
sudo unzip -o "$f" -d /usr/local/share/xray

# бинарник
sudo ln -sf /usr/local/share/xray/xray /usr/local/bin/xray

rm "$f"

# geosite.dat из Xray-core не содержит категорий стран
# Скачиваем от runetfreedom — с ru-blocked, ru-blocked-all и всеми стандартными категориями:
sudo wget -qO /usr/local/share/xray/geosite.dat \
  "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"

# geoip.dat тоже обновляем оттуда (с ru-blocked, cloudflare, telegram и т.д.):
sudo wget -qO /usr/local/share/xray/geoip.dat \
  "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"
```



## 3. Базовый конфиг Xray

```bash
sudo mkdir -p /etc/xray

sudo tee /etc/xray/config.json << 'EOF'
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
```



## 4. Установка VLESS Manager

```bash
sudo mkdir -p /opt/vless-manager
cd /opt/vless-manager

sudo git clone https://github.com/prasx/vless-manager-proxy.git .

# виртуальное окружение
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

deactivate
```



## 5. systemd сервисы

### Xray

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



### VLESS Manager

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



## 6. Запуск

```bash
sudo systemctl daemon-reload
sudo systemctl enable xray vless-manager
sudo systemctl start xray vless-manager
```

---

## 7. Проверка

```bash
systemctl status xray
systemctl status vless-manager

journalctl -u xray -f
journalctl -u vless-manager -f

```
Открой `http://<ip>:5000`.


## Структура

```
vless-manager/
├── app.py                 # Entry point
├── config.py              # Централизованная конфигурация
├── xray_config.json       # Активный конфиг Xray (генерируется automatic)
├── proxies.db             # SQLite (создаётся automatic)
├── requirements.txt
├── app/
│   ├── __init__.py        # Фабрика Flask
│   ├── db.py              # SQLite + Settings класс
│   ├── vless.py           # Парсинг VLESS
│   ├── utils.py           # Время, логи
│   ├── proxy_manager.py   # Тестирование, фоновый чекер
│   ├── xray_configurator.py  # Генерация конфига + Xray API
│   ├── importer.py        # Импорт подписок
│   └── routes/
│       ├── pages.py       # HTML-роуты
│       └── api.py         # REST API
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
| GET | `/api/proxies?filter=&source=&limit=&offset=` | Список прокси с пагинацией (`filter=working/failed_recent`, `source=id/unknown`) |
| GET | `/api/status` | Статистика (total, working, failed_recent, sources[], unknown_count) |
| GET | `/api/test-progress` | Статус фонового теста (running/total/done/ok/label/last_completed/last_ok) |
| POST | `/api/add` | Добавить `{"link": "vless://..."}` + VLESS-тест + определение страны |
| POST | `/api/test/&lt;id&gt;` | VLESS-тест одного прокси |
| POST | `/api/test-all` | VLESS-тест всех прокси параллельно (5 воркеров) |
| DELETE | `/api/delete/&lt;id&gt;` | Удалить прокси |
| POST | `/api/cleanup` | Удалить все failed-прокси |
| POST | `/api/proxies/batch-delete` | Удалить выбранные `{"ids": [1,2,3]}` |
| POST | `/api/proxies/batch-test` | VLESS-тест выбранных |
| GET | `/api/sources` | Список источников |
| POST | `/api/sources` | Добавить `{"name":"...","url":"..."}` |
| DELETE | `/api/sources/&lt;id&gt;` | Удалить источник |
| POST | `/api/sources/&lt;id&gt;/import` | Импорт из источника + VLESS-тест + определение стран |
| POST | `/api/sources/import-all` | Импорт из всех + VLESS-тест + определение стран |
| GET | `/api/settings` | Все настройки |
| POST | `/api/settings` | Сохранить настройки |
| GET | `/api/backup` | Экспорт настроек + источников в JSON |
| POST | `/api/backup/import` | Импорт настроек + источников из JSON |
| GET | `/api/geosite-rules` | Список geosite-правил |
| POST | `/api/geosite-rules` | Сохранить geosite-правила `{"rules":[...]}` |
| GET | `/api/countries` | Список стран с enabled-статусом |
| GET | `/api/xray/status` | Статус Xray (running, API, systemd, outbounds) |
| GET | `/api/xray/outbounds` | Список узлов и трафик |
| POST | `/api/xray/start` | `systemctl start xray` |
| POST | `/api/xray/stop` | `systemctl stop xray` |
| POST | `/api/xray-restart` | `systemctl restart xray` |
| POST | `/api/import` | Импорт по URL `{"url":"..."}` + VLESS-тест + определение стран |
| GET | `/api/subscribe.txt` | Subscription URL (только VLESS-верифицированные узлы, on-demand сборка) |
| GET | `/api/logs?limit=&offset=&level=` | Логи с пагинацией и фильтром (DEBUG/INFO/WARN/ERROR) |
| POST | `/api/logs/clear` | Очистить логи |

---



## 🤝 Вклад в проект
Создавайте Issue, предлагайте Pull Request'ы или форкайте репозиторий.


## 📜 Лицензия
MIT License — свободно используйте, изменяйте и распространяйте.


## 🙏 Благодарности
Xray-core(https://github.com/XTLS/Xray-core)
Flask(https://flask.palletsprojects.com/en/stable/)
