# VLESS Manager Proxy

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![Xray](https://img.shields.io/badge/Xray-24.3%2B-orange)](https://github.com/XTLS/Xray-core)

Веб-панель для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель сама тестирует, собирает конфиг со всеми рабочими узлами и применяет через **Xray API без перезапуска**. Встроенный **Observatory + Balancer** (leastPing) автоматически выбирают лучший узел.

<img width="1898" height="936" alt="roll_compress" src="https://github.com/user-attachments/assets/78d3e424-8f98-4bda-8326-19473129fcac" />

## 🌟 Особенности

*   **⚡️ Hot-swap через API** — Добавление/удаление outbound на лету, без перезапуска Xray и без разрыва соединений.
*   **🎯 Observatory + Balancer** — Xray сам проверяет задержки узлов каждые 30 секунд и выбирает лучший по leastPing. В Observatory попадают только VLESS-верифицированные прокси.
*   **🧪 Двухуровневое тестирование** — TCP ping (быстрая проверка доступности) и реальный VLESS-тест (запуск Xray с прокси, HTTP-запрос через него, замер пинга). Оба пинга отображаются в колонке `TCP | VLESS`.
*   **📡 Фоновое тестирование** — Каждые `CHECK_INTERVAL` секунд:  
      1. **TCP всех прокси параллельно** (`TEST_WORKERS` потоков) — быстрая проверка доступности хостов.  
      2. **Каждые ~10 мин** — VLESS-тест только рабочих прокси.  
      3. **Каждые ~3 часа** — VLESS-тест ВСЕХ TCP-рабочих прокси + переимпорт источников.  
      Конфиг и подписка пересобираются только по VLESS-верифицированным узлам.  
      При лимите `max_active_proxies` в конфиг попадают прокси с лучшим VLESS-пингом.
*   **🌍 Автоопределение страны профиля** — Из фрагмента ссылки (`#RU`, `#NL`) или через ip-api.com.
*   **➕ Импорт** — Вручную (вставка `vless://...` ссылки), по URL подписки, или массовый из источников. После импорта сразу запускается VLESS-тест всех прокси.
*   **🛡 Safe-only import** — Флаг при импорте: пропускать прокси с `security=none`.
*   **🌐 Фильтр по странам** — Выбор разрешённых стран в Settings, конфиг собирается только из них.
*   **📄 Пагинация** — На Dashboard и Logs: показаны первые 50 записей, кнопка "Show next 50".
*   **🔗 Subscription URL** — `/api/subscribe.txt` для v2rayNG, Streisand, Hiddify, Nekobox. Содержит только VLESS-верифицированные узлы.
*   **🧹 Массовые операции** — Чекбоксы, выбор всех, удалить/протестировать выбранные. "Test All" / "Cleanup" скрываются при выборе.
*   **🎨 Тема** — Светлая/тёмная тема.
*   **📊 Фильтры** — All / Working (TCP) / Working (VLESS) / Failed. Логи фильтруются по уровню (INFO/WARN/ERROR).
*   **📈 Traffic stats** — На Dashboard отображается количество активных outbound и узлов с трафиком.

## ⚙️ Конфигурация

Все параметры в `config.py`:

| Параметр | Значение по умолчанию | Описание |
|----------|----------------------|----------|
| `CHECK_INTERVAL` | 60 | Пауза между циклами фонового чекера, секунд |
| `TEST_WORKERS` | 20 | Потоков для параллельного TCP-теста |
| `VLESS_BATCH_SIZE` | 20 | Сколько прокси за цикл проверять через реальный VLESS |
| `VLESS_PER_PROXY_TIMEOUT` | 15 | Таймаут VLESS-теста одного прокси, секунд |
| `VLESS_CHECK_WORKING` | 10 | Каждый N-ный цикл — VLESS-тест только рабочих прокси (10 = ~10 мин) |
| `VLESS_CHECK_ALL` | 180 | Каждый N-ный цикл — VLESS-тест ВСЕХ TCP-рабочих прокси (180 = ~3 часа) |
| `REIMPORT_CYCLES` | 60 | Каждый N-ный цикл делать автоимпорт (60 × 60с = 1 час) |

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

# распаковка
sudo unzip -o "$f" -d /usr/local/share/xray

# бинарник
sudo ln -sf /usr/local/share/xray/xray /usr/local/bin/xray

rm "$f"
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
pip install -r requirements.txt || pip install flask

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
After=network.target

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
| GET | `/api/proxies?filter=&country=&limit=&offset=` | Список прокси с пагинацией (поддерживает `filter=vless`) |
| GET | `/api/status` | Статистика (включая `working_vless`) |
| POST | `/api/add` | Добавить `{"link": "vless://..."}` + VLESS-тест |
| POST | `/api/test/<id>` | TCP-тест одного прокси |
| POST | `/api/test-all` | TCP-тест всех прокси |
| POST | `/api/test-all-vless` | **Реальный VLESS-тест всех прокси, пересборка конфига** |
| DELETE | `/api/delete/<id>` | Удалить |
| POST | `/api/proxies/batch-delete` | Удалить выбранные `{"ids": [1,2,3]}` |
| POST | `/api/proxies/batch-test` | TCP-тест выбранных |
| POST | `/api/proxies/batch-test-vless` | **Реальный VLESS-тест выбранных, пересборка конфига** |
| GET | `/api/sources` | Список источников |
| POST | `/api/sources` | Добавить `{"name":"...","url":"..."}` |
| POST | `/api/sources/<id>/import` | Импорт из источника + VLESS-тест |
| DELETE | `/api/sources/<id>` | Удалить источник |
| POST | `/api/sources/import-all` | Импорт из всех + VLESS-тест |
| GET | `/api/settings` | Настройки |
| POST | `/api/settings` | Сохранить настройки |
| GET | `/api/xray/status` | Статус + активные outbound |
| GET | `/api/xray/outbounds` | Список узлов и трафик |
| POST | `/api/xray/start` | `systemctl start xray` |
| POST | `/api/xray/stop` | `systemctl stop xray` |
| POST | `/api/xray-restart` | `systemctl restart xray` |
| POST | `/api/import` | Импорт по URL `{"url":"..."}` + VLESS-тест |
| GET | `/api/subscribe.txt` | Subscription URL (только VLESS-верифицированные узлы) |
| POST | `/api/cleanup` | Удалить все упавшие прокси |
| GET | `/api/countries` | Список стран с количеством прокси |
| GET | `/api/logs?limit=&offset=&level=` | Логи с пагинацией и фильтром по уровню |
| POST | `/api/logs/clear` | Очистить логи |



## 🤝 Вклад в проект
Создавайте Issue, предлагайте Pull Request'ы или форкайте репозиторий.


## 📜 Лицензия
MIT License — свободно используйте, изменяйте и распространяйте.


## 🙏 Благодарности
Xray-core(https://github.com/XTLS/Xray-core)
Flask(https://flask.palletsprojects.com/en/stable/)
