# VLESS Manager Proxy

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![Xray](https://img.shields.io/badge/Xray-24.3%2B-orange)](https://github.com/XTLS/Xray-core)

Веб-панель для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель сама тестирует, собирает конфиг со всеми рабочими узлами и применяет через **Xray API без перезапуска**. Встроенный **Observatory + Balancer** (leastPing) автоматически выбирают лучший узел.

<img width="1898" height="936" alt="roll_compress" src="https://github.com/user-attachments/assets/78d3e424-8f98-4bda-8326-19473129fcac" />

## 🌟 Особенности

*   **⚡️ Hot-swap через API** — Добавление/удаление outbound на лету, без перезапуска Xray и без разрыва соединений.
*   **🎯 Observatory + Balancer** — Xray сам проверяет задержки узлов каждые 30 секунд и выбирает лучший по leastPing.
*   **📡 Умное тестирование** — Фоновая проверка каждые 60 секунд. Кнопка "Test All" протестирует все прокси и автоматически пересоберет конфиг.
*   **🌍 Автоопределение страны профиля** — Из фрагмента ссылки (`#RU`, `#NL`) или через ip-api.com.
*   **➕ Импорт** — Вручную (вставка `vless://...` ссылки), по URL подписки, или массовый из источников.
*   **🛡 Safe-only import** — Флаг при импорте: пропускать прокси с `security=none`.
*   **🌐 Фильтр по странам** — Выбор разрешённых стран в Settings, конфиг собирается только из них.
*   **📄 Пагинация** — На Dashboard и Logs: показаны первые 50 записей, кнопка "Show next 50".
*   **🔗 Subscription URL** — `/api/subscribe.txt` для v2rayNG, Streisand, Hiddify, Nekobox.
*   **🧹 Массовые операции** — Чекбоксы, выбор всех, удалить/протестировать выбранные. "Test All" / "Cleanup" скрываются при выборе.
*   **🎨 Тема** — Светлая/тёмная тема.
*   **📊 Фильтры** — All / Working / Failed. Логи фильтруются по уровню (INFO/WARN/ERROR).
*   **📈 Traffic stats** — На Dashboard отображается количество активных outbound и узлов с трафиком.
*   **⏰ Фоновые задачи** — Автоимпорт из источников каждый час, автотестирование каждые 60с, Observatory (30с).


## 🚀 Быстрая установка

### 1. Установка Xray-core
```bash
# Установка зависимостей
sudo apt update && sudo apt install unzip -y

# Скачивание Xray под вашу архитектуру
arch=$(uname -m); case "$arch" in x86_64) f="Xray-linux-64.zip" ;; aarch64) f="Xray-linux-arm64-v8a.zip" ;; *) echo "Unsupported arch: $arch"; exit 1 ;; esac
wget "https://github.com/XTLS/Xray-core/releases/latest/download/$f"

# Установка в /usr/local/bin
sudo unzip -o "$f" -d /usr/local/bin/ xray geosite.dat geoip.dat && rm "$f"

# Установка панели
sudo mkdir -p /opt/vless-manager
cd /opt/vless-manager
git clone https://github.com/prasx/vless-manager-proxy.git
pip3 install flask

# Настройка systemd-сервисов
# xray.service
sudo tee /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray VLESS Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=4096
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# vless-manager
sudo tee /etc/systemd/system/vless-manager.service << 'EOF'
[Unit]
Description=VLESS Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vless-manager
ExecStart=/usr/bin/python3 /opt/vless-manager/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF


# Меняем адрес конфига
sed -i 's|/etc/xray/config.json|/opt/vless-manager/xray_config.json|g' /etc/systemd/system/xray.service

# Запуск
sudo systemctl daemon-reload
sudo systemctl enable --now xray vless-manager
```
Открой `http://<ip>:5000`.


## Структура

```
vless-manager/
├── app.py              # Entry point
├── config.py           # Централизованная конфигурация
├── xray_config.json    # Активный конфиг Xray (генерируется automatic)
├── proxies.db          # SQLite (создаётся automatic)
├── requirements.txt
├── app/
│   ├── __init__.py     # Фабрика Flask
│   ├── db.py           # SQLite запросы
│   ├── vless.py        # Парсинг VLESS
│   ├── utils.py        # Время, логи, диагностика
│   ├── xray_api.py     # Xray API (add/remove outbound)
│   ├── xray_config.py  # Генерация конфига + API-замена
│   ├── tester.py       # Тестирование прокси
│   ├── importer.py     # Импорт подписок
│   ├── tasks.py        # Фоновые задачи
│   └── routes/
│       ├── pages.py    # HTML-роуты
│       └── api.py      # REST API
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
| GET | `/api/proxies?filter=&country=&limit=&offset=` | Список прокси с пагинацией |
| GET | `/api/status` | Статистика |
| POST | `/api/add` | Добавить `{"link": "vless://..."}` |
| POST | `/api/test/<id>` | Проверить один |
| POST | `/api/test-all` | Проверить все, пересобрать конфиг |
| DELETE | `/api/delete/<id>` | Удалить |
| POST | `/api/proxies/batch-delete` | Удалить выбранные `{"ids": [1,2,3]}` |
| POST | `/api/proxies/batch-test` | Протестировать выбранные `{"ids": [1,2,3]}` |
| GET | `/api/sources` | Список источников |
| POST | `/api/sources` | Добавить `{"name":"...","url":"..."}` |
| POST | `/api/sources/<id>/import` | Импорт из источника |
| DELETE | `/api/sources/<id>` | Удалить источник |
| POST | `/api/sources/import-all` | Импорт из всех |
| GET | `/api/settings` | Настройки |
| POST | `/api/settings` | Сохранить настройки |
| GET | `/api/xray/status` | Статус + активные outbound |
| GET | `/api/xray/outbounds` | Список узлов и трафик |
| POST | `/api/xray/start` | `systemctl start xray` |
| POST | `/api/xray/stop` | `systemctl stop xray` |
| POST | `/api/xray-restart` | `systemctl restart xray` |
| POST | `/api/import` | Импорт по URL `{"url":"..."}` |
| GET | `/api/subscribe.txt` | Subscription URL (v2rayNG, Streisand, Hiddify, Nekobox) |
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
