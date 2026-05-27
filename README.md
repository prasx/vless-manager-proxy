# VLESS Manager Proxy

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-green)](https://flask.palletsprojects.com/)
[![Xray](https://img.shields.io/badge/Xray-24.3%2B-orange)](https://github.com/XTLS/Xray-core)

Веб-панель для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель сама тестирует, собирает конфиг со всеми рабочими узлами и применяет через **Xray API без перезапуска**. Встроенный **Observatory + Balancer** (leastPing) автоматически выбирают лучший узел.

## 🌟 Особенности

*   **⚡️ Hot-swap через API** — Добавление/удаление outbound на лету, без перезапуска Xray и без разрыва соединений.
*   **🎯 Observatory + Balancer** — Xray сам проверяет задержки узлов каждые 30 секунд и выбирает лучший по leastPing.
*   **📡 Умное тестирование** — Фоновая проверка каждые 60 секунд. Кнопка "Test All" протестирует все прокси и автоматически пересоберет конфиг.
*   **🌍 Автоопределение страны профиля** — Из фрагмента ссылки (`#RU`, `#NL`) или через ip-api.com.
*   **🔄 Импорт** — Вручную (вставка `vless://...` ссылки) или по URL подписки (списком).
*   **🎨 Тема** — Светлая/тёмная тема.
*   **📊 Фильтры** — All / World / Failed.


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
wget https://raw.githubusercontent.com/prasx/vless-manager-proxy/main/app.py
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

# Запуск
sudo systemctl daemon-reload
sudo systemctl enable --now xray vless-manager
```
Открой `http://<ip>:5000`.


## Структура

```
vless-manager/
├── app.py              # Flask-приложение
├── xray_config.json    # Активный конфиг Xray (генерируется automatic)
├── proxies.db          # SQLite (создаётся automatic)
├── requirements.txt
├── static/
│   ├── style.css / dashboard.css / sources.css / logs.css
│   ├── dashboard.js / sources.js / settings.js
│   ├── theme.js / toast.js
└── templates/
    ├── base.html / index.html / sources.html / settings.html / logs.html
```

## API

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/proxies?filter=&country=` | Список прокси |
| GET | `/api/status` | Статистика |
| POST | `/api/add` | Добавить `{"link": "vless://..."}` |
| POST | `/api/test/<id>` | Проверить один |
| POST | `/api/test-all` | Проверить все, пересобрать конфиг |
| DELETE | `/api/delete/<id>` | Удалить |
| GET | `/api/sources` | Список источников |
| POST | `/api/sources` | Добавить `{"name":"...","url":"..."}` |
| POST | `/api/sources/<id>/import` | Импорт из источника |
| POST | `/api/sources/import-all` | Импорт из всех |
| GET | `/api/settings` | Настройки |
| POST | `/api/settings` | Сохранить настройки |
| GET | `/api/xray/status` | Статус + активные outbound |
| GET | `/api/xray/outbounds` | Список узлов и трафик |
| POST | `/api/xray/start` | `systemctl start xray` |
| POST | `/api/xray/stop` | `systemctl stop xray` |
| POST | `/api/xray-restart` | `systemctl restart xray` |
| POST | `/api/import` | Импорт по URL `{"url":"..."}` |




## 🤝 Вклад в проект
Создавайте Issue, предлагайте Pull Request'ы или форкайте репозиторий.


## 📜 Лицензия
MIT License — свободно используйте, изменяйте и распространяйте.


## 🙏 Благодарности
Xray-core(https://github.com/XTLS/Xray-core)
Flask(https://flask.palletsprojects.com/en/stable/)