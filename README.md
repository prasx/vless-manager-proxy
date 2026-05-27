# VLESS Manager

Flask-сервис для управления VLESS прокси. Добавляй подписки и отдельные ссылки — панель сама тестирует, собирает конфиг со всеми рабочими узлами и применяет через Xray API без перезапуска. Встроенный observatory + balancer (leastPing) автоматически выбирают лучший узел.

## Установка

```bash
# 1. Xray-core
sudo apt install unzip -y
arch=$(uname -m)
case "$arch" in x86_64) f="Xray-linux-64.zip" ;; aarch64) f="Xray-linux-arm64-v8a.zip" ;; esac
wget "https://github.com/XTLS/Xray-core/releases/latest/download/$f"
sudo unzip -o "$f" -d /usr/local/bin/ xray geosite.dat geoip.dat && rm "$f"

# 2. Панель
sudo mkdir -p /opt/vless-manager
cd /opt/vless-manager
wget https://raw.githubusercontent.com/prasx/vless-manager/main/app.py
pip install flask

# 3. systemd-сервис Xray
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
sudo systemctl daemon-reload
sudo systemctl enable --now xray

# 4. systemd-сервис панели
sudo tee /etc/systemd/system/vless-manager.service << 'EOF'
[Unit]
Description=vless-manager
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
sudo systemctl daemon-reload
sudo systemctl enable --now vless-manager
```

Открой `http://<ip>:5000`.

## Возможности

- **Добавление** — вставь `vless://...` ссылку вручную или импорт по URL подписки
- **Автоопределение страны профиля** — из фрагмента `#RU` / `#NL` либо через ip-api.com
- **Фоновая проверка** — каждые 60 секунд тестирует все прокси, обновляет статус
- **Test All** — протестировать все и автоматически пересобрать конфиг
- **Observatory + Balancer** — Xray сам проверят задержки узлов каждые 30s и выбирает best по leastPing
- **Hot-swap через API** — добавление/удаление outbound на лету, без перезапуска
- **Фильтры** — All / World / Failed
- **Светлая/тёмная тема**

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
