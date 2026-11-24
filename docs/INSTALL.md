# Установка VLESS Manager

Требования: Linux, Python 3.10+, Xray-core. Панель слушает порт `5000`.

## 1. Подготовка системы

```bash
sudo apt update
sudo apt install -y unzip wget git python3 python3-pip python3-venv conntrack
```

`conntrack` нужен для per-connection трафика в «Соединениях». Остальное работает и без него.

## 2. Xray

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

sudo wget -qO /usr/local/share/xray/geosite.dat \
  "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
sudo wget -qO /usr/local/share/xray/geoip.dat \
  "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"
```

Базовый конфиг, который панель будет перезаписывать:

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

## 3. Панель

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

## 4. systemd

**Xray** — `/etc/systemd/system/xray.service`:

```ini
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
```

**Панель** — `/etc/systemd/system/vless-manager.service`:

```ini
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
```

Запуск:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now xray vless-manager
systemctl status xray vless-manager
journalctl -u vless-manager -f
```

Открыть `http://<ip>:5000`.

## 5. Обновление

```bash
cd /opt/vless-manager
git pull
sudo systemctl restart vless-manager
```

SQLite-схема мигрирует сама при старте. Перед крупным обновлением можно скачать настройки и источники через «Настройки → Бэкап».
