#!/bin/bash

CONFIG_FILE="/etc/sysctl.d/99-network-optimization.conf"
VPN_DIR="/vpn-server/target/release"
VPN_USER="root"


cat > $CONFIG_FILE << EOF
# Network optimization by bratan
net.ipv4.ip_forward = 1
net.core.rmem_max = 104857600
net.core.wmem_max = 104857600
net.ipv4.tcp_rmem = 4096 16384 104857600
net.ipv4.tcp_wmem = 4096 16384 104857600
EOF

echo "Конфиг создан: $CONFIG_FILE"

# Применяем настройки
echo "Применяю настройки..."
sysctl -p $CONFIG_FILE

echo "Въебываю nftables..."

# Проверяем есть ли nftables
if ! command -v nft &> /dev/null; then
    echo "Устанавливаю nftables..."
    apt update && apt install -y nftables
fi

systemctl enable nftables

if [ -f /etc/nftables.conf ]; then
    echo "Применяю правила из /etc/nftables.conf"
    nft -f /etc/nftables.conf
    systemctl restart nftables
else
    echo "Внимание: /etc/nftables.conf не найден!"
fi

echo "Въебываю systemd сервис"
chmod +x $VPN_DIR/vpn
cat > /etc/systemd/system/vpn-server.service << EOF
[Unit]
Description=VPN Server
After=network.target

[Service]
Type=simple
User=$VPN_USER
WorkingDirectory=$VPN_DIR
ExecStart=$VPN_DIR/vpn listen users.txt server.priv 8080 10.0.0.1 255.255.255.0
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpn-server.service
systemctl start vpn-server.service

# Проверяем что въебало
echo ""
echo "Проверяем настройки:"
echo "ip_forward: $(sysctl -n net.ipv4.ip_forward)"
echo "rmem_max: $(sysctl -n net.core.rmem_max)"
echo "wmem_max: $(sysctl -n net.core.wmem_max)"
echo "tcp_rmem: $(sysctl -n net.ipv4.tcp_rmem)"
echo "tcp_wmem: $(sysctl -n net.ipv4.tcp_wmem)"

echo ""
echo "nftables статус:"
systemctl status nftables --no-pager -l

echo ""
echo "Правила nftables:"
nft list ruleset

echo ""
echo "Готово! Всё въебано и сохранится после ребута:"
echo "- Сетевые настройки в $CONFIG_FILE"
echo "- nftables автозагрузка включена"
echo "- Правила применяются из /etc/nftables.conf"

echo "Команды для управления:"
echo "sudo systemctl start vpn-server.service"
echo "sudo systemctl stop vpn-server.service"
echo "sudo systemctl status vpn-server.service"
echo "sudo journalctl -u vpn-server.service -f"
