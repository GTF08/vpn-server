#!/bin/bash
set -e

# Определяем внешний интерфейс (по умолчанию)
EXT_IF=$(ip -4 route list 0/0 | awk '{print $5}' | head -1)
if [ -z "$EXT_IF" ]; then
    echo "ERROR: Cannot determine external interface"
    exit 1
fi
echo "External interface detected: $EXT_IF"

# Заменяем в правиле ens1 на актуальный интерфейс и загружаем nftables
sed "s/ens1/$EXT_IF/g" /etc/nftables.conf > /tmp/nftables.conf
nft -f /tmp/nftables.conf

# Запускаем VPN-сервер
exec vpn "$@"