#!/usr/bin/env bash
# Lock down callora's host-level firewall to the bare minimum.
# Idempotent: safe to re-run.
#
# This is host-level (UFW). Container egress is NOT touched here because:
# 1. Containers reach internet through Docker NAT — different stack
# 2. Strict container egress allowlists are operationally fragile
#    (AWS IP ranges change, package mirrors rotate, etc.)
# 3. Defense for container egress is handled at app-layer (cred encryption,
#    honeytokens, audit log)
#
# What this DOES enforce:
#  - Inbound: only SSH (22), HTTP (80), HTTPS (443) from anywhere
#  - Outbound: allow all (return traffic), but LOG new connections for
#    later anomaly review
#  - Block well-known-bad ports (cryptominer pools, IRC C2)
#
# Run on callora as:    sudo bash /srv/mmwss/repo/ops/setup-firewall.sh

set -euo pipefail

echo "==> Installing UFW if missing"
apt-get update -qq
apt-get install -y -qq ufw

echo "==> Defaults"
ufw --force default deny incoming
ufw --force default allow outgoing
ufw --force default deny routed

echo "==> Allow inbound: SSH, HTTP, HTTPS"
ufw allow 22/tcp   comment 'SSH'
ufw allow 80/tcp   comment 'HTTP (Caddy redirect)'
ufw allow 443/tcp  comment 'HTTPS (Caddy)'

echo "==> Block known-bad outbound (cryptominer pools + IRC C2)"
# Common Stratum mining ports
for port in 3333 4444 5555 7777 8888 9999 14444 14433; do
    ufw deny out "${port}/tcp" comment "Stratum/mining pool"
done
# Common IRC C2
for port in 6660 6661 6662 6663 6664 6665 6666 6667 6668 6669 6697; do
    ufw deny out "${port}/tcp" comment "IRC C2"
done
# Tor SOCKS / relay (don't need this; legitimate sysadmin work doesn't go through Tor)
ufw deny out 9050/tcp comment 'Tor SOCKS'

echo "==> Enable logging (low — kernel log only, no full packet capture)"
ufw logging low

echo "==> Enable UFW"
ufw --force enable
echo
echo "==> Status:"
ufw status verbose

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  Firewall baseline locked down."
echo "  Logs available at: /var/log/ufw.log (or 'journalctl -k | grep UFW')"
echo "  To add an allowed inbound: sudo ufw allow <port>/tcp comment '<reason>'"
echo "  To disable temporarily:   sudo ufw disable"
echo "═══════════════════════════════════════════════════════════════"
