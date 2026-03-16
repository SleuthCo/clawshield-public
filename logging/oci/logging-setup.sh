#!/bin/bash
# ClawShield OCI — Master logging infrastructure setup
# Deploys: eBPF monitor, iptables rules, logrotate, audit DB rotation, fail2ban
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="/opt/clawshield"

echo "================================================"
echo "  ClawShield Logging Infrastructure Setup"
echo "================================================"
echo ""

# --- Prerequisites ---
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

if grep -q "Microsoft" /proc/version 2>/dev/null; then
    echo "ERROR: This script is for OCI/Linux, not WSL2"
    exit 1
fi

echo "[1/7] Checking prerequisites..."

# Install missing packages
PACKAGES_NEEDED=""
command -v bpftrace &>/dev/null || PACKAGES_NEEDED="$PACKAGES_NEEDED bpftrace"
dpkg -l bpfcc-tools &>/dev/null 2>&1 || PACKAGES_NEEDED="$PACKAGES_NEEDED bpfcc-tools python3-bpfcc"
command -v sqlite3 &>/dev/null || PACKAGES_NEEDED="$PACKAGES_NEEDED sqlite3"
command -v fail2ban-client &>/dev/null || PACKAGES_NEEDED="$PACKAGES_NEEDED fail2ban"
command -v crontab &>/dev/null || PACKAGES_NEEDED="$PACKAGES_NEEDED cron"

if [ -n "$PACKAGES_NEEDED" ]; then
    echo "  Installing: $PACKAGES_NEEDED"
    apt-get update -qq && apt-get install -y -qq $PACKAGES_NEEDED
fi

# Create directories
mkdir -p /var/log/clawshield/audit-exports
mkdir -p /var/log/nginx-docker
chmod 750 /var/log/clawshield

echo "  Prerequisites OK"

# --- eBPF Monitor ---
echo ""
echo "[2/7] Deploying eBPF security monitor..."

# Copy files
mkdir -p "$INSTALL_DIR/ebpf/cmd/clawshield-ebpf"
mkdir -p "$INSTALL_DIR/logging/oci"
mkdir -p "$INSTALL_DIR/logging/systemd"

cp "$REPO_ROOT/ebpf/cmd/clawshield-ebpf/main.py" "$INSTALL_DIR/ebpf/cmd/clawshield-ebpf/main.py"
cp "$SCRIPT_DIR/ebpf.yaml" "$INSTALL_DIR/logging/oci/ebpf.yaml"
cp "$REPO_ROOT/logging/systemd/clawshield-ebpf.service" /etc/systemd/system/clawshield-ebpf.service

# Environment file (don't overwrite if already populated)
if [ ! -f "$INSTALL_DIR/logging/systemd/clawshield-ebpf.env" ]; then
    cp "$REPO_ROOT/logging/systemd/clawshield-ebpf.env" "$INSTALL_DIR/logging/systemd/clawshield-ebpf.env"
fi

# Kill ad-hoc BPF processes (they'll be replaced by the full monitor)
pkill -f "execsnoop-bpfcc" 2>/dev/null || true
pkill -f "tcpconnect-bpftrace" 2>/dev/null || true
sleep 1

# Enable and start service
systemctl daemon-reload
systemctl enable clawshield-ebpf
systemctl restart clawshield-ebpf

if systemctl is-active --quiet clawshield-ebpf; then
    echo "  eBPF monitor: RUNNING"
else
    echo "  WARNING: eBPF monitor failed to start. Check: journalctl -u clawshield-ebpf -n 20"
fi

# --- iptables ---
echo ""
echo "[3/7] Configuring iptables firewall..."

cp "$SCRIPT_DIR/iptables-setup.sh" "$INSTALL_DIR/logging/oci/iptables-setup.sh"
chmod +x "$INSTALL_DIR/logging/oci/iptables-setup.sh"
bash "$INSTALL_DIR/logging/oci/iptables-setup.sh"

echo "  iptables: CONFIGURED"

# --- Logrotate ---
echo ""
echo "[4/7] Installing logrotate configs..."

for conf in "$SCRIPT_DIR/logrotate.d/"*; do
    name=$(basename "$conf")
    cp "$conf" "/etc/logrotate.d/$name"
    echo "  Installed: /etc/logrotate.d/$name"
done

# Verify syntax
logrotate --debug /etc/logrotate.d/clawshield-* 2>/dev/null | tail -1 || true
echo "  Logrotate: CONFIGURED"

# --- Audit DB Rotation ---
echo ""
echo "[5/7] Installing audit DB rotation cron..."

cp "$SCRIPT_DIR/audit-db-rotate.sh" "$INSTALL_DIR/logging/oci/audit-db-rotate.sh"
chmod +x "$INSTALL_DIR/logging/oci/audit-db-rotate.sh"

# Install cron job (idempotent)
CRON_LINE="0 3 * * * $INSTALL_DIR/logging/oci/audit-db-rotate.sh"
(crontab -l 2>/dev/null | grep -v "audit-db-rotate"; echo "$CRON_LINE") | crontab -
echo "  Cron: 0 3 * * * audit-db-rotate.sh"

# --- fail2ban ---
echo ""
echo "[6/7] Configuring fail2ban..."

cp "$SCRIPT_DIR/fail2ban/jail.local" /etc/fail2ban/jail.local
cp "$SCRIPT_DIR/fail2ban/filter.d/nginx-badbots.conf" /etc/fail2ban/filter.d/nginx-badbots.conf
cp "$SCRIPT_DIR/fail2ban/filter.d/nginx-botsearch.conf" /etc/fail2ban/filter.d/nginx-botsearch.conf

systemctl enable fail2ban
systemctl restart fail2ban

if systemctl is-active --quiet fail2ban; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//')
    echo "  fail2ban: RUNNING (jails: $JAILS)"
else
    echo "  WARNING: fail2ban failed to start. Check: journalctl -u fail2ban -n 20"
fi

# --- Nginx log bind mount check ---
echo ""
echo "[7/7] Checking nginx log bind mount..."

if docker inspect clawshield-nginx --format '{{range .Mounts}}{{.Destination}}:{{.Type}}{{println}}{{end}}' 2>/dev/null | grep -q "/var/log/nginx:volume"; then
    echo "  NOTE: nginx logs use a Docker named volume."
    echo "  For logrotate + fail2ban integration, consider changing to:"
    echo "    volumes:"
    echo "      - /var/log/nginx-docker:/var/log/nginx"
    echo "  in docker-compose.yml and restarting nginx."
else
    echo "  nginx logs: bind-mounted (OK for logrotate)"
fi

# --- Summary ---
echo ""
echo "================================================"
echo "  Logging Infrastructure — Summary"
echo "================================================"
echo ""
echo "  Services:"
echo "    clawshield-ebpf    $(systemctl is-active clawshield-ebpf 2>/dev/null || echo 'inactive')"
echo "    fail2ban           $(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')"
echo ""
echo "  Log Paths:"
echo "    eBPF alerts:       /var/log/clawshield/ebpf.log"
echo "    eBPF journal:      journalctl -u clawshield-ebpf"
echo "    iptables drops:    dmesg | grep iptables-"
echo "    nginx access:      docker logs clawshield-nginx"
echo "    ClawShield audit:  docker exec standalone-clawshield-1 clawshield-audit --db /var/lib/clawshield/audit.db"
echo "    Audit exports:     /var/log/clawshield/audit-exports/"
echo "    BPF ad-hoc:        /var/log/bpf-*.log (if still running)"
echo ""
echo "  Cron:"
crontab -l 2>/dev/null | grep clawshield || echo "    (none)"
echo ""
echo "  Logrotate:"
ls /etc/logrotate.d/clawshield-* 2>/dev/null | sed 's/^/    /'
echo ""
echo "================================================"
echo "  Setup complete!"
echo "================================================"
