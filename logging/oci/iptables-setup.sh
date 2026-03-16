#!/bin/bash
# ClawShield OCI — iptables firewall setup
# Configures INPUT chain with logging, preserves Docker chains
set -euo pipefail

if grep -q "Microsoft" /proc/version 2>/dev/null; then
    echo "ERROR: This script is for OCI/Linux. Use firewall/scripts/install_iptables_rules.sh for WSL2."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

echo "=== ClawShield OCI iptables setup ==="

# Create log directory
mkdir -p /var/log/clawshield

# --- INPUT chain ---
# Flush INPUT only (preserve FORWARD/DOCKER chains)
iptables -F INPUT

# Default policy
iptables -P INPUT DROP

# Established/related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# ICMP (limited)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec -j ACCEPT
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

# SSH — rate-limited with separate brute-force log
# 15 new connections in 120 seconds = brute force (higher threshold for deploy scripts)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 120 --hitcount 15 --name SSH -j LOG --log-prefix "iptables-ssh-brute: " --log-level 4
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 120 --hitcount 15 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Docker bridge interfaces (container-to-host)
iptables -A INPUT -i docker0 -j ACCEPT
iptables -A INPUT -i br-+ -j ACCEPT

# --- Logging chains ---
# Create or flush LOG_AND_DROP
iptables -N LOG_AND_DROP 2>/dev/null || iptables -F LOG_AND_DROP
iptables -A LOG_AND_DROP -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables-drop: " --log-level 4
iptables -A LOG_AND_DROP -j DROP

# Create or flush LOG_AND_REJECT
iptables -N LOG_AND_REJECT 2>/dev/null || iptables -F LOG_AND_REJECT
iptables -A LOG_AND_REJECT -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "iptables-reject: " --log-level 4
iptables -A LOG_AND_REJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -A LOG_AND_REJECT -j REJECT --reject-with icmp-port-unreachable

# Default: log and reject
iptables -A INPUT -j LOG_AND_REJECT

# --- OUTPUT chain ---
# Permissive but block known C2 ports
iptables -P OUTPUT ACCEPT
# Flush any existing C2 rules, then re-add
iptables -D OUTPUT -p tcp -m multiport --dports 4444,5555,31337,1337,6666,6667 -j LOG --log-prefix "iptables-c2-outbound: " --log-level 4 2>/dev/null || true
iptables -D OUTPUT -p tcp -m multiport --dports 4444,5555,31337,1337,6666,6667 -j DROP 2>/dev/null || true
iptables -A OUTPUT -p tcp -m multiport --dports 4444,5555,31337,1337,6666,6667 -j LOG --log-prefix "iptables-c2-outbound: " --log-level 4
iptables -A OUTPUT -p tcp -m multiport --dports 4444,5555,31337,1337,6666,6667 -j DROP

# --- OCI Instance Services ---
# Keep existing OCI metadata access rules in InstanceServices chain (managed by OCI agent)

# --- Persist ---
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    echo "Rules persisted via netfilter-persistent"
elif [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
    echo "Rules saved to /etc/iptables/rules.v4"
else
    iptables-save > /tmp/iptables-rules.v4
    echo "WARNING: No persistence mechanism found. Rules saved to /tmp/iptables-rules.v4"
fi

echo ""
echo "=== iptables setup complete ==="
echo "Log prefixes:"
echo "  iptables-ssh-brute:     SSH brute force (>15 attempts/2min)"
echo "  iptables-drop:          General drops"
echo "  iptables-reject:        General rejects"
echo "  iptables-c2-outbound:   Suspicious outbound ports blocked"
echo ""
echo "View logs: dmesg | grep iptables- | tail -20"
