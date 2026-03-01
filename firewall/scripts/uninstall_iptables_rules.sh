#!/bin/bash

set -e

CLAWSHIELD_BIN="/usr/local/bin/clawshield-fw"

# Check if running in WSL2
if ! grep -q "Microsoft" /proc/version; then
	echo "Error: ClawShield only supports WSL2. Exiting."
	exit 1
fi

echo "Removing ClawShield iptables rules..."

# Flush OUTPUT chain and restore default ACCEPT policy
sudo iptables -F OUTPUT
sudo iptables -P OUTPUT ACCEPT

echo "Clearing logs (optional)"
sudo dmesg -C

echo "Removing config files..."
sudo rm -rf /etc/clawshield/

echo "ClawShield firewall rules uninstalled."

echo "Note: To completely uninstall, remove binary: sudo rm $CLAWSHIELD_BIN"