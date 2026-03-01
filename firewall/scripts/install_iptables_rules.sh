#!/bin/bash

set -e

CLAWSHIELD_CONFIG="/etc/clawshield/config.yaml"
CLAWSHIELD_BIN="/usr/local/bin/clawshield-fw"

# Check if running in WSL2
if ! grep -q "Microsoft" /proc/version; then
	echo "Error: ClawShield only supports WSL2. Exiting."
	exit 1
fi

# Install dependencies (iptables)
if ! command -v iptables &> /dev/null; then
	echo "Installing iptables..."
	sudo apt-get update && sudo apt-get install -y iptables
fi

# Create config directory
sudo mkdir -p /etc/clawshield/

# Copy sample config (user should edit)
cat > /tmp/clawshield-sample.yaml << 'EOL'
allowed_domains:
  - "api.openai.com"
  - "google.com"
  - "github.com"
dns_resolvers:
  - "8.8.8.8"
  - "8.8.4.4"
EOL

sudo mv /tmp/clawshield-sample.yaml "$CLAWSHIELD_CONFIG"
echo "Sample config written to $CLAWSHIELD_CONFIG"

echo "Installing clawshield-fw binary..."
# Assuming binary is built and copied here (e.g., via package or manual install)
# This script assumes the go binary is already compiled and in PATH
if [ ! -f "$CLAWSHIELD_BIN" ]; then
	echo "Error: clawshield-fw binary not found. Please build and install it first."
	exit 1
fi

chmod +x "$CLAWSHIELD_BIN"

echo "Applying firewall rules..."
sudo "$CLAWSHIELD_BIN" apply --config="$CLAWSHIELD_CONFIG"

echo "ClawShield successfully installed and activated."