#!/bin/sh
set -e

echo "ClawShield Standalone — starting up..."

# --- Environment Variables ---
# ANTHROPIC_API_KEY  — required, passed to OpenClaw gateway
# GATEWAY_AUTH_TOKEN — optional, defaults to random token (shared between gateway + proxy)

if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "ERROR: ANTHROPIC_API_KEY environment variable is required"
  exit 1
fi

# Generate random gateway token if not provided
if [ -z "$GATEWAY_AUTH_TOKEN" ]; then
  GATEWAY_AUTH_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  echo "Generated random gateway auth token."
fi

# --- Inject Gateway Token and Password into openclaw.json ---
# Replace the placeholder token and weak default password with strong random values
OPENCLAW_CONFIG="/home/clawshield/.openclaw/openclaw.json"

# SECURITY: Generate a strong random password for the gateway auth
# This prevents the hardcoded placeholder from being used in any deployment
GATEWAY_AUTH_PASSWORD=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

if [ -f "$OPENCLAW_CONFIG" ]; then
  # Use jq if available, fallback to sed
  if command -v jq >/dev/null 2>&1; then
    jq --arg token "$GATEWAY_AUTH_TOKEN" --arg password "$GATEWAY_AUTH_PASSWORD" \
      '.gateway.auth.token = $token | .gateway.auth.password = $password' \
      "$OPENCLAW_CONFIG" > "${OPENCLAW_CONFIG}.tmp" && \
      mv "${OPENCLAW_CONFIG}.tmp" "$OPENCLAW_CONFIG"
  else
    sed -i "s/\"token\": \"clawshield\"/\"token\": \"${GATEWAY_AUTH_TOKEN}\"/" "$OPENCLAW_CONFIG"
    sed -i "s/\"password\": \"REPLACE_WITH_STRONG_PASSWORD\"/\"password\": \"${GATEWAY_AUTH_PASSWORD}\"/" "$OPENCLAW_CONFIG"
  fi
fi

# --- Patch OpenClaw gateway for WS auth bypass ---
# Problem: dangerouslyDisableDeviceAuth only skips secure context check, not actual
# WS auth. Control UI JS doesn't send password when SubtleCrypto unavailable (HTTP).
# Fix: Add allowControlUiBypass to both device and auth checks.
echo "Applying WS auth bypass patches..."
for f in /usr/local/lib/node_modules/openclaw/dist/gateway-cli-*.js; do
  [ -f "$f" ] || continue
  sed -i 's/const canSkipDevice = sharedAuthOk;/const canSkipDevice = sharedAuthOk || allowControlUiBypass;/' "$f"
  sed -i 's/if (!authOk) {/if (!authOk \&\& !allowControlUiBypass) {/' "$f"
done
echo "Patches applied."

# --- Patch Control UI branding ---
# Replace OpenClaw brand text with ClawShield in the Control UI JS
echo "Applying branding patches..."
CS_SVG_URI='data:image/svg+xml,%3Csvg viewBox='"'"'0 0 36 36'"'"' xmlns='"'"'http://www.w3.org/2000/svg'"'"'%3E%3Ccircle cx='"'"'18'"'"' cy='"'"'18'"'"' r='"'"'16'"'"' fill='"'"'%230d1a2f'"'"' stroke='"'"'%2300d4ff'"'"' stroke-width='"'"'2'"'"'/%3E%3Cpath d='"'"'M18 8 L12 16 L14 16 L10 26 L20 18 L17 18 L22 10 Z'"'"' fill='"'"'%2300d4ff'"'"'/%3E%3C/svg%3E'
for f in /usr/local/lib/node_modules/openclaw/dist/control-ui/assets/index-*.js; do
  [ -f "$f" ] || continue
  # Replace brand title text
  sed -i 's/>OPENCLAW</>CLAWSHIELD</' "$f"
  # Replace brand subtitle text
  sed -i 's/>Gateway Dashboard</>AI Security Gateway</' "$f"
  # Replace favicon.svg references with ClawShield SVG data URI
  sed -i 's|/favicon.svg|'"$CS_SVG_URI"'|g' "$f"
  # The JS template prepends base path: ${p}data:... → broken URL.
  # Remove the ${p} prefix before data: URIs so they work as absolute data URIs.
  sed -i 's|\${p}data:|data:|g' "$f"
  # Replace alt text
  sed -i 's|alt="OpenClaw"|alt="ClawShield"|g' "$f"
done
# Also replace the default favicon.svg file itself
cat > /usr/local/lib/node_modules/openclaw/dist/control-ui/favicon.svg << 'SVGEOF'
<svg viewBox="0 0 36 36" xmlns="http://www.w3.org/2000/svg">
  <circle cx="18" cy="18" r="16" fill="#0d1a2f" stroke="#00d4ff" stroke-width="2"/>
  <path d="M18 8 L12 16 L14 16 L10 26 L20 18 L17 18 L22 10 Z" fill="#00d4ff"/>
</svg>
SVGEOF
echo "Branding patches applied."

# --- Ensure writable directories exist with correct permissions ---
for dir in workspace devices sessions canvas cron skills; do
  mkdir -p "/home/clawshield/.openclaw/$dir"
done
# Per-agent workspace directories with AGENTS.md bootstrap file
for agent in main anvil harbor shield beacon lens; do
  mkdir -p "/home/clawshield/.openclaw/workspace-${agent}"
  if [ ! -f "/home/clawshield/.openclaw/workspace-${agent}/AGENTS.md" ]; then
    cat > "/home/clawshield/.openclaw/workspace-${agent}/AGENTS.md" << EOF
# ${agent} — Workspace

Agent workspace files for **${agent}**.
EOF
  fi
done

# --- Populate agents volume on first run ---
# The agents directory is a Docker volume so it's writable at runtime (OpenClaw
# writes sessions, vectorstore, etc. inside each agent dir). On first run,
# copy baked-in agent configs from /opt/agents-seed/ into the volume.
if [ -d /opt/agents-seed ] && [ ! -f /home/clawshield/.openclaw/agents/.seeded ]; then
  echo "Seeding agents volume from image..."
  cp -rn /opt/agents-seed/* /home/clawshield/.openclaw/agents/ 2>/dev/null || true
  touch /home/clawshield/.openclaw/agents/.seeded
fi
# Ensure every agent has a sessions directory (OpenClaw needs these writable)
for agent in main anvil harbor shield beacon lens; do
  mkdir -p "/home/clawshield/.openclaw/agents/${agent}/sessions"
done

chown -R clawshield:clawshield /home/clawshield/.openclaw 2>/dev/null || true
chown -R clawshield:clawshield /var/lib/clawshield 2>/dev/null || true

# --- Start OpenClaw gateway in background on loopback :18790 ---
echo "Starting OpenClaw gateway on :18790..."
export ANTHROPIC_API_KEY
su -s /bin/sh clawshield -c "cd /home/clawshield/.openclaw && ANTHROPIC_API_KEY='${ANTHROPIC_API_KEY}' node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway" &
GW_PID=$!

# Wait for gateway to be ready (up to 30s)
echo "Waiting for gateway health check..."
TRIES=0
while [ $TRIES -lt 60 ]; do
  if wget -qO- http://127.0.0.1:18790/health >/dev/null 2>&1; then
    echo "Gateway ready."
    break
  fi
  # Check if gateway process died
  if ! kill -0 $GW_PID 2>/dev/null; then
    echo "ERROR: Gateway process exited unexpectedly"
    exit 1
  fi
  TRIES=$((TRIES + 1))
  sleep 0.5
done
if [ $TRIES -ge 60 ]; then
  echo "WARNING: Gateway health check timed out after 30s, starting proxy anyway."
fi

# --- Graceful shutdown ---
cleanup() {
  echo "Shutting down..."
  kill $GW_PID 2>/dev/null || true
  wait $GW_PID 2>/dev/null || true
  exit 0
}
trap cleanup TERM INT

# --- Monitor gateway process ---
# If gateway dies, restart it in background
monitor_gateway() {
  while true; do
    wait $GW_PID 2>/dev/null
    EXIT_CODE=$?
    # If we got here from a signal (cleanup), just exit
    if [ $EXIT_CODE -eq 0 ]; then
      break
    fi
    echo "WARNING: Gateway exited with code $EXIT_CODE, restarting in 2s..."
    sleep 2
    su -s /bin/sh clawshield -c "cd /home/clawshield/.openclaw && ANTHROPIC_API_KEY='${ANTHROPIC_API_KEY}' node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway" &
    GW_PID=$!
  done
}
monitor_gateway &

# --- Start ClawShield proxy in standalone mode (foreground) ---
echo "Starting ClawShield proxy on :18789..."
exec /usr/local/bin/clawshield-proxy \
  --standalone \
  --policy /etc/clawshield/policy.yaml \
  --gateway-url http://127.0.0.1:18790 \
  --gateway-token "$GATEWAY_AUTH_TOKEN" \
  --listen :18789 \
  --audit-db /var/lib/clawshield/audit.db
