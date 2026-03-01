#!/bin/bash
set -e

# Validate required env vars
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "ERROR: ANTHROPIC_API_KEY environment variable is required"
    exit 1
fi

# Generate OpenClaw config via setup CLI (skip npm install — already in image)
SETUP_ARGS=(
    --non-interactive
    --skip-install
    --anthropic-key "$ANTHROPIC_API_KEY"
    --listen-port "${CLAWSHIELD_LISTEN_PORT:-18789}"
    --gateway-port "${OPENCLAW_GATEWAY_PORT:-18790}"
)

# Optional: Slack integration
if [ -n "$SLACK_BOT_TOKEN" ]; then
    SETUP_ARGS+=(--with-slack --slack-bot-token "$SLACK_BOT_TOKEN")
    if [ -n "$SLACK_APP_TOKEN" ]; then
        SETUP_ARGS+=(--slack-app-token "$SLACK_APP_TOKEN")
    fi
fi

# Optional: Telegram integration
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
    SETUP_ARGS+=(--with-telegram --telegram-token "$TELEGRAM_BOT_TOKEN")
fi

# Optional: custom model
if [ -n "$CLAWSHIELD_MODEL" ]; then
    SETUP_ARGS+=(--model "$CLAWSHIELD_MODEL")
fi

echo "Running clawshield-setup..."
clawshield-setup "${SETUP_ARGS[@]}"

# Use custom policy if mounted, otherwise use the generated default
POLICY_PATH="${CLAWSHIELD_POLICY:-/etc/clawshield/policy.yaml}"
if [ ! -f "$POLICY_PATH" ]; then
    POLICY_PATH="$HOME/.clawshield/policy.yaml"
fi

# Start OpenClaw gateway in background (loopback only)
echo "Starting OpenClaw gateway on port ${OPENCLAW_GATEWAY_PORT:-18790}..."
cd "$HOME/.openclaw"
ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" openclaw gateway &
GATEWAY_PID=$!

# Wait for gateway to be ready
echo "Waiting for gateway startup..."
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${OPENCLAW_GATEWAY_PORT:-18790}/health" > /dev/null 2>&1; then
        echo "Gateway ready."
        break
    fi
    if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
        echo "ERROR: Gateway process died during startup"
        exit 1
    fi
    sleep 1
done

# Start ClawShield proxy in foreground
echo "Starting ClawShield proxy on port ${CLAWSHIELD_LISTEN_PORT:-18789}..."
exec clawshield-proxy \
    --policy "$POLICY_PATH" \
    --gateway-url "http://127.0.0.1:${OPENCLAW_GATEWAY_PORT:-18790}" \
    --listen ":${CLAWSHIELD_LISTEN_PORT:-18789}" \
    --audit-db /var/lib/clawshield/audit.db
