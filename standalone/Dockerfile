# ClawShield Standalone — Single container with OpenClaw gateway + ClawShield proxy
# Usage: docker compose up (set ANTHROPIC_API_KEY in .env)

# Stage 1: Install OpenClaw + skills
FROM node:22-slim AS openclaw
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates python3 make g++ && \
    rm -rf /var/lib/apt/lists/*
# Rewrite SSH git URLs to HTTPS (openclaw dep whiskeysockets/libsignal-node uses ssh://)
ENV GIT_CONFIG_COUNT=2 \
    GIT_CONFIG_KEY_0=url.https://github.com/.insteadOf \
    GIT_CONFIG_VALUE_0=ssh://git@github.com/ \
    GIT_CONFIG_KEY_1=url.https://github.com/.insteadOf \
    GIT_CONFIG_VALUE_1=git@github.com:
RUN npm install -g openclaw@2026.2.9 && npm cache clean --force

# Stage 2: Build ClawShield proxy
FROM golang:1.24-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o clawshield-proxy ./proxy/cmd/clawshield-proxy/

# Stage 3: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget libsqlite3-0 curl jq && \
    rm -rf /var/lib/apt/lists/*

# Copy Node.js runtime from openclaw stage
COPY --from=openclaw /usr/local/bin/node /usr/local/bin/node
COPY --from=openclaw /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/openclaw/dist/gateway-cli-esm.mjs /usr/local/bin/openclaw || \
    ln -s ../lib/node_modules/openclaw/bin/openclaw.js /usr/local/bin/openclaw
# Make npx available for skill installs at runtime
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx 2>/dev/null || true
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm 2>/dev/null || true
RUN chmod +x /usr/local/bin/node

# Copy ClawShield binary
COPY --from=builder /build/clawshield-proxy /usr/local/bin/clawshield-proxy

# Create non-root user
RUN groupadd -r clawshield && useradd -r -g clawshield -m -d /home/clawshield clawshield

# Create directories — all writable dirs OpenClaw needs at runtime
RUN mkdir -p /etc/clawshield /var/lib/clawshield \
    /home/clawshield/.openclaw \
    /home/clawshield/.openclaw/workspace \
    /home/clawshield/.openclaw/devices \
    /home/clawshield/.openclaw/sessions \
    /home/clawshield/.openclaw/canvas \
    /home/clawshield/.openclaw/cron \
    /home/clawshield/.openclaw/skills && \
    chown -R clawshield:clawshield /var/lib/clawshield /home/clawshield

# Copy configuration
COPY standalone/config/policy.yaml /etc/clawshield/policy.yaml
COPY standalone/config/openclaw.json /home/clawshield/.openclaw/openclaw.json

# Copy agents to seed directory — entrypoint copies into writable volume on first run
COPY standalone/agents/ /opt/agents-seed/
RUN mkdir -p /home/clawshield/.openclaw/agents

# Copy entrypoint (strip Windows CRLF line endings)
COPY standalone/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 18789

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:18789/api/v1/status || exit 1

ENTRYPOINT ["/bin/sh", "/usr/local/bin/docker-entrypoint.sh"]
