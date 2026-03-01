# ClawShield + OpenClaw Turnkey Docker Image
# Usage:
#   docker build -t sleuthco/clawshield-openclaw .
#   docker run -d -p 18789:18789 -e ANTHROPIC_API_KEY=sk-ant-... sleuthco/clawshield-openclaw

# Stage 1: Install OpenClaw
FROM node:22-slim AS openclaw
RUN npm install -g openclaw@2026.2.9

# Stage 2: Build Go binaries
FROM golang:1.24-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /clawshield-proxy ./proxy/cmd/clawshield-proxy/
RUN CGO_ENABLED=0 go build -o /clawshield-setup ./proxy/cmd/clawshield-setup/

# Stage 3: Runtime image
FROM node:22-slim

# Copy OpenClaw from stage 1
COPY --from=openclaw /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=openclaw /usr/local/bin/openclaw /usr/local/bin/openclaw

# Copy ClawShield binaries from stage 2
COPY --from=builder /clawshield-proxy /usr/local/bin/clawshield-proxy
COPY --from=builder /clawshield-setup /usr/local/bin/clawshield-setup

# Copy default policy
COPY policy/examples/security_scanning.yaml /etc/clawshield/policy.yaml

# Copy entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directory for audit logs
RUN mkdir -p /var/lib/clawshield && \
    useradd -r -s /usr/sbin/nologin clawshield && \
    chown clawshield:clawshield /var/lib/clawshield

ENV CLAWSHIELD_LISTEN_PORT=18789
ENV OPENCLAW_GATEWAY_PORT=18790

EXPOSE 18789

ENTRYPOINT ["docker-entrypoint.sh"]
