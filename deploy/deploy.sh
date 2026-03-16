#!/usr/bin/env bash
# ClawShield deployment script — run from Windows (Git Bash)
# Usage: ./deploy.sh <VM_PUBLIC_IP> <ANTHROPIC_API_KEY>
set -euo pipefail

VM_IP="${1:?Usage: deploy.sh <VM_PUBLIC_IP> <ANTHROPIC_API_KEY>}"
ANTHROPIC_KEY="${2:?Usage: deploy.sh <VM_PUBLIC_IP> <ANTHROPIC_API_KEY>}"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
REMOTE_USER="deploy"
REMOTE_DIR="/opt/clawshield"
DOMAIN="${DOMAIN:-clawshield.example.com}"

ssh_cmd() {
    ssh $SSH_OPTS -i "$SSH_KEY" "${REMOTE_USER}@${VM_IP}" "$@"
}

scp_cmd() {
    scp $SSH_OPTS -i "$SSH_KEY" "$@"
}

echo "=== ClawShield Deployment to ${VM_IP} ==="

# --- Step 1: Wait for cloud-init ---
echo "[1/8] Waiting for cloud-init to complete..."
ssh_cmd "sudo cloud-init status --wait" || {
    echo "WARNING: cloud-init may not have completed cleanly"
}

# --- Step 2: Upload deployment files ---
echo "[2/8] Uploading deployment files..."
scp_cmd -r "$(dirname "$0")/" "${REMOTE_USER}@${VM_IP}:${REMOTE_DIR}/deploy/"

# Upload ClawShield source for Docker build
echo "       Uploading ClawShield source..."
CLAWSHIELD_SRC="$(dirname "$0")/.."
# Create a temporary tarball excluding .git and deploy artifacts
tar czf /tmp/clawshield-src.tar.gz \
    -C "$CLAWSHIELD_SRC" \
    --exclude='.git' \
    --exclude='deploy' \
    --exclude='dist' \
    --exclude='*.exe' \
    .
scp_cmd /tmp/clawshield-src.tar.gz "${REMOTE_USER}@${VM_IP}:/tmp/"
ssh_cmd "mkdir -p ${REMOTE_DIR}/src && tar xzf /tmp/clawshield-src.tar.gz -C ${REMOTE_DIR}/src && rm /tmp/clawshield-src.tar.gz"
rm -f /tmp/clawshield-src.tar.gz

# --- Step 3: Generate secrets and configure ---
echo "[3/8] Generating secrets and configuring..."
GATEWAY_TOKEN=$(ssh_cmd "openssl rand -hex 24")

ssh_cmd bash <<REMOTE_SCRIPT
set -euo pipefail

cd ${REMOTE_DIR}/deploy

# Create .env with real secrets
cat > .env <<EOF
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
GATEWAY_AUTH_TOKEN=${GATEWAY_TOKEN}
EOF
chmod 600 .env

# Inject gateway token into openclaw.json
sed -i "s/GATEWAY_TOKEN_PLACEHOLDER/${GATEWAY_TOKEN}/" config/openclaw.json
chmod 600 config/openclaw.json

# Fix Dockerfile.clawshield context — it builds from parent (src/)
# Copy deploy files into the right structure
cp Dockerfile.clawshield ${REMOTE_DIR}/src/deploy/Dockerfile.clawshield 2>/dev/null || true

# Lock down permissions
chmod 700 ${REMOTE_DIR}/config 2>/dev/null || true
chmod 750 ${REMOTE_DIR}
REMOTE_SCRIPT

# --- Step 4: TLS certificate ---
echo "[4/8] Obtaining TLS certificate..."
ssh_cmd bash <<REMOTE_SCRIPT
set -euo pipefail

# Create webroot for ACME challenges
sudo mkdir -p /var/lib/letsencrypt/.well-known/acme-challenge

# Check if cert already exists
if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
    echo "TLS certificate already exists, skipping certbot"
else
    # Start a temporary nginx for the ACME challenge
    sudo docker run -d --name certbot-nginx \
        -p 80:80 \
        -v /var/lib/letsencrypt:/var/lib/letsencrypt:ro \
        nginx:1.27-alpine \
        sh -c 'mkdir -p /usr/share/nginx/html/.well-known && ln -s /var/lib/letsencrypt/.well-known/acme-challenge /usr/share/nginx/html/.well-known/acme-challenge && nginx -g "daemon off;"' \
        || true

    sleep 2

    sudo certbot certonly --webroot \
        -w /var/lib/letsencrypt \
        -d "${DOMAIN}" \
        --non-interactive \
        --agree-tos \
        --email "${CERTBOT_EMAIL:-you@example.com}" \
        --no-eff-email

    sudo docker rm -f certbot-nginx 2>/dev/null || true
fi

# Copy certs to clawshield directory
sudo cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${REMOTE_DIR}/certs/fullchain.pem
sudo cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${REMOTE_DIR}/certs/privkey.pem
sudo chown deploy:deploy ${REMOTE_DIR}/certs/*.pem
chmod 600 ${REMOTE_DIR}/certs/privkey.pem
chmod 644 ${REMOTE_DIR}/certs/fullchain.pem

# Set up certbot auto-renewal hook to copy new certs
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/copy-certs.sh > /dev/null <<'HOOK'
#!/bin/bash
cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${REMOTE_DIR}/certs/fullchain.pem
cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${REMOTE_DIR}/certs/privkey.pem
chown deploy:deploy ${REMOTE_DIR}/certs/*.pem
docker exec clawshield-nginx nginx -s reload 2>/dev/null || true
HOOK
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/copy-certs.sh
REMOTE_SCRIPT

# --- Step 5: Build containers ---
echo "[5/8] Building Docker containers..."
ssh_cmd bash <<REMOTE_SCRIPT
set -euo pipefail
cd ${REMOTE_DIR}/deploy

# Set build context to uploaded source
export CLAWSHIELD_SRC_DIR=${REMOTE_DIR}/src
export CLAWSHIELD_DOCKERFILE=deploy/Dockerfile.clawshield

# Copy Dockerfile into expected location
mkdir -p ${REMOTE_DIR}/src/deploy
cp ${REMOTE_DIR}/deploy/Dockerfile.clawshield ${REMOTE_DIR}/src/deploy/

docker compose build --no-cache
REMOTE_SCRIPT

# --- Step 6: Start services ---
echo "[6/8] Starting services..."
ssh_cmd bash <<REMOTE_SCRIPT
set -euo pipefail
cd ${REMOTE_DIR}/deploy
docker compose up -d

echo "Waiting for containers to become healthy..."
for i in \$(seq 1 60); do
    HEALTHY=\$(docker compose ps --format json | grep -c '"healthy"' || true)
    if [ "\$HEALTHY" -ge 3 ]; then
        echo "All 3 containers healthy."
        break
    fi
    if [ "\$i" -eq 60 ]; then
        echo "WARNING: Not all containers healthy after 60s"
        docker compose ps
        docker compose logs --tail=20
    fi
    sleep 1
done

docker compose ps
REMOTE_SCRIPT

# --- Step 7: Deploy logging infrastructure ---
echo "[7/8] Deploying logging infrastructure..."

# Source was already uploaded to ${REMOTE_DIR}/src in step 2
# logging-setup.sh uses REPO_ROOT which is two dirs up from SCRIPT_DIR
ssh_cmd "sudo bash ${REMOTE_DIR}/src/logging/oci/logging-setup.sh"

# --- Step 8: Smoke tests ---
echo "[8/8] Running smoke tests..."
scp_cmd "$(dirname "$0")/smoke-test.sh" "${REMOTE_USER}@${VM_IP}:/tmp/smoke-test.sh"
ssh_cmd "chmod +x /tmp/smoke-test.sh && /tmp/smoke-test.sh ${DOMAIN}"

echo ""
echo "=== Deployment complete ==="
echo "URL: https://${DOMAIN}"
echo "Gateway token: ${GATEWAY_TOKEN}"
echo ""
echo "Next steps:"
echo "  1. Add DNS A record: ${DOMAIN} → ${VM_IP}"
echo "  2. Run SSL Labs test: https://www.ssllabs.com/ssltest/analyze.html?d=${DOMAIN}"
echo "  3. Share URL with pen testers"
