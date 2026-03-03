# ClawShield Fleet Management: Security Hardening Guide

This guide provides security hardening recommendations for production deployments of the ClawShield Enterprise Fleet Management system.

---

## Production Requirements

### Transport Security

#### HTTPS/TLS Everywhere

- **Requirement**: Deploy the Hub behind a TLS-terminating reverse proxy
- **Recommended Proxies**: nginx, HAProxy, AWS ALB, or similar
- **Minimum TLS Version**: TLS 1.2 (TLS 1.3 preferred)
- **Cipher Suites**: Use only strong ciphers (AES-GCM preferred, no RC4, DES, or MD5)

#### Configuration Example (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name hub.clawshield.internal;

    ssl_certificate /etc/nginx/certs/hub.crt;
    ssl_certificate_key /etc/nginx/certs/hub.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    location / {
        proxy_pass http://localhost:18800;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name hub.clawshield.internal;
    return 301 https://$server_name$request_uri;
}
```

#### mTLS for Agent-to-Hub Communication

For additional security, enable mutual TLS (mTLS) between agents and the Hub:

1. **Hub-side**: Reverse proxy validates agent certificates
2. **Agent-side**: Issues agent certificates during enrollment process
3. **Certificate Pinning** (Optional): Agent can pin the Hub's certificate for additional security

```nginx
server {
    listen 443 ssl http2;
    
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_client_certificate /etc/nginx/certs/agent-ca.crt;
    ssl_trusted_certificate /etc/nginx/certs/agent-ca.crt;
    
    # Handle certificate verification failures
    error_page 495 = @error_cert_required;
    location @error_cert_required {
        default_type application/json;
        return 403 '{"error": "client certificate required"}';
    }
}
```

#### Never Expose Hub Directly

- ❌ Do NOT expose the Hub on the public internet
- ❌ Do NOT expose the Hub without authentication/authorization
- ✅ Always use a reverse proxy with TLS termination
- ✅ Always run the Hub in a private network segment

---

### Authentication (Required - Not Built-In)

**IMPORTANT**: The Hub API has **NO built-in authentication**. This is by design — authentication is deployment-specific and should be implemented by the deployer using industry-standard solutions.

#### Why Authentication Is Required

- All Hub API endpoints accept unauthenticated requests by design
- The Hub is intended to run in a trusted network environment
- Authentication must be enforced at the network/proxy layer, not in the application

#### Authentication Options

##### Option 1: API Gateway with OAuth2/OIDC (Recommended)

**Best for**: Enterprise environments with existing identity infrastructure.

Use an API gateway (e.g., AWS API Gateway, Okta, Apigee) that:
- Validates OAuth2 access tokens or OIDC ID tokens
- Supports role-based access control (RBAC)
- Rate limits and throttles requests
- Provides audit logging

```nginx
# Using nginx with external OAuth2 validation
location /api/v1/ {
    auth_request /oauth2/check_token;
    auth_request_set $user $upstream_http_x_oauth_user;
    auth_request_set $user_id $upstream_http_x_oauth_user_id;
    
    proxy_set_header X-OAuth-User $user;
    proxy_set_header X-OAuth-User-Id $user_id;
    proxy_pass http://localhost:18800;
}

location /oauth2/check_token {
    internal;
    proxy_pass http://oauth2-server/validate;
}
```

##### Option 2: mTLS Client Certificates (Strong Security)

**Best for**: Machine-to-machine or strongly authenticated environments.

Issue client certificates to authorized administrators and automation tools:

```bash
# Generate CA for client certificates
openssl genrsa -out client-ca.key 4096
openssl req -new -x509 -days 3650 -key client-ca.key -out client-ca.crt

# Issue client certificate for admin
openssl genrsa -out admin-client.key 2048
openssl req -new -key admin-client.key -out admin-client.csr
openssl x509 -req -in admin-client.csr -CA client-ca.crt -CAkey client-ca.key \
  -CAcreateserial -out admin-client.crt -days 365 -sha256
```

Configure nginx to require client certificates:

```nginx
ssl_verify_client on;
ssl_client_certificate /etc/nginx/certs/client-ca.crt;
error_page 495 = @forbidden;
location @forbidden {
    return 403;
}
```

##### Option 3: Reverse Proxy with API Key Validation

**Best for**: Simpler deployments with fewer integration points.

Implement API key validation in nginx or use a lightweight auth proxy:

```nginx
location /api/v1/ {
    if ($http_x_api_key != "secret-key-12345") {
        return 401;
    }
    proxy_pass http://localhost:18800;
}
```

**Security Note**: API keys should be:
- Stored in environment variables or secure vaults (not in code)
- Rotated regularly (at least quarterly)
- Never transmitted over unencrypted channels

### Agent Authentication

#### Enrollment Authentication

Agents use **enrollment tokens** for initial registration with the Hub:

- **Single-use**: Token is consumed on first agent enrollment
- **Format**: Cryptographically secure random string (minimum 32 bytes)
- **Generation**: Created by administrator via Hub API
- **Transmission**: Should be transmitted over secure, out-of-band channels

**Secure Enrollment Flow**:

```
1. Administrator generates enrollment token
2. Token is transmitted securely (not via email or Slack)
3. Agent uses token to enroll with Hub
4. Hub validates token and issues agent_id
5. Token is invalidated and cannot be reused
6. Subsequent check-ins use agent_id (no token needed)
```

#### Check-in Authentication

After enrollment, agents authenticate using their **agent_id**:

- **Mechanism**: Agent ID included in check-in request headers
- **Format**: UUID or similar unique identifier
- **Storage**: Stored in agent's local file system
- **Transmission**: Should be transmitted over TLS (mTLS recommended)

**Recommended**: Combine agent_id with client certificates for mTLS:

```bash
# Agent includes both agent_id and client certificate
curl -X POST https://hub.clawshield.internal/api/v1/checkin \
  --cert agent-client.crt \
  --key agent-client.key \
  --header "X-Agent-Id: 550e8400-e29b-41d4-a716-446655440000"
```

---

### Enrollment Token Security

#### Token Lifecycle

```
Created (admin)
   ↓
Issued (single-use)
   ↓
Transmitted (secure channel)
   ↓
Used by Agent (redeemed with Hub)
   ↓
Invalidated (cannot be reused)
```

#### Best Practices

1. **Generate Tokens Close to Enrollment Time**
   - Don't pre-generate tokens days in advance
   - Create token immediately before agent deployment
   - Minimize time token exists without being used

2. **Secure Transmission**
   - ❌ Never send via email, Slack, or unencrypted channels
   - ✅ Use encrypted communication (VPN, secure file transfer)
   - ✅ Use SSH or other authenticated channels
   - ✅ Transmit only when agent is ready to start

3. **Logging and Auditing**
   - Log all token generation events with timestamp and requesting user
   - Do NOT log the actual token value
   - Log token consumption (agent enrollment)
   - Alert if token is generated but not used within expected timeframe

4. **Token Expiration** (Future Enhancement)
   - Currently: Tokens remain valid indefinitely until consumed or admin revocation
   - Planned: Time-limited tokens (e.g., 1 hour expiration)
   - Until implemented: Manually revoke unused tokens

#### Token Revocation

Revoke tokens that are no longer needed:

```bash
POST /api/v1/enroll/{token}/revoke

# This invalidates the token, preventing agent enrollment
```

---

### Key Management

#### Encryption Key Storage

**Critical**: Do NOT store raw encryption key material in the Hub database.

#### Recommended: KMS Integration

Use a Key Management Service (KMS) for all encryption keys:

**Supported KMS Solutions**:
- AWS Key Management Service (KMS)
- HashiCorp Vault
- Azure Key Vault
- Google Cloud KMS
- Hardware Security Modules (HSM)

**Architecture**:

```
ClawShield Hub         KMS (HSM, Vault, AWS KMS, etc.)
     │                          │
     ├─ Key Reference ──────────┤
     │  (key-id, version)       │
     │                          │
     └─ Wrap/Unwrap requests ──→ Perform crypto
                                │ Keep raw keys secure
                                │
                           Encryption/Decryption
                           happens in KMS only
```

**Implementation**:

1. **Store Only Key References in Hub Database**
   - Store key_id, key_version, key_alias
   - Never store raw key material

2. **Use KMS Wrapping API**
   - All encrypt/decrypt operations call KMS
   - Raw key material never leaves KMS

3. **Audit All KMS Operations**
   - Log all key access requests
   - Monitor for unusual patterns
   - Alert on failed decryption attempts

#### Key Rotation

**Minimum Rotation Frequency**: Quarterly (every 90 days)

**Rotation Process**:

```
1. Generate new key in KMS
2. Update Hub config to reference new key_id
3. Agents receive new key during check-in
4. Agents begin using new key for encryption
5. Old key remains available for decryption (transition period)
6. After transition period (30-60 days), revoke old key
```

**Monitoring During Rotation**:

```bash
GET /api/v1/keys/{id}

Response includes:
{
  "key_id": "prod-key-2024-q1",
  "status": "active",
  "rotation_status": "in_progress",
  "rotation_deadline": "2024-03-15",
  "agents_migrated": 985,
  "agents_pending": 15
}
```

#### Key Material Security

- **Never Return Raw Keys**: Key material is returned only once on initial creation
  - Instruct administrators to store it in secure vault immediately
  - Provide no method to retrieve key material again

- **No Key Logs**: Key material must never appear in logs or debug output
  - Sanitize log output
  - Use secure string types that overwrite memory

- **Secure Transport**: When distributing keys to agents
  - Always use TLS
  - Verify agent identity (mTLS recommended)
  - Consider additional encryption layer (wrap key before transmission)

#### Key Destruction

- **Revoked Keys**: Mark as revoked, don't delete immediately
- **Retention**: Keep revoked keys for minimum 1 year for forensics
- **Secure Deletion**: When purging keys, use cryptographic erasure (overwrite memory/disk)
- **Backup Keys**: Backup key encryption keys separately with secure key escrow

---

### Policy Signing

#### Enable Mandatory Policy Signing

In production, always enable RSA-SHA256 policy signing:

```bash
./clawshield-hub \
  --listen :18800 \
  --db hub.db \
  --policy-signing-key /etc/clawshield/policy-key.pem \
  --policy-signing-key-bits 4096
```

#### Key Management

**Generate Signing Key Pair**:

```bash
# Generate 4096-bit RSA key pair
openssl genrsa -out policy-signing-key.pem 4096
openssl rsa -in policy-signing-key.pem -pubout -out policy-signing-key.pub

# Restrict permissions
chmod 600 policy-signing-key.pem
chmod 644 policy-signing-key.pub
```

**Key Size Requirements**:
- **Minimum**: 2048 bits (enforced by code)
- **Recommended**: 4096 bits
- **Future**: 8192 bits for highest security

**Private Key Storage** (CRITICAL):

- ❌ Never store in Hub database
- ❌ Never commit to version control
- ✅ Store in HSM or KMS (recommended)
- ✅ Store in secure file system with restricted permissions (600)
- ✅ Back up to secure vault with strong encryption

**Public Key Distribution**:

- ✅ Distribute to all agents via secure channel
- ✅ Configure agents with public key during deployment
- ✅ Verify public key fingerprint before use
- Can be distributed via:
  - Agent configuration file
  - Hub API during enrollment
  - Embedded in agent binary

#### Signing Verification

**Agent-side Verification Process**:

1. Agent receives policy with signature
2. Agent extracts signature and policy content
3. Agent verifies signature using public key
4. If valid: Policy is applied
5. If invalid: Policy is rejected, logged, and reported to Hub

**Signature Bypass Prevention** (Built-in):

- Empty signatures are rejected when public key is configured
- Malformed signatures cause rejection, not silent failure
- Timing-safe comparison prevents timing attacks
- Failed verification is logged for audit

#### Signature Algorithm Details

| Property | Value |
|----------|-------|
| Algorithm | RSA-SHA256 |
| Hash Function | SHA-256 |
| Padding | PKCS#1 v1.5 |
| Minimum Key Size | 2048 bits |
| Recommended Key Size | 4096 bits |

---

### Hub Database Security

#### SQLite Limitations

The Hub uses **SQLite** for persistence:

**Suitable for**:
- Single-instance deployments
- Fleets up to ~1000 agents
- Non-mission-critical environments
- Development and testing

**Limitations**:
- No network access (file-based only)
- Single-threaded writes
- Limited to one process accessing at a time
- No built-in replication or HA

#### Migration to PostgreSQL

For larger deployments (>1000 agents) or HA requirements:

**Steps**:

1. **Set Up PostgreSQL**
   ```bash
   # Create database
   createdb clawshield_hub
   createuser clawshield_admin
   ```

2. **Migrate Schema**
   - Export SQLite schema
   - Import to PostgreSQL
   - Verify data integrity

3. **Update Hub Configuration**
   ```bash
   ./clawshield-hub \
     --listen :18800 \
     --db "postgresql://user:pass@localhost:5432/clawshield_hub"
   ```

#### Database Encryption

**At-Rest Encryption**:

1. **Disk Encryption** (Recommended)
   - Enable full-disk encryption on Hub server (LUKS, BitLocker, etc.)
   - Encrypts all files including hub.db

   ```bash
   # Linux example
   sudo cryptsetup luksFormat /dev/sdb1
   sudo cryptsetup luksOpen /dev/sdb1 clawshield_data
   sudo mkfs.ext4 /dev/mapper/clawshield_data
   sudo mount /dev/mapper/clawshield_data /var/lib/clawshield/
   ```

2. **Database-Level Encryption** (PostgreSQL)
   - Use transparent data encryption (TDE)
   - Or PostgreSQL extensions like pgcrypto

#### Database Backups

**Backup Strategy**:

1. **Regular Backups**
   - Automated daily backups
   - Minimum 30-day retention
   - Test restore procedures monthly

2. **Backup Encryption**
   - Always encrypt backups
   - Store encryption keys separately from backups
   - Consider key escrow for backup decryption

3. **Backup Locations**
   - Store in geographically separated locations
   - Use secure, encrypted storage (S3 with encryption, vault, etc.)
   - Never store on same disk as primary database

4. **Backup Example**
   ```bash
   # Full backup with encryption
   tar -czf - /var/lib/clawshield/hub.db | \
     openssl enc -aes-256-cbc -out hub.db.tar.gz.enc -k $BACKUP_KEY
   
   # Upload to secure storage
   aws s3 cp hub.db.tar.gz.enc s3://clawshield-backups/$(date +%Y-%m-%d)/
   ```

#### Access Control

- **File Permissions**: `600` for hub.db (read/write owner only)
- **Process Isolation**: Run Hub as dedicated non-root user
- **SELinux/AppArmor**: Configure mandatory access controls

---

### Network Security

#### Hub Network Isolation

**Deployment Architecture**:

```
Public Internet
     │
     ↓
┌─────────────────┐
│ Reverse Proxy   │ (TLS termination, auth)
│ (nginx/HAProxy) │
└────────┬────────┘
         │
         ↓
    ┌────────────┐
    │ Management │ (Private network)
    │ VLAN       │
    └────┬───────┘
         │
         ↓
    ┌────────────┐
    │  Hub       │ (Port 18800)
    │ Database   │
    └────────────┘
         ↑
         │
    Private Network
    (Agent network)
```

#### Firewall Rules

**Hub Server Rules**:

```
Inbound:
  - TCP 18800: From reverse proxy only (internal)
  - TCP 443: From reverse proxy (external, TLS)
  - TCP 22: From admin jump host (SSH management)

Outbound:
  - TCP 443: To KMS (if using external KMS)
  - TCP 5432: To PostgreSQL server (if using external DB)
  - DNS: To internal DNS resolvers
  - NTP: To time servers (optional)

Deny all others
```

**Agent Network Rules**:

```
Outbound:
  - TCP 443: To Hub (only required service)
  
Deny all others (including to other agents)
```

#### Network Segmentation

- **Hub Network**: Isolated management VLAN
  - Only reverse proxy can access
  - Agents cannot directly access other agent networks
  - No direct internet access from Hub (only KMS/DB if needed)

- **Agent Networks**: Per-environment isolation
  - Production agents in prod VLAN
  - Staging agents in staging VLAN
  - Development agents in dev VLAN
  - No cross-environment communication

#### Reverse Proxy Hardening

**nginx Configuration Hardening**:

```nginx
# Disable unnecessary HTTP methods
if ($request_method !~ ^(GET|POST|PUT|DELETE|PATCH)$) {
    return 405;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
location /api/v1/ {
    limit_req zone=api_limit burst=20 nodelay;
    limit_req_status 429;
}

# Request size limits
client_max_body_size 10m;

# Hide server version
server_tokens off;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Disable unnecessary headers
proxy_hide_header Server;
proxy_hide_header X-Powered-By;
```

---

## Security Controls Summary

| Control | Status | Notes |
|---------|--------|-------|
| **Input validation on all IDs** | ✅ Implemented | Alphanumeric + hyphens, max 128 characters |
| **Policy status transition enforcement** | ✅ Implemented | draft → approved → published only |
| **RSA-SHA256 policy signing** | ✅ Implemented | Cryptographic policy integrity |
| **Signature bypass prevention** | ✅ Implemented | Empty/invalid signatures rejected |
| **Key material stripping from API** | ✅ Implemented | Only returned once at creation |
| **Response size limits** | ✅ Implemented | 10MB normal, 1KB errors |
| **Timing-safe hash comparison** | ✅ Implemented | crypto/subtle for all comparisons |
| **Atomic binary updates** | ✅ Implemented | os.Rename, no TOCTOU vulnerabilities |
| **Minimum signing key size** | ✅ Implemented | 2048-bit minimum enforced |
| **Transport encryption (TLS)** | ⚠️ Deployment | Use reverse proxy with TLS 1.2+ |
| **mTLS agent-to-hub** | ⚠️ Deployment | Optional, recommended for production |
| **API authentication** | ⚠️ Deployment | Use OAuth2, mTLS, or API gateway |
| **Rate limiting** | ⚠️ Deployment | Configure in reverse proxy or API gateway |
| **Audit logging of Hub actions** | 🔲 Future | Track admin actions, policy changes, key operations |
| **Time-limited enrollment tokens** | 🔲 Future | Currently indefinite until consumed/revoked |
| **Hub HA/clustering** | 🔲 Future | Single-instance only currently |
| **Disk encryption at rest** | ⚠️ Deployment | Use OS-level full disk encryption |
| **Database backups encrypted** | ⚠️ Deployment | Encrypt backups with separate key storage |
| **KMS integration** | ⚠️ Deployment | Recommended for encryption key material |

---

## Security Incident Response

### Compromise Detection

**Signs of compromise**:
- Tamper detection alerts from agents
- Unusual policy changes or approvals
- Enrollment tokens used from unexpected sources
- High rates of policy rejection/failure
- Database corruption or unexpected data changes

### Incident Checklist

If you suspect a security incident:

1. **Immediate Actions**
   - Isolate Hub from network immediately
   - Preserve database and logs for forensics
   - Review recent policy changes and approvals
   - Check enrollment token generation logs

2. **Investigation**
   - Review audit logs for unauthorized access
   - Check for tamper alerts from agents
   - Verify database integrity
   - Review recent administrative changes

3. **Remediation**
   - Revoke compromise agent IDs
   - Invalidate suspicious enrollment tokens
   - Revoke potentially compromised signing keys
   - Force re-enrollment of affected agents
   - Publish updated policies with integrity checks

4. **Recovery**
   - Restore Hub from clean backup (verify timestamp)
   - Restart with fresh database
   - Re-enroll agents with new tokens
   - Rotate all encryption keys
   - Rotate signing key pair
   - Review and update security controls

### Communication and Disclosure

- Notify affected stakeholders
- Prepare incident report with timeline
- Follow responsible disclosure practices
- Coordinate with security team and management

---

## Deployment Checklist

Use this checklist before deploying to production:

- [ ] TLS certificates obtained and validated
- [ ] Reverse proxy configured with TLS termination
- [ ] Authentication/authorization configured (OAuth2, mTLS, or API gateway)
- [ ] Hub running as non-root dedicated user
- [ ] Database encrypted (disk or database-level)
- [ ] Regular automated backups configured
- [ ] Backup encryption and recovery tested
- [ ] Encryption keys stored in KMS or secure vault
- [ ] Policy signing keys generated and stored securely
- [ ] Policy signing enabled in Hub
- [ ] Firewall rules configured and tested
- [ ] Network segmentation verified
- [ ] Agents using mTLS or client certificates
- [ ] Enrollment token generation documented
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Security incident response plan documented
- [ ] Disaster recovery plan tested
- [ ] Security training provided to operational staff

---

## References and Further Reading

- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/pubs/NSA_Kubernetes_Hardening_Guidance.pdf)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
