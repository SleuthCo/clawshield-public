---
framework: "Secrets Management"
version: "1.0"
domain: "Security"
agent: "friday"
tags: ["secrets", "vault", "gitleaks", "environment-variables", "secret-rotation", "zero-trust"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Secrets Management

## Secrets in Code Detection

Hardcoded secrets in source code are one of the most common security vulnerabilities. Secrets include API keys, database passwords, private keys, tokens, connection strings, and encryption keys.

**Why secrets in code are dangerous:**

- Source code is widely shared (team members, contractors, open-source).
- Version control retains secrets forever (even after deletion from the working tree).
- CI/CD logs may expose secrets from code.
- Attackers specifically scan public repositories for leaked credentials.

**Detection tools:**

### Gitleaks

Gitleaks scans Git repositories for hardcoded secrets using regex patterns and entropy analysis.

```bash
# Scan the current repo
gitleaks detect --source . --verbose

# Scan in CI (only new commits)
gitleaks detect --source . --log-opts="origin/main..HEAD"

# Configuration file (.gitleaks.toml)
```

```toml
# .gitleaks.toml
title = "Custom Gitleaks Config"

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]'''
tags = ["api", "key"]

[allowlist]
paths = [
    '''\.gitleaks\.toml$''',
    '''test/fixtures/''',
    '''docs/examples/''',
]
```

### TruffleHog

TruffleHog uses regex patterns, entropy detection, and verified credential checking (actually tests whether leaked credentials are valid).

```bash
# Scan a Git repo
trufflehog git file://. --since-commit HEAD~10

# Scan a GitHub org
trufflehog github --org=myorg

# Scan filesystem
trufflehog filesystem --directory=/path/to/code
```

**Pre-commit hooks:** Prevent secrets from being committed in the first place.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

**Incident response for leaked secrets:**

1. **Revoke immediately.** Do not wait. Rotate the credential before anything else.
2. **Assess impact.** Check access logs for the compromised credential.
3. **Remove from Git history** using `git filter-branch`, `BFG Repo-Cleaner`, or `git filter-repo`. Note: if the repo was public, assume the secret was captured.
4. **Audit.** Determine how the secret was committed and improve preventive controls.

## Vault Patterns

### HashiCorp Vault

Vault centralizes secret storage, provides dynamic secrets, encryption as a service, and identity-based access control.

**Key concepts:**

- **Secrets engines:** Mount points for different secret types. KV (static secrets), AWS (dynamic IAM credentials), database (dynamic DB credentials), PKI (certificates), Transit (encryption as a service).
- **Auth methods:** How clients authenticate to Vault. AppRole (for applications), Kubernetes (service account), OIDC/JWT, AWS IAM, TLS certificates.
- **Policies:** Define what secrets a client can access. Written in HCL. Follow least privilege.
- **Leases:** Dynamic secrets have a lease (TTL). When the lease expires, the secret is revoked. Clients must renew leases before expiration.

**Static secrets (KV v2):**

```bash
# Store a secret
vault kv put secret/myapp/database \
  username=appuser \
  password=supersecret

# Read a secret
vault kv get secret/myapp/database

# Versioned: access previous versions
vault kv get -version=1 secret/myapp/database
```

**Dynamic database credentials:**

```bash
# Configure database secrets engine
vault write database/config/mydb \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@db:5432/mydb" \
  allowed_roles="readonly,readwrite" \
  username="vault_admin" \
  password="vault_admin_password"

# Create a role
vault write database/roles/readonly \
  db_name=mydb \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# Get dynamic credentials (unique per request, auto-revoked on TTL)
vault read database/creds/readonly
# Returns: username=v-app-readonly-xyz, password=randompassword, lease_duration=1h
```

**Application integration pattern:**

```typescript
import Vault from "node-vault";

const vault = Vault({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN, // or use AppRole auth
});

async function getDatabaseConfig(): Promise<DatabaseConfig> {
  const result = await vault.read("secret/data/myapp/database");
  return {
    host: result.data.data.host,
    username: result.data.data.username,
    password: result.data.data.password,
  };
}

// With dynamic credentials and lease renewal
async function getDynamicCredentials(): Promise<Credentials> {
  const result = await vault.read("database/creds/readonly");
  const leaseId = result.lease_id;

  // Renew lease periodically
  setInterval(async () => {
    await vault.renew(leaseId);
  }, (result.lease_duration / 2) * 1000);

  return {
    username: result.data.username,
    password: result.data.password,
  };
}
```

### AWS Secrets Manager

AWS-native secret storage with automatic rotation, fine-grained IAM access control, and integration with AWS services.

```python
import boto3
import json

def get_secret(secret_name: str) -> dict:
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])

# In application startup
db_config = get_secret("production/myapp/database")
connection_string = (
    f"postgresql://{db_config['username']}:{db_config['password']}"
    f"@{db_config['host']}:{db_config['port']}/{db_config['dbname']}"
)
```

**Automatic rotation:** AWS Secrets Manager can automatically rotate secrets using a Lambda function. It supports native rotation for RDS, Redshift, and DocumentDB.

### Other Vault Solutions

- **Azure Key Vault:** Azure-native. Integrates with Azure AD for access control. Supports secrets, keys, and certificates.
- **Google Secret Manager:** GCP-native. IAM-based access. Automatic replication across regions.
- **CyberArk Conjur:** Open-source, designed for DevOps. Role-based access to secrets.

## Environment Variables

Environment variables are the most common way to inject secrets into applications. They are better than hardcoding but have limitations.

**Best practices:**

- Never log environment variables. Filter them from error reports and stack traces.
- Use `.env` files only in development. Never commit `.env` files to Git. Add `.env` to `.gitignore`.
- In production, inject environment variables through the orchestrator (Kubernetes Secrets, ECS task definitions, Docker Compose) or a secrets manager.
- Validate that required environment variables are present at startup. Fail fast with a clear error message if a required secret is missing.

```typescript
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`);
  }
  return value;
}

const config = {
  databaseUrl: requireEnv("DATABASE_URL"),
  apiKey: requireEnv("API_KEY"),
  jwtSecret: requireEnv("JWT_SECRET"),
};
```

**Limitations of environment variables:**

- Visible in process listings (`/proc/PID/environ` on Linux).
- Inherited by child processes (may leak to subprocesses).
- Logged by some orchestrators during crashes or debugging.
- No access control: any code running in the process can read all environment variables.
- No rotation support: changing a secret requires restarting the application.

**Prefer Vault or Secrets Manager over environment variables** for secrets that need rotation, audit logging, or fine-grained access control.

## Secret Rotation

Secret rotation changes credentials periodically to limit the exposure window if a secret is compromised.

**Rotation strategies:**

**Dual-credential rotation:** Issue a new credential while the old one is still valid. Update the consumer to use the new credential. Revoke the old credential. This ensures zero downtime.

```
1. Secret v1 active, v2 created
2. Both v1 and v2 valid (overlap period)
3. Application updated to use v2
4. v1 revoked
```

**Dynamic credentials (recommended):** Use a secrets engine (Vault, AWS Secrets Manager) to issue short-lived credentials on demand. Each request gets a unique credential with a short TTL. No rotation needed because credentials expire automatically.

**Automated rotation with AWS Secrets Manager:**

```python
# Lambda rotation function (simplified)
def lambda_handler(event, context):
    step = event["Step"]
    secret_id = event["SecretId"]

    if step == "createSecret":
        # Generate new credentials
        new_password = generate_password()
        client.put_secret_value(
            SecretId=secret_id,
            ClientRequestToken=event["ClientRequestToken"],
            SecretString=json.dumps({"password": new_password}),
            VersionStages=["AWSPENDING"],
        )

    elif step == "setSecret":
        # Update the resource (e.g., database) with the new credentials
        pending = get_secret_version(secret_id, "AWSPENDING")
        update_database_password(pending["password"])

    elif step == "testSecret":
        # Verify the new credentials work
        pending = get_secret_version(secret_id, "AWSPENDING")
        test_database_connection(pending["password"])

    elif step == "finishSecret":
        # Mark the new version as current
        client.update_secret_version_stage(
            SecretId=secret_id,
            VersionStage="AWSCURRENT",
            MoveToVersionId=event["ClientRequestToken"],
        )
```

**Rotation frequency guidelines:**

- Database passwords: 30-90 days, or use dynamic credentials.
- API keys: 90 days, or per-session.
- TLS certificates: 90 days (Let's Encrypt default), or shorter with automated renewal.
- SSH keys: 90-180 days.
- Service account tokens: 1-24 hours (short-lived, automated).

## Zero-Trust Secrets

Zero-trust security assumes no implicit trust. Every access request is verified, regardless of network location.

**Zero-trust principles for secrets:**

1. **Verify every request:** Authenticate and authorize every secret access. No permanent access grants.
2. **Least privilege:** Grant access to only the specific secrets needed for a specific purpose.
3. **Short-lived credentials:** Issue credentials with short TTLs. Require re-authentication for renewal.
4. **Audit everything:** Log every secret read, write, and renewal. Alert on anomalous access patterns.
5. **Encrypt in transit and at rest:** Secrets are encrypted in the vault and transmitted over TLS.

**Workload identity for secret access:**

- **Kubernetes:** Use service account tokens and Vault's Kubernetes auth method. Each pod authenticates with its service account and receives only the secrets its role allows.
- **AWS:** Use IAM roles for EC2/ECS/Lambda. No static credentials. The runtime environment provides temporary credentials through the metadata service.
- **GCP:** Use workload identity for GKE. Map Kubernetes service accounts to GCP service accounts.

**Secret access audit:**

```json
{
  "timestamp": "2024-03-15T10:30:00Z",
  "action": "secret.read",
  "path": "secret/data/production/database",
  "identity": "kubernetes/production/order-service",
  "source_ip": "10.0.1.42",
  "success": true,
  "lease_id": "database/creds/readonly/abc123",
  "lease_ttl": 3600
}
```

Monitor for:
- Access from unexpected identities.
- Access to secrets outside a service's normal scope.
- Unusual access volume (potential exfiltration).
- Failed authentication attempts.
- Secret access from unusual IP addresses or networks.

## Secret Sprawl Prevention

Secret sprawl occurs when secrets are duplicated across multiple systems, configuration files, and environments without centralized management.

**Prevention strategies:**

- **Centralize:** Use a single secrets manager as the source of truth. Applications fetch secrets at runtime rather than having them injected through multiple configuration paths.
- **Reference, do not copy:** Store a reference to the secret (e.g., Vault path, Secrets Manager ARN) in configuration, not the secret value itself.
- **Inventory:** Maintain an inventory of all secrets, their owners, consumers, and rotation schedules.
- **Expire unused secrets:** Regularly audit which secrets are actually being accessed. Revoke secrets that have not been accessed in 90 days.
- **Automate provisioning:** When a new service is deployed, automatically create its secrets, assign permissions, and configure rotation. Manual secret creation leads to inconsistency and drift.
