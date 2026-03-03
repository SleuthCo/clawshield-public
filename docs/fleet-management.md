# ClawShield Enterprise Fleet Management

## Overview

ClawShield provides enterprise-grade fleet management through two core components: the **Management Hub** and the **Agent**.

### Management Hub
The Hub is a centralized control plane that manages policies, encryption keys, software updates, and fleet inventory. It serves as the authoritative source for configuration and security policies across your entire fleet of ClawShield Proxies.

### Agent
The Agent runs alongside each ClawShield Proxy instance and maintains communication with the Hub. It handles policy enforcement, key distribution, software updates, and telemetry reporting. Agents operate autonomously with a hybrid communication model that combines periodic polling with push capabilities for urgent actions.

### Architecture

```
                      ┌─────────────────────┐
                      │ Management Hub      │
                      │  (Control Plane)    │
                      └──────────┬──────────┘
                                 │
                    ┌────────────┴────────────┐
                    │  Hybrid Communication  │
                    │  Pull (60s) + Push     │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
   ┌────▼────┐           ┌──────▼──────┐         ┌──────▼──────┐
   │  Agent  │           │   Agent     │         │   Agent     │
   │ +Proxy  │           │  +Proxy     │         │  +Proxy     │
   └────┬────┘           └──────┬──────┘         └──────┬──────┘
        │                       │                       │
   ┌────▼────────┐         ┌────▼────────┐       ┌────▼────────┐
   │  ClawShield │         │ ClawShield  │       │ ClawShield  │
   │   Proxy     │         │   Proxy     │       │   Proxy     │
   └─────────────┘         └─────────────┘       └─────────────┘
        Region A               Region B              Region C
```

### Communication Model

**Pull-based (Polling)**
- Agents check in with the Hub every 60 seconds (configurable)
- Agents pull new policies, encryption keys, and software updates
- Reliable for steady-state operations
- Minimal latency impact

**Push-based (Urgent Actions)**
- Hub can push urgent security actions directly to agents
- Used for emergency policy changes, key revocation, or critical security patches
- Agents respond immediately without waiting for next polling interval

---

## Getting Started

### Hub Deployment

#### Build
```bash
go build -o clawshield-hub ./hub/cmd/clawshield-hub/
```

#### Run
```bash
./clawshield-hub --listen :18800 --db hub.db
```

#### Command-line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:18800` | Listen address and port for the Hub API |
| `--db` | `hub.db` | Path to the SQLite database file |

#### Docker Deployment

Reference the existing Docker patterns in the repository. Example:

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o clawshield-hub ./hub/cmd/clawshield-hub/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/clawshield-hub /usr/local/bin/
EXPOSE 18800
ENTRYPOINT ["/usr/local/bin/clawshield-hub"]
CMD ["--listen", ":18800", "--db", "/var/lib/clawshield/hub.db"]
```

#### Health Check

Verify the Hub is running and healthy:

```bash
curl http://localhost:18800/api/v1/health
```

Expected response: `200 OK` with health status payload.

### Agent Deployment

#### Build
```bash
go build -o clawshield-agent ./agent/cmd/clawshield-agent/
```

#### Pre-deployment: Create Enrollment Token

Generate an enrollment token via the Hub API (before starting the agent):

```bash
curl -X POST http://hub:18800/api/v1/enroll \
  -H "Content-Type: application/json" \
  -d '{"group_id": "production-group"}'
```

This returns an enrollment token (single-use, consumed on first agent start).

#### Run

```bash
./clawshield-agent \
  --hub-url http://hub:18800 \
  --enrollment-token <token> \
  --proxy-url http://localhost:18789
```

#### Command-line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--hub-url` | (required) | URL of the Management Hub |
| `--enrollment-token` | (required on first start) | Single-use token for agent enrollment |
| `--proxy-url` | `http://localhost:18789` | URL where the ClawShield Proxy is running |
| `--audit-db-path` | `/var/lib/clawshield/audit.db` | Path to local audit database |
| `--checkin-interval` | `60s` | How often to poll the Hub for updates |
| `--agent-id-file` | `/var/lib/clawshield/agent-id` | Path to store the agent's unique ID |

#### Agent Enrollment Process

1. **First Start**: Agent uses the enrollment token to register with the Hub
2. **Auto-Enrollment**: Hub generates and assigns a unique `agent_id`
3. **Persistence**: Agent saves its `agent_id` to the local file specified by `--agent-id-file`
4. **Subsequent Starts**: Agent uses its stored `agent_id` for authentication (enrollment token no longer needed)

Once enrolled, the agent will automatically appear in the fleet inventory and can be assigned to policy groups and monitored.

---

## Fleet Management

### Agent Enrollment

**Step 1: Generate Enrollment Token**

An administrator generates a single-use enrollment token via the Hub API:

```bash
POST /api/v1/enroll
Content-Type: application/json

{
  "group_id": "production-group"
}
```

Response:
```json
{
  "enrollment_token": "eyJhbGc...",
  "expires_at": "2024-02-15T10:30:00Z"
}
```

**Step 2: Start Agent with Token**

Provide the enrollment token when starting the agent:

```bash
./clawshield-agent --hub-url http://hub:18800 \
  --enrollment-token eyJhbGc... \
  --proxy-url http://localhost:18789
```

**Step 3: Agent Appears in Fleet**

On successful enrollment, the agent is registered in the fleet inventory and can be queried via the Fleet API.

### Viewing Fleet

#### List All Agents

```bash
GET /api/v1/agents

Response:
{
  "agents": [
    {
      "id": "agent-001",
      "status": "healthy",
      "last_checkin": "2024-02-15T10:28:45Z",
      "hostname": "proxy-prod-1",
      "version": "1.2.0",
      "tags": ["production", "us-west-2"]
    },
    ...
  ]
}
```

#### Filter by Status

```bash
GET /api/v1/agents?status=healthy

Supported values: healthy, degraded, offline
```

#### Filter by Tag

```bash
GET /api/v1/agents?tag=production

Returns agents with the specified tag.
```

#### View Agent Details

```bash
GET /api/v1/agents/{id}

Response:
{
  "id": "agent-001",
  "status": "healthy",
  "last_checkin": "2024-02-15T10:28:45Z",
  "hostname": "proxy-prod-1",
  "version": "1.2.0",
  "tags": ["production", "us-west-2"],
  "policy_version": "v2.1",
  "last_policy_update": "2024-02-15T09:00:00Z",
  "encryption_keys": [
    {
      "id": "key-prod-001",
      "rotation_status": "active"
    }
  ]
}
```

---

## Policy Management

### Workflow

ClawShield policies follow a structured lifecycle from creation to enforcement.

**Step 1: Create a Policy Group**

Create a logical group to organize agents and assign policies:

```bash
POST /api/v1/policy-groups
Content-Type: application/json

{
  "name": "Engineering",
  "parent_group_id": "corporate-base",
  "description": "Policies for engineering team infrastructure"
}

Response:
{
  "group_id": "engineering-group",
  "name": "Engineering",
  "parent_group_id": "corporate-base"
}
```

**Step 2: Assign Agents to the Group**

Add agents to a policy group:

```bash
POST /api/v1/agents/{id}/assign-group
Content-Type: application/json

{
  "group_id": "engineering-group"
}
```

**Step 3: Create a Policy Version (Draft)**

Create a new policy in draft status:

```bash
POST /api/v1/policy-versions
Content-Type: application/json

{
  "group_id": "engineering-group",
  "name": "Engineering Policy v2.1",
  "policy_content": {
    "tls_min_version": "1.3",
    "require_client_auth": true,
    "blocked_ciphers": ["RSA"]
  }
}

Response:
{
  "policy_version_id": "pol-v2.1-eng",
  "status": "draft",
  "created_at": "2024-02-15T10:00:00Z"
}
```

**Step 4: Approve the Policy**

Transition the policy from draft to approved:

```bash
POST /api/v1/policy-versions/{id}/approve
Content-Type: application/json

{
  "approval_notes": "Reviewed and tested in staging"
}

Response:
{
  "policy_version_id": "pol-v2.1-eng",
  "status": "approved",
  "approved_at": "2024-02-15T10:15:00Z"
}
```

**Step 5: Publish the Policy**

Make the policy active across all assigned agents:

```bash
POST /api/v1/policy-versions/{id}/publish

Response:
{
  "policy_version_id": "pol-v2.1-eng",
  "status": "published",
  "published_at": "2024-02-15T10:20:00Z"
}
```

**Step 6: Agents Pick Up Changes**

Agents automatically pull the new policy on their next check-in (typically within 60 seconds). The agent verifies the policy signature before applying it.

### Policy Signing

Policies can be cryptographically signed to ensure integrity and prevent tampering.

#### Signature Algorithm
- **Algorithm**: RSA-SHA256
- **Minimum Key Size**: 2048 bits
- **Verification**: Agents verify signatures before applying policies

#### Signing Workflow

1. **Generate or Import Private Key**
   - Store the private signing key in an HSM or KMS (recommended for production)
   - Never store raw keys in the Hub database

2. **Configure Public Key on Agents**
   - Distribute the corresponding public key to agents via secure channel
   - Agents validate all incoming policies against this key

3. **Hub Signs Policies Automatically**
   - If a signing key is configured in the Hub, all policies are signed before distribution
   - Signature is included in the policy payload sent to agents

4. **Agent Verification**
   - Agent receives policy with signature
   - Agent verifies signature using public key
   - If verification fails, policy is rejected and not applied
   - If public key is configured and signature is empty/invalid, policy is rejected

#### Security Notes
- **Unsigned Policies**: When a public key is configured on an agent, unsigned policies are automatically rejected
- **Signature Bypass Prevention**: Empty or malformed signatures are not accepted as valid
- Ensures policies cannot be modified in transit or by unauthorized administrators

### Policy Groups & Inheritance

Policy groups support hierarchical inheritance, allowing you to define base policies and make them more restrictive at lower levels.

#### Hierarchy Example

```
Corporate Base Group
├── Policy: TLS 1.2+, AES-256
│
├── Engineering Group (parent: Corporate Base)
│   ├── Policy: TLS 1.3, AES-256, require mTLS
│   │
│   └── Team Alpha (parent: Engineering)
│       └── Policy: TLS 1.3, AES-256, require mTLS, block legacy protocols
│
└── Operations Group (parent: Corporate Base)
    └── Policy: TLS 1.2+, AES-256, audit all connections
```

#### Inheritance Rules

- **Child groups must be more restrictive than parents**
  - If parent requires TLS 1.2+, child cannot allow TLS 1.1
  - If parent requires AES-256, child cannot allow weaker ciphers
  - Enforcement is validated at policy approval time

- **Policy Cascading**
  - Agents assigned to a child group receive both parent and child policies
  - Child policies override parent policies for the same configuration keys

#### Defining Hierarchy

```bash
POST /api/v1/policy-groups
{
  "name": "Team Alpha",
  "parent_group_id": "engineering-group",
  "description": "Stricter policies for Team Alpha"
}
```

Validation ensures that Team Alpha's policies are more restrictive than Engineering Group's policies.

---

## Encryption Key Management

### Key Lifecycle

#### 1. Create a Key

Generate a new encryption key for a policy group:

```bash
POST /api/v1/keys
Content-Type: application/json

{
  "group_id": "production-group",
  "algorithm": "AES-256-GCM",
  "key_size": 256,
  "name": "Production Key Q1 2024"
}

Response:
{
  "key_id": "key-prod-q1-2024",
  "key_material": "0x8f7a2e9c...",
  "algorithm": "AES-256-GCM",
  "created_at": "2024-02-15T10:00:00Z",
  "status": "active"
}
```

**Important**: Key material is only returned once at creation. Store it securely immediately.

#### 2. Key Distribution to Agents

Keys are distributed to agents in the policy group automatically:

- Included in policy payloads during agent check-in
- Agents store keys in their local encrypted audit database
- Key material is never logged or exposed in audit trails

#### 3. Rotate Keys

Initiate a key rotation to introduce a new key while retiring the old one:

```bash
POST /api/v1/keys/{id}/rotate
Content-Type: application/json

{
  "new_key_id": "key-prod-q2-2024"
}

Response:
{
  "old_key_id": "key-prod-q1-2024",
  "new_key_id": "key-prod-q2-2024",
  "rotation_status": "in_progress",
  "rotation_deadline": "2024-03-15T10:00:00Z"
}
```

- Old key remains available for decryption during transition period
- Agents use new key for all new operations
- After rotation deadline, old key can be revoked

#### 4. Revoke Keys

Permanently disable a key:

```bash
POST /api/v1/keys/{id}/revoke

Response:
{
  "key_id": "key-prod-q1-2024",
  "status": "revoked",
  "revoked_at": "2024-03-15T10:00:00Z"
}
```

- Revoked keys cannot be used for new operations
- For recovery of old data, restored keys must be explicitly un-revoked by administrator
- Agents reject operations with revoked keys

### Key Storage Security

- **Hub Storage**: Do NOT store raw encryption key material in the Hub database
- **KMS Integration** (Recommended):
  - Use AWS KMS, HashiCorp Vault, or Azure Key Vault
  - Only store key references and wrapped keys in the Hub
  - Master keys remain secure in the KMS
  - Key rotation at the KMS level

- **Rotation Schedule**: Rotate keys at minimum quarterly
- **Backup**: Encrypted backups of the Hub database must be stored securely with key material in separate secure storage

---

## Software Updates

### Rollout Process

ClawShield supports staged software rollouts across your fleet with automatic rollback on failure.

#### Step 1: Publish a Release

Create a new software release:

```bash
POST /api/v1/releases
Content-Type: application/json

{
  "version": "1.3.0",
  "release_notes": "Security fixes and performance improvements",
  "binary_url": "https://releases.clawshield.io/v1.3.0/clawshield-agent",
  "binary_hash": "sha256:abc123...",
  "minimum_os_version": "ubuntu-20.04"
}

Response:
{
  "release_id": "rel-1.3.0",
  "version": "1.3.0",
  "status": "published",
  "created_at": "2024-02-15T10:00:00Z"
}
```

#### Step 2: Start a Rollout

Begin a staged rollout across agent groups:

```bash
POST /api/v1/rollouts
Content-Type: application/json

{
  "release_id": "rel-1.3.0",
  "group_id": "production-group",
  "wave_config": {
    "canary_percent": 5,
    "wave1_percent": 25,
    "wave2_percent": 50
  },
  "max_failure_rate": 5.0
}

Response:
{
  "rollout_id": "rollout-1.3.0-prod",
  "release_id": "rel-1.3.0",
  "status": "in_progress",
  "stages": [
    {
      "stage_name": "canary",
      "percent": 5,
      "status": "in_progress",
      "agents_targeted": 50,
      "agents_updated": 2
    }
  ]
}
```

#### Wave Configuration

```json
{
  "canary_percent": 5,
  "wave1_percent": 25,
  "wave2_percent": 50
}
```

- **Canary (5%)**: Initial rollout to a small percentage (5 of 1000 agents)
- **Wave 1 (25%)**: If canary succeeds, expand to 25% of fleet
- **Wave 2 (50%)**: If Wave 1 succeeds, expand to 50% of fleet
- **Wave 3 (Remainder)**: Final rollout to remaining agents

#### Step 3: Monitor Rollout

```bash
GET /api/v1/rollouts/{id}

Response:
{
  "rollout_id": "rollout-1.3.0-prod",
  "status": "in_progress",
  "overall_progress": {
    "total_agents": 1000,
    "updated": 250,
    "failed": 8,
    "pending": 742
  },
  "stages": [
    {
      "stage_name": "canary",
      "percent": 5,
      "status": "completed",
      "agents_targeted": 50,
      "agents_updated": 50,
      "agents_failed": 0,
      "completed_at": "2024-02-15T10:30:00Z"
    },
    {
      "stage_name": "wave1",
      "percent": 25,
      "status": "in_progress",
      "agents_targeted": 250,
      "agents_updated": 200,
      "agents_failed": 5,
      "failure_rate": 2.5
    }
  ]
}
```

#### Automatic Rollback

The rollout automatically rolls back if:

- **Failure rate exceeds threshold** (e.g., 5% max_failure_rate)
- **Critical error in binary** detected during early stages
- **Administrator initiates rollback**

```bash
POST /api/v1/rollouts/{id}/rollback
Content-Type: application/json

{
  "reason": "Performance regression detected"
}
```

All agents in current and completed stages revert to the previous version.

---

## Dashboard

Get a quick overview of your fleet health and security posture.

### Fleet Overview

```bash
GET /api/v1/dashboard/overview

Response:
{
  "fleet_size": 1000,
  "healthy_agents": 985,
  "degraded_agents": 10,
  "offline_agents": 5,
  "avg_checkin_latency_ms": 250,
  "policy_compliance": 98.5,
  "encryption_key_rotation_overdue": 2,
  "pending_updates": 45
}
```

### Security Summary

```bash
GET /api/v1/dashboard/security

Response:
{
  "total_policies": 12,
  "policies_in_draft": 2,
  "policies_approved_pending_publish": 1,
  "policies_active": 9,
  "encryption_keys": {
    "active": 15,
    "rotating": 3,
    "revoked": 5
  },
  "policy_violations_last_24h": 3,
  "agents_with_tampered_binaries": 0,
  "agents_with_tampered_policies": 0
}
```

---

## Integrity & Tamper Detection

ClawShield includes built-in tamper detection to verify the integrity of agent binaries and policies.

### Binary Integrity Verification

**Agent Verification Process**:

1. Agent downloads binary hash from Hub during check-in
2. Agent calculates its own current binary hash (SHA-256)
3. Agent compares calculated hash with Hub-provided expected hash
4. If hashes match, binary is verified as authentic
5. If hashes don't match, agent:
   - Does not apply the update
   - Reports tampering to Hub
   - Logs the discrepancy with full details

### Policy Integrity Verification

**Agent Verification Process**:

1. Agent receives policy from Hub (during check-in or push update)
2. Agent verifies policy signature if a public key is configured
3. Agent saves policy to local file
4. On next load, agent calculates hash of saved policy file
5. Agent compares with signed policy hash from Hub
6. If hashes match, policy is trusted
7. If hashes don't match, agent:
   - Does not apply the policy
   - Reports tampering to Hub
   - Reverts to previous known-good policy

### Tamper Detection Response

When tampering is detected, agents report to the Hub:

```
POST /api/v1/agents/{id}/report-tamper
{
  "type": "binary" | "policy",
  "expected_hash": "sha256:abc123...",
  "actual_hash": "sha256:def456...",
  "detected_at": "2024-02-15T10:28:45Z"
}
```

**Hub Actions**:
- Records tamper incident in audit log
- Alerts administrators via configured notification channels
- Can trigger automatic isolation or remediation policies
- Provides forensic evidence for investigation

### Security Implications

- **No Silent Updates**: Binaries and policies cannot be modified without Hub knowledge
- **Forensic Trail**: Every tamper incident is logged with timestamps and details
- **Automatic Detection**: Happens on every policy enforcement, not just on new deployments
- **Signature-Based**: Uses cryptographic hashing, resistant to casual modification

---

## Best Practices

1. **Enroll agents in policy groups immediately** after deployment
2. **Test policies in staging** before publishing to production groups
3. **Rotate encryption keys quarterly** or after any security incident
4. **Monitor rollouts closely** using the Dashboard API
5. **Configure policy signing** with RSA keys in production environments
6. **Use policy group hierarchies** to enforce consistent security baselines
7. **Review tamper detection alerts** promptly to identify unauthorized modifications
8. **Keep agents up-to-date** with planned, phased rollouts
9. **Backup the Hub database** regularly and store securely
10. **Isolate the Hub network** - only agents should access it, never public internet
