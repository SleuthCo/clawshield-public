# ClawShield Management Hub — API Reference

**Base URL:** `http://localhost:18800`

All request/response bodies are JSON unless otherwise noted.

---

## System

### GET /api/v1/health

Returns hub health status.

**Response 200:**
```json
{
  "status": "ok",
  "timestamp": "2026-03-03T13:00:00Z"
}
```

---

## Agent Enrollment & Fleet

### POST /api/v1/enroll

Enroll a new agent using a one-time enrollment token.

**Request:**
```json
{
  "token": "abc-123",
  "hostname": "prod-agent-01",
  "tags": ["production", "us-west"]
}
```

**Response 200:**
```json
{
  "agent_id": "uuid",
  "hub_url": "",
  "checkin_interval_seconds": 60
}
```

**Errors:**
- `400` – Bad JSON
- `401` – Invalid or used token

---

### POST /api/v1/checkin

Agent periodic check-in with status report.

**Request:**
```json
{
  "agent_id": "uuid",
  "hostname": "prod-agent-01",
  "clawshield_version": "1.4.2",
  "agent_version": "1.0.0",
  "policy_hash": "sha256:...",
  "policy_version": "v2.1",
  "encryption_key_id": "key-2026-03",
  "uptime_seconds": 86412,
  "health": {
    "status": "healthy",
    "audit_db_size_bytes": 52428800,
    "queue_depth": 0
  },
  "metrics_summary": {
    "decisions_total": 14523,
    "decisions_denied": 127,
    "scanner_detections": {
      "injection": 23,
      "pii": 89
    },
    "period_seconds": 60
  },
  "tags": ["production"]
}
```

**Response 200:**
```json
{
  "actions": [
    {
      "type": "update_policy",
      "payload": {
        "policy_version": "v2.4",
        "policy_hash": "sha256:...",
        "policy_url": "/api/v1/policy-versions/{id}/content",
        "signature": "base64..."
      }
    }
  ],
  "next_checkin_seconds": 60,
  "server_time": "2026-03-03T13:00:01Z"
}
```

**Action types:** `update_policy`, `rotate_encryption_key`, `update_binary`, `emergency_lockdown`

**Errors:**
- `400` – Bad JSON, invalid agent_id format
- `404` – Unknown agent

---

### GET /api/v1/agents

List registered agents.

**Query Parameters:**
- `status` – Filter by status: `healthy`, `unhealthy`, `stale`
- `tag` – Filter by tag

**Response 200:** JSON array of Agent objects

---

### GET /api/v1/agents/{id}

Get agent details with recent check-ins.

**Response 200:**
```json
{
  "agent": { ... },
  "recent_checkins": [ ... ]
}
```

**Errors:**
- `400` – Invalid ID
- `404` – Not found

---

## Policy Management

### POST /api/v1/policy-groups

Create a policy group.

**Request:**
```json
{
  "name": "Engineering",
  "parent_group_id": "",
  "description": "Engineering team policy"
}
```

**Response 201:** PolicyGroup object with generated `group_id`

---

### GET /api/v1/policy-groups

List all policy groups.

**Response 200:** JSON array of PolicyGroup objects

---

### GET /api/v1/policy-groups/{id}

Get policy group details.

**Errors:**
- `400` – Invalid ID
- `404` – Not found

---

### POST /api/v1/policy-versions

Create a new policy version (draft).

**Request:**
```json
{
  "group_id": "uuid",
  "version_label": "v2.4",
  "policy_yaml": "default_action: deny\n...",
  "created_by": "admin@corp.com"
}
```

**Response 201:** PolicyVersion with generated `version_id`, computed `policy_hash`, and `status="draft"`

---

### GET /api/v1/policy-versions/{id}

Get policy version details.

---

### POST /api/v1/policy-versions/{id}/approve

Approve or reject a policy version.

**Request:**
```json
{
  "approver_id": "reviewer@corp.com",
  "decision": "approved",
  "comment": "LGTM"
}
```

**Valid decisions:** `approved`, `rejected`

**Status transitions:** `draft` → `approved`, `draft` → `rejected`

**Response 200:** Success message

---

### POST /api/v1/policy-versions/{id}/publish

Publish an approved policy version. The previous published version for the same group is automatically superseded.

**Precondition:** Version must have status `approved` (enforced)

**Response 200:** Success message

**Errors:**
- `400` – Version not approved

---

### GET /api/v1/policy-versions/{id}/content

Download the raw policy YAML.

**Response 200:** `Content-Type: text/x-yaml`

**Headers:**
- `X-Policy-Hash`
- `X-Policy-Signature`

---

### POST /api/v1/agents/{id}/assign-group

Assign an agent to a policy group.

**Request:**
```json
{
  "group_id": "uuid"
}
```

**Response 200:** Success message

---

## Encryption Key Management

### POST /api/v1/keys

Create a new encryption key.

**Request:**
```json
{
  "group_id": "uuid",
  "encrypted_key": "hex-encoded-key",
  "expires_at": "2027-01-01T00:00:00Z"
}
```

**Response 201:** EncryptionKey object (includes `encrypted_key` — only time it's returned)

---

### GET /api/v1/keys

List encryption keys. Key material is NOT included.

**Query Parameters:**
- `group_id` – Filter by group

**Response 200:** JSON array (EncryptionKey objects with `encrypted_key` field stripped)

---

### GET /api/v1/keys/{id}

Get key metadata. Key material is NOT included.

**Response 200:** EncryptionKey object with `encrypted_key` field stripped

---

### POST /api/v1/keys/{id}/rotate

Rotate a key. Marks current key as 'rotated'; new key must already exist.

**Request:**
```json
{
  "new_key_id": "uuid"
}
```

**Response 200:** Success message

---

### POST /api/v1/keys/{id}/revoke

Revoke a key immediately.

**Response 200:** Success message

---

## Software Updates

### POST /api/v1/releases

Publish a new software release.

**Request:**
```json
{
  "version": "1.5.0",
  "binary_hash": "sha256:...",
  "signature": "base64...",
  "release_notes": "Bug fixes"
}
```

**Response 201:** UpdateRelease object with generated `release_id`

---

### GET /api/v1/releases

List all releases (newest first).

**Response 200:** JSON array of UpdateRelease objects

---

### POST /api/v1/rollouts

Start a wave-based rollout.

**Request:**
```json
{
  "release_id": "uuid",
  "wave_config": {
    "canary_percent": 5,
    "wave1_percent": 25,
    "wave2_percent": 50
  }
}
```

**Response 201:** UpdateRollout object with generated `rollout_id`

---

### GET /api/v1/rollouts/{id}

Get rollout status with task statistics.

**Response 200:**
```json
{
  "rollout": { ... },
  "stats": {
    "total": 100,
    "completed": 5,
    "failed": 0
  }
}
```

---

### POST /api/v1/rollouts/{id}/pause

Pause a running rollout.

**Response 200:** Success message

---

## Dashboard

### GET /api/v1/dashboard/overview

Fleet overview statistics.

**Response 200:**
```json
{
  "total_agents": 150,
  "healthy_agents": 142,
  "unhealthy_agents": 3,
  "stale_agents": 5,
  "version_distribution": {
    "1.4.2": 140,
    "1.4.1": 10
  },
  "policy_compliance": {
    "compliant": 130,
    "non_compliant": 12,
    "unassigned": 8
  }
}
```

---

### GET /api/v1/dashboard/security

Aggregated security metrics (last 24 hours).

**Response 200:**
```json
{
  "total_decisions": 145230,
  "total_denied": 1270,
  "scanner_detections": {
    "injection": 230,
    "pii": 890,
    "secrets": 150,
    "malware": 0
  }
}
```

---

## Common Error Responses

All errors return JSON in the format:

```json
{
  "error": "description"
}
```

| Status | Meaning |
|--------|---------|
| `400` | Bad request (invalid JSON, invalid ID format, business rule violation) |
| `401` | Unauthorized (invalid enrollment token) |
| `404` | Not found |
| `405` | Method not allowed |
| `500` | Internal server error |

---

## ID Format

All IDs (agent_id, group_id, version_id, key_id, etc.) must:

- Contain only alphanumeric characters, hyphens, and underscores
- Be 1–128 characters long
- Not contain path separators or traversal sequences
