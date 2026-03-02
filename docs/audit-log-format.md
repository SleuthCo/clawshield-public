# ClawShield Audit Log Format

## Overview
ClawShield logs all security decisions made by the proxy layer for forensic and compliance purposes. Logs are stored in an SQLite database with structured tables and integrity protections.

## Core Tables

### `decisions`
Each row represents a single access decision (allow/deny/redacted).

| Column | Type | Description |
|--------|------|-------------|
| `decision_id` | INTEGER | Unique auto-incrementing ID |
| `timestamp` | TIMESTAMP | RFC3339 datetime of decision |
| `session_id` | TEXT | Reference to session that triggered the decision |
| `tool` | TEXT | Name of the MCP tool called (e.g., `file.read`, `network.connect`) |
| `arguments_hash` | TEXT | SHA-256 hash of redacted arguments (privacy-preserving) |
| `decision` | TEXT | One of: `allow`, `deny`, `redacted` |
| `reason` | TEXT | Human-readable reason for decision |
| `policy_version` | TEXT | Version of policy that governed this decision |
| `scanner_type` | TEXT | Scanner that triggered the decision (`vuln`, `injection`, `malware`, `secrets`, `pii`, or empty for policy engine) |
| `correlation_id` | TEXT | Bridge/integration correlation ID |
| `classification` | TEXT | Data classification: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED` |
| `source` | TEXT | Request source: `forge-bridge`, `direct`, `slack`, `telegram` |
| `response_blocked` | INTEGER | Whether the response (not request) was blocked (0/1) |
| `agent_name` | TEXT | Agent identity from `X-Agent-Name` header |
| `decision_details` | JSON | Structured forensic detail (see [Decision Explainability](#decision-explainability) below) |

### `tool_calls`
Stores full request and response payloads linked to a decision.

| Column | Type | Description |
|--------|------|-------------|
| `call_id` | INTEGER | Unique auto-incrementing ID |
| `decision_id` | INTEGER | Foreign key to `decisions.decision_id` (UNIQUE) |
| `request_json` | BLOB | Full JSON request sent to the tool |
| `response_json` | BLOB | Full JSON response received from the tool (nullable if failed) |
| `created_at` | TIMESTAMP | When the call was logged |

### `sessions`
Tracks agent session lifecycle.

| Column | Type | Description |
|--------|------|-------------|
| `session_id` | TEXT | Unique UUID for session |
| `start_time` | TIMESTAMP | Session start time |
| `end_time` | TIMESTAMP | Session end time (nullable) |
| `agent_version` | TEXT | Version of ClawShield agent |
| `node_id` | TEXT | Identifier of the node where agent runs |
| `context` | JSON | Optional extra context (e.g., user, request ID) as JSON blob |

### `policy_changes`
Audit trail for policy updates.

| Column | Type | Description |
|--------|------|-------------|
| `change_id` | INTEGER | Unique auto-incrementing ID |
| `timestamp` | TIMESTAMP | When policy changed |
| `session_id` | TEXT | Session that triggered the change (if applicable) |
| `old_policy_hash` | TEXT | SHA-256 of previous policy version |
| `new_policy_hash` | TEXT | SHA-256 of new policy version |
| `changed_by` | TEXT | User/service responsible for change |
| `reason` | TEXT | Why the policy was changed |

### `integrity_checkpoints`
Cryptographic integrity tracking.

| Column | Type | Description |
|--------|------|-------------|
| `checkpoint_id` | INTEGER | Unique auto-incrementing ID |
| `timestamp` | TIMESTAMP | When checkpoint created |
| `db_hash` | TEXT | SHA-256 hash of entire SQLite database file at time of checkpoint |
| `reason` | TEXT | e.g., "daily rotation", "policy update" |

### `security_events`
Cross-layer security event audit trail. Records events exchanged between the proxy, firewall, and eBPF monitor via the event bus, along with any adaptive reactions taken.

| Column | Type | Description |
|--------|------|-------------|
| `event_id` | INTEGER | Unique auto-incrementing ID |
| `timestamp` | TIMESTAMP | When the event occurred |
| `event_type` | TEXT | Type of security event (e.g., `privesc`, `injection_blocked`, `port_scan`, `exec_suspicious`, `malware_blocked`, `vuln_blocked`) |
| `severity` | TEXT | Event severity: `critical`, `high`, `medium`, `low`, `info` |
| `source` | TEXT | Which layer produced the event: `proxy`, `ebpf`, `firewall`, `adaptive` |
| `session_id` | TEXT | Proxy session ID (for proxy-originated events) |
| `pid` | INTEGER | Process ID (for eBPF-originated events) |
| `tool` | TEXT | MCP tool name or command involved |
| `reason` | TEXT | Human-readable explanation |
| `details` | JSON | Event-specific metadata as key-value pairs |
| `reaction` | TEXT | Adaptive action taken in response (e.g., `elevate_sensitivity`, `elevate_default_deny`) |

## Argument Redaction

Sensitive fields (e.g., API keys, tokens) are identified by key name and replaced with `[REDACTED]` before hashing. The hash (`arguments_hash`) is stored in the `decisions` table; full arguments remain in `tool_calls` for forensic use.

**Redacted Fields:**
- `api_key`
- `token`
- `password`
- `secret`
- `credentials`
- `access_token`
- `refresh_token`
- `session_id`
- `email`
- `phone`
- `ssn`

## Decision Explainability

Every deny/redact decision includes a structured `decision_details` JSON blob that captures exactly *why* the decision was made, enabling SOC analysts to investigate without reproducing the evaluation.

### `DecisionDetail` Structure

| Field | Type | Description |
|-------|------|-------------|
| `pipeline_stage` | string | Where in the evaluation pipeline the decision was made: `denylist`, `allowlist`, `arg_filter`, `domain_allowlist`, `vuln_scan`, `injection_scan`, `secrets_scan`, `pii_scan`, `malware_scan`, `default_action`, `timeout`, `parse_error`, `duplicate_keys` |
| `eval_duration_ms` | float | Wall-clock evaluation time in milliseconds |
| `scan_results` | array | Per-scanner forensic details (see below). Only populated for scanner-triggered decisions |
| `active_overrides` | array | Adaptive overrides in effect at decision time (e.g., `"sensitivity_override:high"`, `"default_action_override:deny"`) |

### `ScanResult` Structure

Each entry in `scan_results` captures what a specific scanner found:

| Field | Type | Description |
|-------|------|-------------|
| `scanner` | string | Scanner name: `vuln`, `injection`, `malware`, `secrets`, `pii` |
| `rule_id` | string | Stable machine-readable rule identifier (see table below) |
| `description` | string | Human-readable explanation of what was detected |
| `match_excerpt` | string | Safely truncated/redacted excerpt of matched content. **Secrets and PII are redacted** (e.g., `AKIA****LE`) — full values are never stored |
| `confidence` | string | Detection confidence: `high`, `medium`, `low` |
| `blocked` | boolean | Whether this scanner result caused a deny decision |
| `metadata` | object | Scanner-specific key-value pairs (e.g., entropy score, CIDR block) |

### Rule IDs by Scanner

| Scanner | Rule IDs |
|---------|----------|
| `vuln` | `sqli`, `ssrf`, `path_traversal`, `command_injection`, `xss` |
| `injection` | `role_override`, `instruction_injection`, `encoding_attack`, `delimiter_injection`, `canary_leak` |
| `malware` | `executable_magic`, `high_entropy`, `script_detection`, `signature_match`, `zip_bomb`, `gzip_bomb` |
| `secrets` | `aws_access_key_id`, `github_personal_access_token`, `stripe_api_key`, `jwt_token`, `private_key`, etc. |
| `pii` | `email_address`, `phone_number`, `social_security_number`, `credit_card_number`, `ip_address` |

### Example Decision Detail

```json
{
  "pipeline_stage": "vuln_scan",
  "eval_duration_ms": 1.23,
  "scan_results": [
    {
      "scanner": "vuln",
      "rule_id": "sqli",
      "description": "vuln_scan: SQL injection detected (pattern: OR\\s+1\\s*=\\s*1)",
      "match_excerpt": "OR\\s+1\\s*=\\s*1",
      "confidence": "high",
      "blocked": true
    }
  ],
  "active_overrides": ["sensitivity_override:high"]
}
```

### Security Properties

- **Match excerpts are truncated** to 100 characters maximum to prevent large payloads in audit logs
- **Secrets and PII excerpts are redacted** — only first 4 and last 2 characters shown (e.g., `ghp_****yz`)
- **DecisionDetail never appears in client-facing error responses** — only stored server-side in audit logs
- **UTF-8 safe** — truncation operates on rune boundaries to prevent invalid strings

## Query Interface

The `clawshield-audit` CLI allows querying logs by:
- Time range (`--from`, `--to`)
- Decision type (`--decision allow|deny|redacted`)
- Tool name (`--tool file.read`)
- Scanner type (`--scanner vuln|injection|malware|secrets|pii`)
- Rule ID (`--rule-id sqli|ssrf|...`) — forensic filtering by specific detection rule
- Argument patterns (partial hash match or regex on redacted args)

Output formats: JSON, CSV, human-readable.

## Retention Policy

Logs are automatically purged based on policy configuration. Default retention: 90 days. Policy defines maximum age per table.

Integrity checkpoints are retained indefinitely to detect tampering.

## Integrity & Tamper Detection

- `integrity_checkpoints` store cryptographic hashes of the entire DB at known points.
- To verify integrity, recompute SHA-256 hash of the database file and compare against checkpoint records.
- Any change (even one byte) to the DB will invalidate past checkpoints.

## SIEM Integration

Export logs as JSON for ingestion into SIEM tools (e.g., Splunk, ELK). Use `clawshield-audit --format json` for full structured output.