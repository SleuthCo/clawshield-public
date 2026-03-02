# ClawShield Policy Language Reference

## Overview

ClawShield policies are defined in YAML and enforce security rules on tool usage, network access, argument redaction, and audit logging. Policies use a simple, declarative format with JSONPath-style selectors for deep argument inspection.

## Schema Structure

### `version` (required)

SemVer string indicating policy schema version. Must match the validator’s expected version.

Example: `"1.0.0"`

### `default_action` (required)

Defines the action taken when no rule matches.

- `allow`: Permit by default, deny only explicitly listed tools/domains.
- `deny`: Deny by default, allow only explicitly listed tools/domains.

### `tools`

Controls which system commands/tools are allowed or denied.

#### `allowlist` (array of strings)

List of tool names or patterns to permit. Uses prefix matching and glob patterns (`*`).

Examples:
- `"cat"` — matches exact name
- `"curl*"` — matches `curl`, `curl -X POST`
- `"*"` — allows all tools (use with caution)

#### `denylist` (array of strings)

List of tool names or patterns to explicitly block. Overrides allowlist.

Examples:
- `"rm"`
- `"sudo"`
- `"python*"`

### `domains`

Controls outbound network access via URL pattern matching.

#### `allowlist` (array of strings)

List of allowed domains or URLs using regex-compatible patterns.

Supported syntax:
- `https://api.example.com/v1/*` — matches any path under v1/
- `http://localhost:*` — matches all ports on localhost
- `https://*.example.com` — matches subdomains

### `arguments`

Defines rules for inspecting and redacting sensitive data in command arguments.

#### `redact_patterns` (array of strings)

Regular expressions matching sensitive values. Redacted entries appear as `[REDACTED]` in logs.

Examples:
- `"sk_.*"` — matches Stripe secret keys
- `"eyJ.*"` — matches JWT tokens
- `"password=.*"`

#### `selectors` (array of strings)

JSONPath-style paths to extract and inspect nested data in structured arguments.

Examples:
- `"$.api_key"` — matches top-level api_key field
- `"$.credentials.token"` — matches nested token
- `"$.headers.Authorization"`
- `"$.data[*].secret"` — matches all elements in array

> Note: Selectors are used to trigger redaction and audit events when matched.

### `audit`

Configures logging behavior for decisions.

#### `enabled` (boolean)

Enable or disable audit logging. Always recommended in production.

#### `level` (enum)

Verbosity of logs:
- `none`: No logs
- `info`: Logs allow/deny decisions
- `debug`: Includes full arguments and selectors matched

#### `output` (string)

Destination for audit log output:
- `stdout`
- `stderr`
- `/path/to/file` — write to specified file (must be writable)

## Policy Evaluation Flow

1. Evaluate `default_action`
2. Apply `denylist` rules first → deny if matched
3. Apply `allowlist` rules → allow if matched
4. If tool/domain is allowed, inspect arguments using `selectors`
5. For matching selectors, apply redaction per `redact_patterns`
6. Log decision to audit output based on `audit` settings

### `adaptive`

Configures cross-layer adaptive security responses. When enabled, security events from one layer (e.g., eBPF detecting privilege escalation) automatically trigger defensive responses in other layers (e.g., proxy elevating injection sensitivity).

#### `enabled` (boolean)

Enable or disable the cross-layer adaptive controller.

#### `socket_path` (string)

Path to the Unix domain socket used for inter-layer communication. Default: `/tmp/clawshield-events.sock`

#### `rules` (array of objects)

Each rule defines a trigger condition and an automatic response action.

**Trigger fields:**

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Event source: `proxy`, `ebpf`, `firewall` |
| `type` | string | Event type: `privesc`, `exec_suspicious`, `port_scan`, `file_access`, `injection_blocked`, `malware_blocked`, `vuln_blocked`, `policy_deny` |
| `min_severity` | string | Minimum severity to match: `critical`, `high`, `medium`, `low`, `info` |
| `min_count` | integer | Minimum number of matching events within the time window before firing |
| `window_seconds` | integer | Time window for count threshold (default: 60) |

**Action types:**

| Action | Description |
|--------|-------------|
| `elevate_sensitivity` | Temporarily elevates the injection scanner sensitivity level |
| `restrict_domains` | Temporarily restricts domain allowlist access |
| `elevate_default_deny` | Temporarily overrides default action to `deny` |
| `block_session` | Temporarily blocks the triggering session |
| `add_temp_firewall_rule` | Adds a temporary iptables block rule for the destination IP |

**Params:**

| Param | Type | Description |
|-------|------|-------------|
| `duration_seconds` | integer | How long the adaptive response stays active (default: 300) |
| `level` | integer | Sensitivity level for `elevate_sensitivity`: 1=low, 2=medium, 3=high |

**Example:**

```yaml
adaptive:
  enabled: true
  socket_path: /tmp/clawshield-events.sock
  rules:
    - trigger:
        source: ebpf
        type: privesc
      action: elevate_sensitivity
      params:
        duration_seconds: 300

    - trigger:
        source: proxy
        type: injection_blocked
        min_count: 3
        window_seconds: 60
      action: elevate_default_deny
      params:
        duration_seconds: 900
```

## Examples

See `/policy/examples/` for sample policies covering:
- Developer default (permissive)
- Production strict (deny-by-default)
- Read-only mode
- Offline/no-network mode
- Cross-layer adaptive response

## Best Practices

- Always use `deny` as the default in production.
- Use precise patterns over wildcards (`*`) where possible.
- Test policies with unit tests before deployment.
- Rotate secrets regularly — policy redaction is a fallback, not a replacement.
- Enable `adaptive` in production to get automated cross-layer defense-in-depth.
- Start with conservative `duration_seconds` values and tune based on your threat model.

> **Note**: This schema is versioned. Ensure your validator and policy versions are compatible.