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

### `secrets_scan`

Detects leaked credentials and secrets in tool arguments and responses by matching value patterns — AWS access keys, GitHub tokens, Stripe keys, JWTs, private keys, database connection strings, and more.

Unlike key-name-based redaction (which only catches secrets in well-named fields like `api_key`), secrets scanning detects credentials regardless of which JSON field they appear in.

#### `enabled` (boolean)

Enable or disable secrets scanning.

#### `scan_requests` (boolean)

Scan outbound tool arguments for secrets. Catches credentials being sent to tools.

#### `scan_responses` (boolean)

Scan inbound tool responses for secrets. Catches credentials leaked in tool outputs.

#### `action` (string)

What to do when a secret is detected:
- `block` (default): Deny the request/response entirely
- `redact`: Replace the detected secret with `[REDACTED]` and allow the message through

#### `rules` (array of strings)

Which rule categories to enable. Empty = all categories. Available categories:

| Category | Detects |
|----------|---------|
| `aws` | AWS access keys, secret keys, session tokens |
| `gcp` | GCP API keys, service account JSON, OAuth client IDs |
| `azure` | Azure storage keys, AD client secrets |
| `github` | GitHub PATs, OAuth tokens, app tokens, fine-grained tokens |
| `gitlab` | GitLab personal access tokens, pipeline tokens |
| `slack` | Slack bot/user tokens, webhook URLs |
| `stripe` | Stripe secret and restricted API keys |
| `atlassian` | Atlassian/Jira/Confluence API tokens |
| `jwt` | JSON Web Tokens |
| `private_key` | RSA, EC, OpenSSH, PGP, PKCS#8 private keys |
| `database` | PostgreSQL, MySQL, MongoDB, Redis connection strings with credentials |
| `generic_api` | SendGrid, Twilio, Mailgun, NPM, PyPI, Heroku, Datadog keys, generic bearer tokens |

#### `exclude_tools` (array of strings)

Tools exempt from secrets scanning (e.g., `vault.read`, `secrets.get`).

#### `custom_patterns` (array of objects)

User-defined secret detection patterns:

```yaml
custom_patterns:
  - name: "Internal Service Token"
    pattern: "intl_svc_[a-zA-Z0-9]{32}"
    description: "internal service-to-service token"
```

**Example:**

```yaml
secrets_scan:
  enabled: true
  scan_requests: true
  scan_responses: true
  action: block
  rules:
    - aws
    - github
    - stripe
    - jwt
    - private_key
    - database
  exclude_tools:
    - vault.read
    - secrets.get
```

## Examples

See `/policy/examples/` for sample policies covering:
- Developer default (permissive)
- Production strict (deny-by-default)
- Read-only mode
- Offline/no-network mode

## Best Practices

- Always use `deny` as the default in production.
- Use precise patterns over wildcards (`*`) where possible.
- Test policies with unit tests before deployment.
- Rotate secrets regularly — policy redaction is a fallback, not a replacement.

> **Note**: This schema is versioned. Ensure your validator and policy versions are compatible.