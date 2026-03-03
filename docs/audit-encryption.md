# Audit Log Encryption at Rest

ClawShield supports field-level encryption for sensitive audit log data stored in SQLite. When enabled, tool call request/response bodies, decision details, and argument hashes are encrypted with AES-256-GCM before being written to disk.

## Overview

ClawShield's audit system captures detailed forensic data about every tool call processed by the proxy. This data may contain sensitive information including:

- **Secrets** detected by the secrets scanner (API keys, tokens, credentials)
- **PII** detected by the PII scanner (SSNs, credit card numbers, emails)
- **Prompt injection attempts** with match excerpts
- **Full MCP request/response bodies** in the tool_calls table

Encryption at rest ensures this data is protected even if an attacker gains access to the SQLite database file.

## What Gets Encrypted

| Field | Table | Why |
|-------|-------|-----|
| `request_json` | `tool_calls` | Full MCP request body — may contain secrets, PII, credentials |
| `response_json` | `tool_calls` | Full MCP response body — may contain sensitive AI output |
| `decision_details` | `decisions` | Scanner forensic data including match excerpts |
| `arguments_hash` | `decisions` | Hash of tool call arguments — correlatable to sensitive data |

## What Remains Queryable (Not Encrypted)

These operational fields stay in plaintext so you can filter and query audit logs without the encryption key:

- `timestamp` — when the decision was made
- `session_id` — which session
- `tool` — which tool was called
- `decision` — allow, deny, or redacted
- `reason` — why the decision was made
- `policy_version` — which policy version was active
- `scanner_type` — which scanner triggered (if any)
- `correlation_id` — request correlation ID
- `classification` — data classification label
- `source` — request source (forge-bridge, direct, etc.)

## Configuration

### 1. Generate an Encryption Key

Generate a 32-byte (256-bit) random key, hex-encoded:

```bash
# Using OpenSSL
openssl rand -hex 32

# Or using Go
go run -e 'import ("crypto/rand"; "encoding/hex"; "fmt"); b := make([]byte, 32); rand.Read(b); fmt.Println(hex.EncodeToString(b))'
```

### 2. Set the Environment Variable

```bash
export CLAWSHIELD_AUDIT_ENCRYPTION_KEY="<your-64-char-hex-key>"
```

For Docker deployments, add to your `.env` file or Docker Compose:

```yaml
services:
  clawshield:
    environment:
      - CLAWSHIELD_AUDIT_ENCRYPTION_KEY=${AUDIT_ENCRYPTION_KEY}
```

### 3. Restart ClawShield

The encryption key is read at startup. New audit entries will be encrypted; existing plaintext entries remain readable.

## Programmatic Usage

```go
import "github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"

// From environment variable
enc, err := crypto.NewFieldEncryptorFromEnv()

// Or with a raw key
key := make([]byte, 32) // your 32-byte key
enc, err := crypto.NewFieldEncryptor(key)

// Attach to writer (encrypts on write)
writer.SetEncryptor(enc)

// Attach to reader (decrypts on read)
reader := sqlite.NewReaderWithEncryptor(db, enc)
```

## Migration Guide

### Enabling Encryption on an Existing Database

Encryption can be enabled on an existing database with **zero downtime**:

1. Set `CLAWSHIELD_AUDIT_ENCRYPTION_KEY`
2. Restart ClawShield
3. New entries are encrypted; old entries remain plaintext
4. The Reader automatically detects encrypted vs. plaintext fields using a version prefix byte

**No data migration is required.** Both encrypted and plaintext data coexist in the same database. The Reader handles both transparently.

### Reading Encrypted Data Without the Key

If you query an encrypted database without providing the encryption key:
- Non-sensitive fields (tool, decision, timestamp, etc.) are readable normally
- Sensitive fields return raw ciphertext (binary data)
- Decision details will appear as `nil` (the JSON unmarshaler can't parse ciphertext)
- No errors are thrown — this is a safe failure mode

## Key Management Best Practices

### DO
- ✅ Store the key in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)
- ✅ Restrict access to the key to only the ClawShield process
- ✅ Back up the key in a separate security domain from the database
- ✅ Rotate the key annually
- ✅ Use the provided `crypto.GenerateKey()` function or `openssl rand` for key generation

### DON'T
- ❌ Commit the key to source control
- ❌ Store the key in the same directory as the SQLite database
- ❌ Derive the key from a password or passphrase
- ❌ Share the key across environments (dev/staging/prod)
- ❌ Log the key value

## Key Rotation

### Procedure

1. Generate a new key: `openssl rand -hex 32`
2. Update `CLAWSHIELD_AUDIT_ENCRYPTION_KEY` with the new key
3. Restart ClawShield — new writes use the new key
4. **Keep the old key** — it's needed to decrypt historical data

### Important Notes

- After rotation, the database contains data encrypted with both the old and new keys
- Currently, reading historical data requires the original key that was used to encrypt it
- A future `clawshield-audit-rekey` tool will support re-encrypting historical data with a new key

## SIEM Integration

**SIEM forwarding is not affected by encryption.** When both encryption and SIEM forwarding are enabled:

- SIEM receives **unencrypted** decision data in real-time (before storage encryption)
- SQLite stores **encrypted** data at rest
- This is by design — SOC analysts need immediate access to events without managing encryption keys

```
MCP Request → Scanner → SIEM Forwarder (plaintext) → SIEM
                           ↓
                      Encryptor (AES-256-GCM)
                           ↓
                      SQLite (encrypted at rest)
```

## Troubleshooting

### "corrupt decision_details JSON" warnings in logs

This typically means the Reader is trying to parse encrypted data as JSON without a decryptor configured. Set the encryption key on the Reader:

```go
reader := sqlite.NewReaderWithEncryptor(db, enc)
```

### "failed to decrypt" warnings in logs

The encryption key doesn't match the key used to encrypt the data. This can happen after key rotation when reading historical data. Ensure you're using the correct key for the time period.

### Empty decision details after enabling encryption

If `decision.Details` is `nil` for entries written after enabling encryption, verify that:
1. The `CLAWSHIELD_AUDIT_ENCRYPTION_KEY` environment variable is set
2. The key is exactly 64 hex characters (32 bytes)
3. The same key is used for both the Writer and Reader

## Technical Details

- **Algorithm:** AES-256-GCM (NIST SP 800-38D)
- **Key size:** 256 bits (32 bytes)
- **Nonce:** 12 bytes, randomly generated per encryption operation
- **Authentication:** GCM tag (16 bytes) — detects any tampering
- **Ciphertext format:** `version(1) || nonce(12) || ciphertext(var) || tag(16)`
- **Overhead:** 29 bytes per encrypted field
- **Dependencies:** Go standard library only (`crypto/aes`, `crypto/cipher`, `crypto/rand`)
