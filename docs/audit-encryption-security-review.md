# Audit Encryption at Rest — Security Review

**Feature:** Field-level AES-256-GCM encryption for ClawShield audit logs  
**Date:** 2026-03-03  
**Status:** Implementation complete  
**Package:** `proxy/internal/audit/crypto`

---

## 1. Threat Model

### Assets Protected
| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Tool call request JSON | `tool_calls.request_json` | HIGH — may contain user queries with secrets, PII, credentials |
| Tool call response JSON | `tool_calls.response_json` | HIGH — may contain AI responses with sensitive data |
| Decision details | `decisions.decision_details` | MEDIUM — contains scanner match excerpts (redacted but still indicative) |
| Arguments hash | `decisions.arguments_hash` | MEDIUM — hash of tool call arguments; correlatable |

### Threats Mitigated
| Threat | STRIDE | Mitigation |
|--------|--------|------------|
| **T1:** Attacker gains read access to SQLite file on disk | Information Disclosure | Sensitive fields encrypted with AES-256-GCM; plaintext never touches disk |
| **T2:** Attacker modifies audit records to cover tracks | Tampering | GCM authentication tag detects any modification to ciphertext |
| **T3:** Backup/snapshot exposure of audit data | Information Disclosure | Encrypted fields remain protected in cold storage |
| **T4:** Insider access to database file | Information Disclosure | Requires encryption key (separate from DB access) to read sensitive fields |

### Threats NOT Mitigated (Residual Risk)
| Threat | Risk | Compensating Control |
|--------|------|---------------------|
| **T5:** Attacker with access to encryption key AND database | HIGH | Key management discipline (KMS, rotation); see Section 6 |
| **T6:** Memory-resident plaintext during processing | LOW | Process-level isolation; encrypted at rest, not in transit through proxy |
| **T7:** SIEM receives unencrypted events | ACCEPTED | By design — SOC analysts need real-time access; SIEM has its own access controls |
| **T8:** Non-sensitive fields remain plaintext (tool name, decision, timestamp) | ACCEPTED | Required for queryability; these fields are operational metadata, not sensitive content |
| **T9:** Side-channel attacks on ciphertext length | LOW | Length reveals approximate size of original data; acceptable for audit logs |

---

## 2. Algorithm Choice: AES-256-GCM

### Why AES-256-GCM
- **Authenticated encryption:** GCM provides both confidentiality and integrity in a single operation. Any tampering with ciphertext, nonce, or tag is detected.
- **Performance:** AES-GCM has hardware acceleration (AES-NI) on all modern x86/ARM CPUs. Go's `crypto/aes` automatically uses hardware instructions.
- **Standard:** NIST SP 800-38D. Widely reviewed, no known practical attacks with proper nonce management.
- **No additional dependencies:** Go standard library only — zero supply chain risk.

### Alternatives Considered
| Alternative | Rejected Because |
|-------------|-----------------|
| SQLCipher (full-DB encryption) | Requires replacing SQLite driver; prevents selective field queries on non-sensitive data |
| ChaCha20-Poly1305 | Equally secure but AES-GCM has hardware acceleration advantage on server CPUs |
| AES-CBC + HMAC | Requires careful Encrypt-then-MAC composition; GCM is simpler and less error-prone |
| Age/NaCl secretbox | External dependency; secretbox uses XSalsa20 which is non-standard for compliance |

---

## 3. Nonce Generation Strategy

- **Size:** 12 bytes (96 bits) per GCM recommendation
- **Source:** `crypto/rand.Reader` (OS CSPRNG — `/dev/urandom` on Linux, `CryptGenRandom` on Windows)
- **Uniqueness:** Random nonce per encryption operation. With 96-bit random nonces, the birthday bound collision probability reaches 2^-32 after ~2^32 encryptions with the same key. For audit logs, this is far beyond operational lifetime.
- **Verification:** Test `TestEncrypt_UniqueNonces` verifies 1,000 sequential encryptions produce unique nonces.

### Nonce Reuse Risk Assessment
At 1,000 audit entries/second (extremely high), it would take ~136 years to reach 2^32 encryptions. Key rotation (recommended annually) resets this counter. **Risk: NEGLIGIBLE.**

---

## 4. Ciphertext Format

```
+----------+----------+--------------------+----------+
| Version  |  Nonce   |    Ciphertext      | GCM Tag  |
| (1 byte) | (12 bytes)|  (variable)       | (16 bytes)|
+----------+----------+--------------------+----------+
```

- **Version prefix (0x01):** Enables future algorithm rotation. The `IsEncrypted()` function uses this byte to distinguish encrypted from plaintext data during migration.
- **Why 0x01?** The byte `0x01` is not a valid leading byte for UTF-8 text, JSON (`{`, `[`, `"`), or common text formats, making false positive detection extremely unlikely.
- **Total overhead:** 29 bytes per encrypted field (1 + 12 + 16).

---

## 5. Key Management Requirements

### Current Implementation
The encryption key is provided via:
1. **Direct API:** `NewFieldEncryptor(key []byte)` — 32-byte raw key
2. **Environment variable:** `CLAWSHIELD_AUDIT_ENCRYPTION_KEY` — 64-character hex string

### Production Recommendations
| Requirement | Recommendation | Priority |
|-------------|---------------|----------|
| Key storage | Use a KMS (AWS KMS, Azure Key Vault, HashiCorp Vault) to wrap the encryption key | CRITICAL |
| Key rotation | Rotate annually; old keys must be retained for decrypting historical data | HIGH |
| Key access | Limit to the ClawShield process only; never log or expose in config files | CRITICAL |
| Key backup | Store encrypted backup of the key in a separate security domain | HIGH |
| Key generation | Use `crypto.GenerateKey()` or equivalent CSPRNG; never derive from passwords | HIGH |

### Key Rotation Procedure
1. Generate a new 32-byte key via `crypto.GenerateKey()`
2. Update the `CLAWSHIELD_AUDIT_ENCRYPTION_KEY` environment variable
3. Restart ClawShield — new writes use the new key
4. Historical data remains readable because the Reader's `IsEncrypted()` check plus the version prefix are key-agnostic — but decryption requires the correct key
5. **For full rotation:** run a migration tool to re-encrypt old records with the new key (not yet implemented — see Limitations)

---

## 6. Attack Surface Analysis

### Encryption Boundaries
```
                    ┌─────────────────────────────────────────┐
                    │           ClawShield Proxy              │
                    │                                         │
  MCP Request ──────►  Scanner Pipeline  ──► SIEM Forwarder ──► SIEM (plaintext)
                    │        │                                │
                    │        ▼                                │
                    │   Decision + ToolCall                   │
                    │        │                                │
                    │        ▼                                │
                    │  ┌─────────────┐                        │
                    │  │ Encryptor   │ ◄── AES-256-GCM        │
                    │  └──────┬──────┘                        │
                    │         │                               │
                    └─────────┼───────────────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │  SQLite (disk)  │ ◄── Encrypted at rest
                    └─────────────────┘
```

### What Is Encrypted (at rest in SQLite)
- `decisions.decision_details` — scanner forensic data including match excerpts
- `decisions.arguments_hash` — tool call argument hash
- `tool_calls.request_json` — full MCP request body
- `tool_calls.response_json` — full MCP response body

### What Remains Plaintext (for queryability)
- `decisions.timestamp` — required for time-range queries
- `decisions.session_id` — required for session correlation
- `decisions.tool` — required for tool-based filtering
- `decisions.decision` — required for allow/deny filtering
- `decisions.reason` — operational metadata
- `decisions.policy_version` — operational metadata
- `decisions.scanner_type` — required for scanner-based filtering
- `decisions.correlation_id` — required for request tracing
- `decisions.classification` — data classification label
- `decisions.source` — request source identifier

### Plaintext Field Risk Assessment
The plaintext fields are **operational metadata** — they reveal *what tool was called* and *what decision was made*, but not *what data was in the request/response*. This is an acceptable trade-off: an attacker who gains DB access can see that `web_search` was denied due to `injection` detection, but cannot see the actual content that triggered the detection.

---

## 7. Migration Path

### Enabling Encryption on Existing Databases
The implementation supports **zero-downtime migration**:

1. **Before encryption:** All fields stored as plaintext
2. **Enable encryption:** Set `CLAWSHIELD_AUDIT_ENCRYPTION_KEY` and restart
3. **Mixed state:** New writes are encrypted; old data remains plaintext
4. **Reader compatibility:** `IsEncrypted()` detects the version prefix byte to determine whether decryption is needed, so old plaintext and new ciphertext coexist in the same database

### Tested Migration Scenarios
| Scenario | Test | Result |
|----------|------|--------|
| Encrypted write → encrypted read | `TestEncryptedWriteDecryptedRead` | ✅ PASS |
| Plaintext write → encrypted read | `TestUnencryptedWriteDecryptedRead` | ✅ PASS |
| Encrypted write → plaintext read | `TestEncryptedWritePlaintextRead` | ✅ PASS (ciphertext returned) |
| Mixed encrypted + plaintext | `TestMixedEncryptedPlaintextData` | ✅ PASS |
| Wrong decryption key | `TestWrongKeyDecryption` | ✅ PASS (graceful warning) |

---

## 8. Compliance Mapping

| Standard | Control | Coverage |
|----------|---------|----------|
| **SOC 2** | CC6.1 — Logical and Physical Access Controls | Encryption key separates data access from DB access |
| **SOC 2** | CC6.7 — Restriction of Data in Transmission and Storage | Sensitive audit fields encrypted at rest |
| **NIST 800-53** | SC-28 — Protection of Information at Rest | AES-256-GCM encryption of sensitive audit fields |
| **NIST 800-53** | SC-12 — Cryptographic Key Management | Key provided via env var; KMS integration recommended |
| **NIST 800-53** | AU-9 — Protection of Audit Information | GCM authentication prevents tampering with encrypted audit records |
| **ISO 27001** | A.10.1.1 — Cryptographic Controls Policy | Documented algorithm, key management, and rotation requirements |
| **ISO 27001** | A.10.1.2 — Key Management | Key generation, distribution, and rotation procedures documented |
| **HIPAA** | §164.312(a)(2)(iv) — Encryption and Decryption | Encryption of ePHI that may appear in tool call data |
| **PCI-DSS** | Req 3.4 — Render PAN Unreadable | Credit card numbers in audit logs encrypted at rest |

---

## 9. Limitations and Future Work

| Limitation | Impact | Planned Mitigation |
|------------|--------|-------------------|
| No automated key rotation tool | Manual re-encryption of historical data | Build `clawshield-audit-rekey` CLI tool |
| No KMS integration | Key stored in environment variable | Add AWS KMS / Vault / Azure Key Vault providers |
| Plaintext metadata queryable | Tool names, decisions visible without key | Acceptable trade-off for operational needs |
| Single key for all fields | Compromise of key exposes all encrypted fields | Consider per-field or per-tenant keys for multi-tenant |
| No envelope encryption | Key used directly (not wrapped) | Implement envelope encryption with KMS-wrapped DEKs |
| SIEM receives plaintext | SOC analysts see unencrypted events | By design; SIEM should have its own encryption |

---

## 10. Test Coverage Summary

| Test Category | Tests | Coverage |
|---------------|-------|----------|
| Key validation | 5 | Empty, nil, short, long, valid keys |
| Round-trip encryption | 9 | Text, JSON, unicode, binary, empty, large, PII, API keys |
| Nil/empty handling | 4 | Nil plaintext, nil ciphertext, empty string |
| Tamper detection | 3 | Wrong key, tampered ciphertext, tampered nonce |
| Error handling | 2 | Too-short ciphertext, unsupported version |
| Nonce safety | 2 | Unique nonces, non-deterministic ciphertext |
| Concurrency | 2 | 100 goroutines encrypt/decrypt, 200 concurrent writes |
| Integration: encrypted round-trip | 1 | Write encrypted → read decrypted |
| Integration: migration | 3 | Plaintext→encrypted read, encrypted→plaintext read, mixed |
| Integration: wrong key | 1 | Graceful degradation with wrong key |
| Integration: queryability | 1 | Filters work on non-encrypted fields |
| Integration: SIEM | 1 | SIEM receives unencrypted data |
| Integration: raw storage | 1 | Verify ciphertext in database |
| Integration: nil fields | 1 | Nil details and empty args_hash |
| **Total** | **36** | |
