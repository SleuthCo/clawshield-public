---
framework: "Secure Development Lifecycle"
version: "1.0"
domain: "Security"
agent: "friday"
tags: ["sdl", "threat-modeling", "security", "secure-design", "security-testing", "devsecops"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Secure Development Lifecycle

## SDL Phases

The Secure Development Lifecycle (SDL) integrates security into every phase of software development, shifting security left from a post-deployment concern to a design-time consideration.

**Phase 1 -- Requirements:** Define security requirements alongside functional requirements. Identify regulatory requirements (GDPR, HIPAA, PCI DSS, SOC 2). Define data classification levels (public, internal, confidential, restricted). Establish security acceptance criteria for features.

**Phase 2 -- Design:** Conduct threat modeling. Apply secure design principles. Define authentication and authorization models. Design for data protection (encryption at rest and in transit). Plan audit logging and monitoring.

**Phase 3 -- Implementation:** Follow secure coding standards. Use security linters and SAST tools. Conduct peer code reviews with security focus. Use approved libraries for cryptography and authentication.

**Phase 4 -- Verification:** Run automated security testing (SAST, DAST, SCA). Conduct manual penetration testing for high-risk features. Verify security requirements are met. Test error handling and edge cases.

**Phase 5 -- Release:** Security review gate before production deployment. Ensure all high/critical vulnerabilities are resolved. Document known risks and mitigations. Verify incident response plan is in place.

**Phase 6 -- Operations:** Monitor for security events. Patch vulnerabilities promptly. Conduct periodic security assessments. Maintain incident response readiness.

## Threat Modeling in Development

Threat modeling is a structured process for identifying security threats and designing countermeasures. It should happen during design, before code is written.

**STRIDE framework:** Categorize threats by type:

- **Spoofing:** Can an attacker impersonate a user or system? Countermeasure: strong authentication.
- **Tampering:** Can an attacker modify data in transit or at rest? Countermeasure: integrity checks (HMAC, signatures, checksums).
- **Repudiation:** Can a user deny performing an action? Countermeasure: audit logging, digital signatures.
- **Information Disclosure:** Can an attacker access data they should not see? Countermeasure: encryption, access control, data minimization.
- **Denial of Service:** Can an attacker make the system unavailable? Countermeasure: rate limiting, resource limits, redundancy.
- **Elevation of Privilege:** Can an attacker gain higher privileges? Countermeasure: authorization checks, least privilege, input validation.

**Lightweight threat modeling process:**

1. **Draw a data flow diagram:** Identify components (web app, API, database, external services), data flows between them, trust boundaries (internet/DMZ, DMZ/internal, service/database).
2. **Identify threats using STRIDE:** For each data flow crossing a trust boundary, consider each STRIDE category.
3. **Prioritize threats:** Use DREAD scoring (Damage, Reproducibility, Exploitability, Affected users, Discoverability) or a simple High/Medium/Low assessment.
4. **Define mitigations:** For each high-priority threat, define a specific countermeasure and assign it as a work item.

**Example threat model entry:**

```
Component: User API
Data Flow: Client -> API Gateway -> User Service -> PostgreSQL
Trust Boundary: Internet -> Internal Network

Threat: SQL Injection (Tampering, Information Disclosure)
Risk: High
Mitigation: Use parameterized queries exclusively. Add SQLi detection
  to WAF rules. Input validation on all user-provided fields.
Status: Mitigated (parameterized queries in ORM, WAF rule deployed)
```

**When to threat model:** For every new service or significant feature. When the architecture changes (new external integration, new data store, new trust boundary). Review existing threat models annually or when the risk landscape changes.

## Security Requirements

Security requirements should be as specific and testable as functional requirements.

**Authentication requirements:**

- Multi-factor authentication for admin users.
- Password policy: minimum 12 characters, no commonly breached passwords (check against Have I Been Pwned API).
- Account lockout after 5 failed attempts with progressive delay.
- Session timeout after 30 minutes of inactivity.
- Token rotation: refresh tokens expire after 7 days.

**Authorization requirements:**

- Role-based access control (RBAC) with clearly defined roles and permissions.
- Resource-level authorization: users can only access their own data.
- All API endpoints have authorization checks (no open endpoints by accident).
- Admin actions require re-authentication.

**Data protection requirements:**

- All data encrypted in transit (TLS 1.2+).
- Sensitive data encrypted at rest (AES-256).
- PII access is logged and auditable.
- Data retention policies enforced automatically.

## Secure Design Principles

### Least Privilege

Every component, user, and process should have only the minimum permissions needed to perform its function. No more.

**Implementation:**

- Database accounts with specific grants, not superuser access.
- IAM roles scoped to specific resources and actions.
- API tokens with limited scopes.
- Microservices have network access only to the services they need (zero-trust networking).
- Containers run as non-root users.

### Defense in Depth

Layer multiple security controls so that if one fails, others provide protection. No single control is relied upon exclusively.

**Layers:**

- Network: Firewalls, security groups, VPN, network segmentation.
- Application: Input validation, authentication, authorization, CSRF protection.
- Data: Encryption, access control, backup, audit logging.
- Monitoring: Intrusion detection, anomaly detection, log analysis.

### Fail-Safe Defaults

Access decisions should default to denial. If a security check fails or is missing, the request should be denied.

```typescript
// Good: deny by default
function checkAccess(user: User, resource: Resource): boolean {
  // Explicitly check each allowed case
  if (user.role === "admin") return true;
  if (resource.ownerId === user.id) return true;
  return false; // Default: deny
}

// Bad: allow by default
function checkAccess(user: User, resource: Resource): boolean {
  if (user.isBanned) return false;
  if (resource.isRestricted && user.role !== "admin") return false;
  return true; // Default: allow -- dangerous if a case is missed
}
```

### Separation of Duties

No single individual or component should have unchecked control over a critical process. Split responsibilities to require collaboration.

- Code changes require peer review before merge.
- Production deployments require approval from someone other than the author.
- Database schema changes require DBA review.
- Access to production data requires a logged, approved request.

### Economy of Mechanism

Keep security mechanisms simple. Complex security systems are harder to verify and more likely to have flaws. Prefer well-established libraries and protocols over custom implementations.

- Use established authentication protocols (OAuth 2.0, OpenID Connect) instead of custom auth.
- Use well-tested cryptographic libraries (libsodium, OpenSSL) instead of implementing crypto.
- Use parameterized queries instead of manual SQL escaping.

### Complete Mediation

Every access to every resource should be checked for authorization. Do not rely on cached authorization decisions for sensitive operations.

**Anti-pattern:** Checking authorization once at login and trusting all subsequent requests. If a user's permissions change (e.g., they are fired), the old session should not retain access.

**Implementation:** Check authorization on every API request. Use short-lived tokens. Implement token revocation for sensitive operations.

## Security Testing in CI

Automated security testing should be integrated into the CI/CD pipeline. Each tool catches a different category of vulnerabilities.

**SAST (Static Application Security Testing):** Analyze source code for vulnerabilities without executing it. Finds SQL injection, XSS, hardcoded secrets, insecure cryptography. Tools: Semgrep, CodeQL, SonarQube, Checkmarx, Snyk Code.

```yaml
# GitHub Actions SAST example
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/owasp-top-ten
          p/r2c-security-audit
          p/typescript
```

**SCA (Software Composition Analysis):** Scan dependencies for known vulnerabilities (CVEs). Tools: Dependabot, Snyk, Trivy, npm audit, pip-audit. Configure to fail the build on critical or high severity findings.

**DAST (Dynamic Application Security Testing):** Test the running application for vulnerabilities by sending crafted requests. Finds runtime issues that SAST misses. Tools: OWASP ZAP, Burp Suite, Nuclei. Run against a deployed test environment.

**Container scanning:** Scan Docker images for vulnerabilities in the base image and installed packages. Tools: Trivy, Grype, Snyk Container. Integrate into the build pipeline after image build.

**Secret scanning:** Detect accidentally committed secrets (API keys, passwords, tokens). Tools: Gitleaks, TruffleHog, detect-secrets, GitHub Secret Scanning. Run as a pre-commit hook and in CI.

**Security testing pipeline:**

```
[Code Push] -> SAST + Secret Scan -> Unit Tests -> Build ->
  Container Scan + SCA -> Integration Tests -> DAST -> Deploy
```

**Vulnerability management process:**

- Critical/High: Block deployment. Fix within 24-48 hours.
- Medium: Track in backlog. Fix within 30 days.
- Low: Track in backlog. Fix when convenient or when the area is modified.
- False positives: Document and suppress with an explanation. Review suppressions quarterly.
