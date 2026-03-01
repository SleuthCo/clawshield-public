---
framework: "OWASP Top 10"
version: "2021"
domain: "Web Application Security"
agent: "sentinel"
tags: ["owasp", "web-security", "application-security", "top-10", "vulnerabilities"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# OWASP Top 10 — 2021 Edition

The OWASP Top 10 represents the most critical security risks to web applications. This document provides detailed descriptions, examples, prevention strategies, and testing approaches for each category.

## A01:2021 — Broken Access Control

**Description:** Access control enforces policy such that users cannot act outside of their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits.

**Common Vulnerabilities:**
- Insecure Direct Object References (IDOR): manipulating identifiers to access other users' data (e.g., changing /api/users/123 to /api/users/456)
- Missing function-level access control: accessing admin endpoints without proper authorization
- Path traversal: accessing files outside intended directory via ../
- Metadata manipulation: tampering with JWT tokens, cookies, or hidden fields to elevate privileges
- CORS misconfiguration allowing unauthorized cross-origin access
- Forced browsing to authenticated pages or accessing API endpoints directly
- Bypassing access control by modifying URL, application state, HTML pages, or API requests

**Prevention:**
- Implement access control in a centralized, server-side module
- Deny by default: require explicit grants for every resource
- Implement RBAC or ABAC with consistent enforcement across all endpoints
- Use indirect object references (map user-accessible IDs to internal references)
- Rate limit API and controller access to minimize automated attack impact
- Invalidate JWT tokens on the server side after logout
- Log access control failures and alert administrators on repeated violations
- Disable web server directory listing and remove sensitive metadata from web roots
- Implement proper CORS policy with restrictive origin allowlists

**Testing Approaches:**
- Automated: Burp Suite active scanner, OWASP ZAP forced browse
- Manual: attempt horizontal privilege escalation by changing resource IDs
- Manual: attempt vertical privilege escalation by accessing admin functions
- Test CORS headers with cross-origin requests from unauthorized domains
- Verify access controls for every API endpoint and HTTP method

## A02:2021 — Cryptographic Failures

**Description:** Failures related to cryptography (or lack thereof) that lead to exposure of sensitive data. Previously known as Sensitive Data Exposure, this refocusing highlights the root cause: cryptographic failures.

**Common Vulnerabilities:**
- Data transmitted in cleartext (HTTP, FTP, SMTP without TLS)
- Weak or deprecated cryptographic algorithms (MD5, SHA1 for passwords, DES, RC4)
- Default or weak cryptographic keys and missing key rotation
- Missing certificate validation or pinning
- Passwords stored using reversible encryption or unsalted hashes
- Insufficient entropy in initialization vectors or random number generation
- Use of deprecated protocols (SSLv3, TLS 1.0, TLS 1.1)

**Prevention:**
- Classify data by sensitivity and apply controls accordingly
- Encrypt all data in transit with TLS 1.2+ (prefer TLS 1.3)
- Encrypt sensitive data at rest using AES-256-GCM or ChaCha20-Poly1305
- Hash passwords with Argon2id, bcrypt, or scrypt with appropriate work factors
- Use authenticated encryption modes (GCM, CCM) instead of unauthenticated modes
- Generate keys using cryptographically secure random number generators
- Implement proper key management with HSM for critical keys
- Disable TLS compression and older protocol versions
- Set HSTS headers with appropriate max-age and includeSubDomains

**Testing Approaches:**
- SSL/TLS configuration testing: testssl.sh, SSLyze, Qualys SSL Labs
- Static analysis for hard-coded keys and weak algorithms
- Review password storage mechanisms for appropriate hashing
- Check data classification and encryption of sensitive fields in databases

## A03:2021 — Injection

**Description:** An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized; dynamic queries or non-parameterized calls are used without context-aware escaping; hostile data is used within ORM search parameters.

**Injection Types:**
- SQL Injection: manipulating SQL queries through user input
- NoSQL Injection: manipulating NoSQL queries (MongoDB, DynamoDB)
- OS Command Injection: executing system commands through application input
- LDAP Injection: manipulating LDAP queries for directory enumeration
- Expression Language (EL) Injection: injecting into template engines
- ORM Injection: exploiting ORM query builders
- Header Injection: CRLF injection in HTTP headers
- XPath Injection: manipulating XML queries

**Prevention:**
- Use parameterized queries (prepared statements) for all database interactions
- Use positive server-side input validation (allowlists over denylists)
- Escape special characters using context-specific output encoding
- Use LIMIT and other SQL controls to prevent mass disclosure
- Implement ORM safely with parameterized query methods
- Avoid concatenating user input into dynamic queries of any kind
- Apply least privilege to database accounts used by the application
- Use stored procedures where appropriate (but still parameterize inputs)

**Testing Approaches:**
- SAST tools scanning for concatenated queries (SonarQube, Checkmarx, Semgrep)
- DAST scanning for injection vulnerabilities (Burp Suite, OWASP ZAP)
- Manual testing with payloads for each injection type
- Code review focusing on data flow from input to query execution
- Fuzzing input parameters with injection payloads

## A04:2021 — Insecure Design

**Description:** Insecure design refers to weaknesses in the design and architecture of the application, not implementation bugs. A secure implementation of an insecure design is still insecure. This category highlights the need for threat modeling and secure design patterns.

**Common Issues:**
- Missing or inadequate threat modeling during design phase
- Absence of security requirements in design specifications
- Business logic flaws that cannot be caught by testing alone
- Missing rate limiting on sensitive operations (password reset, payment)
- Insufficient anti-automation controls for critical business flows
- Trust boundary violations in system architecture
- Missing security controls for identified threat scenarios

**Prevention:**
- Integrate threat modeling (STRIDE, PASTA) into the design phase
- Establish and use a secure design pattern library
- Develop abuse cases and misuse stories alongside user stories
- Implement defense in depth with multiple layers of controls
- Separate tenant data at the design level in multi-tenant applications
- Limit resource consumption by user and service tier
- Design with the assumption that all inputs are malicious

**Testing Approaches:**
- Design review with security architects before implementation
- Threat model review covering STRIDE categories
- Business logic testing with abuse case scenarios
- Architecture review for trust boundary violations

## A05:2021 — Security Misconfiguration

**Description:** The application lacks appropriate security hardening across any part of the application stack, or has improperly configured permissions on cloud services. This includes missing security headers, unnecessary features enabled, default accounts and passwords, and overly verbose error handling.

**Common Misconfigurations:**
- Default credentials on applications, databases, and infrastructure
- Unnecessary features enabled: ports, services, pages, accounts, privileges
- Error handling revealing stack traces or internal implementation details
- Missing security headers (CSP, X-Content-Type-Options, X-Frame-Options)
- Misconfigured cloud storage permissions (public S3 buckets)
- Missing or permissive CORS configuration
- XML External Entity (XXE) processing enabled
- Directory listing enabled on web servers

**Prevention:**
- Implement hardening procedures using CIS Benchmarks as baseline
- Automated configuration management (Ansible, Chef, Puppet, Terraform)
- Minimal platform: remove unused features, components, documentation, samples
- Review and update configurations as part of patch management
- Implement security headers via web server/application configuration
- Automated scanning of cloud configurations (CSPM tools)
- Segmented application architecture with proper isolation between components
- Disable detailed error messages in production; log details server-side only

**Testing Approaches:**
- Automated configuration scanning (Nessus, Qualys, cloud CSPM)
- Review HTTP security headers (Mozilla Observatory, SecurityHeaders.com)
- Check for default credentials against known defaults
- Cloud configuration auditing (ScoutSuite, Prowler, CloudSploit)

## A06:2021 — Vulnerable and Outdated Components

**Description:** Applications and APIs using components with known vulnerabilities or components that are no longer supported. This includes OS, web/application server, DBMS, APIs, libraries, and all components both directly included and transitive dependencies.

**Risk Factors:**
- No inventory of component versions (client-side and server-side)
- Software is out of support or unpatched (OS, server, DBMS)
- Vulnerability scanning not performed regularly
- Underlying platform or framework not updated timely
- Developers not testing compatibility of updated libraries
- Component configurations not secured (see A05)

**Prevention:**
- Maintain inventory of all component versions using SBOM
- Continuously monitor for vulnerabilities: CVE databases, NVD, vendor advisories
- Implement Software Composition Analysis (SCA) in CI/CD pipeline
- Only obtain components from official sources over secure links
- Monitor for unmaintained libraries and plan migration
- Establish a patch management process with SLAs by severity
- Remove unused dependencies and features
- Use dependency lock files to ensure reproducible builds

**Testing Approaches:**
- SCA scanning: Snyk, Dependabot, OWASP Dependency-Check, npm audit
- Container image scanning: Trivy, Grype, Snyk Container
- Infrastructure scanning for outdated OS and middleware
- Regular penetration testing targeting known CVEs in stack

## A07:2021 — Identification and Authentication Failures

**Description:** Confirmation of the user's identity, authentication, and session management are critical for protecting against authentication-related attacks. Previously named Broken Authentication.

**Common Vulnerabilities:**
- Permits brute force or credential stuffing attacks
- Permits default, weak, or well-known passwords
- Uses weak credential recovery (knowledge-based questions)
- Uses plain text, encrypted, or weakly hashed password data stores
- Missing or ineffective MFA
- Exposes session identifier in URL
- Reuses session identifier after successful login (session fixation)
- Does not properly invalidate sessions during logout or inactivity

**Prevention:**
- Implement multi-factor authentication to prevent automated attacks
- Do not ship with default credentials
- Implement weak password checks against top 10,000 worst passwords
- Align password length, complexity, and rotation with NIST SP 800-63b
- Harden registration, credential recovery, and API pathways against enumeration
- Limit failed login attempts with progressive delays and lockout
- Use server-side, secure session manager generating random session IDs
- Session IDs should not be in URLs; invalidate after logout and idle timeout

**Testing Approaches:**
- Automated: credential stuffing with common password lists
- Test account lockout mechanisms and bypass possibilities
- Verify session management: fixation, timeout, invalidation
- Test MFA implementation and bypass vectors
- Check password storage mechanism through code review

## A08:2021 — Software and Data Integrity Failures

**Description:** Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes using software from untrusted sources, insecure CI/CD pipelines, and auto-update mechanisms without integrity verification.

**Common Issues:**
- Using libraries from untrusted CDNs or repositories without verification
- Insecure deserialization of untrusted data
- CI/CD pipeline without proper access controls and integrity verification
- Auto-update functionality downloading updates without signature verification
- Objects or data serialized without integrity protection for use by the client

**Prevention:**
- Use digital signatures to verify software and data integrity
- Ensure libraries and dependencies are from trusted repositories
- Implement SRI (Subresource Integrity) for CDN-hosted resources
- Use SBOM tools to verify component integrity
- Ensure CI/CD pipeline has proper access controls, segregation, and configuration
- Serialized data sent to untrusted clients has integrity checks (digital signature)
- Review code and configuration changes before deployment

**Testing Approaches:**
- Review CI/CD pipeline security controls and access
- Test deserialization with crafted payloads (ysoserial, marshalsec)
- Verify integrity checks on software updates and package downloads
- Review code signing and deployment verification processes

## A09:2021 — Security Logging and Monitoring Failures

**Description:** Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs anytime when events are not logged, logs are not monitored, or alerting thresholds are not properly set.

**Common Failures:**
- Auditable events (logins, failed logins, high-value transactions) not logged
- Warnings and errors generate no, inadequate, or unclear log messages
- Logs only stored locally without centralization
- Appropriate alerting thresholds not established or effective
- Penetration testing and DAST scans do not trigger alerts
- Application unable to detect or alert on active attacks in real time
- Log data available to users, leading to information leakage or tampering

**Prevention:**
- Log all authentication events (success and failure), access control failures, input validation failures
- Ensure logs contain sufficient context: who, what, when, where, outcome
- Encode log data correctly to prevent log injection attacks
- Centralize logs in a SIEM with tamper-evident storage
- Establish alerting for suspicious activities and known attack patterns
- Implement real-time monitoring and automated response where feasible
- Establish incident response and recovery plans (see NIST SP 800-61r2)
- Use structured logging formats (JSON) for easier parsing and analysis

**Testing Approaches:**
- Review logging configuration for completeness
- Test that security events generate appropriate log entries
- Verify log centralization and retention
- Test alerting rules with simulated attack patterns
- Verify log integrity protection mechanisms

## A10:2021 — Server-Side Request Forgery (SSRF)

**Description:** SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. This allows attackers to coerce the application to send crafted requests to unexpected destinations, even when protected by firewalls, VPN, or network ACLs.

**Attack Scenarios:**
- Access internal services: http://localhost/admin, http://internal-service/api
- Cloud metadata API access: http://169.254.169.254/latest/meta-data/
- Port scanning internal networks through the application
- Read local files using file:// protocol
- Access internal databases, caches, or message queues
- Bypass Web Application Firewalls by routing through the application
- DNS rebinding to bypass domain-based SSRF protections

**Prevention:**
- Sanitize and validate all client-supplied URLs
- Enforce URL schema, port, and destination allowlists
- Disable HTTP redirections from user-supplied URLs
- Block requests to private IP ranges (RFC 1918) and link-local addresses
- Do not send raw responses from server-side requests to clients
- Use a dedicated network segment for outbound requests from applications
- Implement IMDSv2 (AWS) requiring token for metadata access
- Use DNS resolution checking to prevent DNS rebinding attacks

**Testing Approaches:**
- Test with internal IP addresses and localhost
- Test with cloud metadata endpoints
- Test with various URL schemas (file://, gopher://, dict://)
- Test with DNS rebinding payloads
- Test with URL encoding and bypass techniques
- Use Burp Collaborator or similar for out-of-band detection
