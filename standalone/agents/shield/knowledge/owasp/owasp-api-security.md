---
framework: "OWASP API Security Top 10"
version: "2023"
domain: "API Security"
agent: "sentinel"
tags: ["owasp", "api-security", "rest", "graphql", "bola", "authentication"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# OWASP API Security Top 10 — 2023 Edition

APIs are the backbone of modern applications. This document details the top API-specific security risks, their exploitation patterns, and defensive strategies.

## API1:2023 — Broken Object Level Authorization (BOLA)

**Description:** APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object-level authorization checks should be implemented in every function that accesses a data source using an input from the user.

**Attack Patterns:**
- Manipulate resource IDs in API requests to access unauthorized data: GET /api/v1/accounts/12345 changed to /api/v1/accounts/12346
- Enumerate objects through sequential or predictable identifiers
- Replace user IDs in request bodies to access other users' resources
- Access objects through relationship traversal (e.g., /users/123/orders instead of /users/456/orders)
- GraphQL queries accessing nodes by ID without authorization checks
- Batch endpoints processing mixed authorized and unauthorized IDs

**Real-World Impact:**
- Unauthorized access to personally identifiable information (PII)
- Modification or deletion of other users' data
- Financial fraud through unauthorized account access
- HIPAA/GDPR violations through unauthorized health/personal data access

**Prevention Strategies:**
- Implement authorization checks at the object level for every data access function
- Use random, non-sequential identifiers (UUIDs) to reduce enumeration risk
- Write integration tests specifically for authorization logic
- Implement policy-based authorization (OPA, Cedar) with centralized evaluation
- Log and monitor for object-level access violations
- Use the authenticated user's session to derive ownership rather than client-supplied IDs
- Implement rate limiting to slow enumeration attacks
- Apply authorization checks consistently in REST, GraphQL, and webhook endpoints

## API2:2023 — Broken Authentication

**Description:** Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities temporarily or permanently.

**Common Vulnerabilities:**
- Missing authentication on internal or sensitive API endpoints
- Weak authentication: API keys as sole authentication mechanism
- Missing rate limiting on authentication endpoints (brute force)
- Credentials transmitted in URL query parameters (logged in server/proxy logs)
- Token validation bypass through algorithm confusion (JWT none/HS256 vs RS256)
- Missing token expiration or excessively long token lifetimes
- Permissive CORS allowing credential theft from any origin
- API keys exposed in client-side code or version control

**Prevention Strategies:**
- Use standard authentication protocols: OAuth 2.0, OpenID Connect
- Implement MFA for sensitive API operations
- Enforce rate limiting and account lockout on authentication endpoints
- Use short-lived access tokens (15-60 minutes) with refresh token rotation
- Validate JWT signatures, algorithms, expiration, and audience claims
- Never transmit credentials in URL parameters
- Implement API key rotation and restrict key scope
- Use mTLS for service-to-service authentication
- Centralize authentication logic to avoid inconsistent implementations

## API3:2023 — Broken Object Property Level Authorization

**Description:** This category combines the previous concepts of Excessive Data Exposure and Mass Assignment. The common root cause is lack of or improper authorization validation at the object property level, leading to information exposure or manipulation by unauthorized parties.

**Excessive Data Exposure:**
- API responses include more data than the client needs
- Sensitive fields returned even when not displayed in the UI
- Reliance on client-side filtering to restrict visible data
- Full object graphs serialized including internal or sensitive properties

**Mass Assignment:**
- API accepts and processes properties that the client should not be able to set
- Example: setting is_admin=true in a user profile update request
- Binding all request parameters to object properties without filtering
- Auto-binding frameworks mapping request fields to database columns
- Allowing clients to modify read-only fields (created_at, owner_id)

**Prevention Strategies:**
- Define and enforce response schemas that only include necessary properties
- Never rely on client-side filtering for data security
- Implement property-level authorization: different users see different properties
- Use explicit allowlists for writeable properties on each endpoint
- Apply DTOs (Data Transfer Objects) to control input/output serialization
- Test API responses for data over-exposure using automated checks
- Review API specifications for sensitive data in response schemas
- Implement field-level encryption for highly sensitive properties

## API4:2023 — Unrestricted Resource Consumption

**Description:** Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. APIs are vulnerable when they do not limit the amount of resources that can be consumed by a single request or aggregated over time.

**Attack Scenarios:**
- Missing pagination: requesting all records in a single query
- Uploading very large files or many files simultaneously
- Sending requests that trigger expensive operations (complex queries, report generation)
- GraphQL complexity attacks: deeply nested or highly branched queries
- Batch operations processing unlimited items per request
- Regex Denial of Service (ReDoS) through crafted input patterns
- Resource exhaustion through concurrent connection flooding

**Prevention Strategies:**
- Implement rate limiting per user, per IP, per API key with sliding windows
- Set maximum request payload size limits
- Enforce pagination with maximum page size limits
- Implement query complexity analysis and limits for GraphQL
- Set timeouts for database queries and external service calls
- Use circuit breakers for upstream service protection
- Implement cost-based rate limiting (complex operations consume more quota)
- Monitor and alert on resource utilization anomalies
- Implement request queuing with capacity limits
- Use CDN and caching to reduce origin load

## API5:2023 — Broken Function Level Authorization

**Description:** Complex access control policies with different hierarchies, groups, and roles create a tendency for authorization flaws. Attackers exploit these flaws to access other users' resources or administrative functions.

**Attack Patterns:**
- Accessing administrative API endpoints as a regular user
- Changing HTTP method to bypass authorization (GET to PUT/DELETE)
- Accessing management APIs through URL manipulation (/api/v1/users/delete)
- Guessing administrative endpoint patterns (/api/admin/, /api/internal/)
- Exploiting different authorization between REST and corresponding GraphQL mutations
- Accessing undocumented internal APIs exposed on the same host

**Prevention Strategies:**
- Implement consistent authorization module enforced across all endpoints
- Deny by default: require explicit access grants for every endpoint
- Enforce authorization based on user role, group membership, and context
- Separate administrative and user-facing APIs on different hosts/paths
- Test authorization for every endpoint and HTTP method combination
- Review API routes for unprotected administrative functionality
- Implement API gateway-level authorization policies
- Use function-level authorization decorators in code
- Regular authorization matrix review against implemented access controls

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Description:** APIs that expose business flows without compensating controls are at risk from automated exploitation. This is not necessarily an implementation bug but rather a design flaw that fails to account for automated abuse.

**Business Flows at Risk:**
- Purchasing flow: automated scalping of limited inventory (bots buying concert tickets)
- Account creation: automated creation of fake accounts for spam or fraud
- Comment/review systems: automated posting of fake reviews or spam
- Referral/reward systems: automated exploitation of promotional programs
- Content scraping: automated extraction of proprietary data
- Reservation systems: automated holding and releasing of resources

**Prevention Strategies:**
- Identify business flows critical to the business and assess automation risk
- Implement device fingerprinting for non-browser clients
- Use behavioral analysis to detect non-human interaction patterns
- Implement CAPTCHA for sensitive flows (but balance with user experience)
- Rate limit by business function, not just technical endpoint
- Block known automation tooling through fingerprinting
- Implement anti-bot solutions (Cloudflare Bot Management, PerimeterX)
- Analyze usage patterns and implement velocity checks
- Require additional verification for bulk or high-velocity operations

## API7:2023 — Server-Side Request Forgery (SSRF)

**Description:** SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL. This allows attackers to force the application to send crafted requests to unexpected destinations.

**API-Specific SSRF Vectors:**
- Webhook URLs: user-provided callback URLs for event notifications
- File import from URL: document/image fetching from user-supplied URLs
- Custom integration endpoints: user-configured API endpoints
- PDF generation from user-supplied HTML/URLs
- URL preview/unfurl functionality
- GraphQL data federation fetching from attacker-controlled schemas

**Prevention Strategies:**
- Validate and sanitize all user-supplied URLs
- Maintain an allowlist of permitted domains and IP ranges
- Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Block requests to link-local addresses (169.254.0.0/16)
- Disable HTTP redirects or validate redirect destinations
- Use a dedicated outbound proxy for URL fetching with filtering
- Implement DNS resolution checking before request execution
- Monitor outbound requests for unexpected internal access patterns
- Disable unnecessary URL schemes (file://, gopher://, ftp://)

## API8:2023 — Security Misconfiguration

**Description:** APIs and their supporting infrastructure can contain misconfigurations at any level, from network to application, that can be exploited.

**Common Misconfigurations:**
- Missing or misconfigured TLS (HTTP endpoints, weak cipher suites)
- Missing security headers in API responses
- Permissive CORS: Access-Control-Allow-Origin: * with credentials
- Verbose error messages exposing stack traces and internal details
- Unnecessary HTTP methods enabled (TRACE, OPTIONS returning too much)
- Missing rate limiting and throttling configuration
- Default configurations on API gateways and load balancers
- Exposed debug endpoints, Swagger/OpenAPI documentation in production
- Missing request/response validation against API specification
- Outdated or unpatched API infrastructure components

**Prevention Strategies:**
- Implement automated configuration scanning in CI/CD pipeline
- Enforce TLS 1.2+ with strong cipher suites
- Configure minimal CORS policies specific to allowed origins
- Implement generic error responses; log details server-side
- Disable unnecessary HTTP methods and restrict OPTIONS responses
- Remove debug endpoints and documentation from production deployments
- Apply CIS Benchmarks for API gateways and web servers
- Regular security configuration review and hardening
- API specification validation at runtime (request/response contract testing)

## API9:2023 — Improper Inventory Management

**Description:** APIs tend to expose more endpoints than traditional web applications, making proper and updated documentation particularly important. A proper inventory of hosts and deployed API versions is also important.

**Common Issues:**
- Undocumented or shadow APIs running in production
- Deprecated API versions still accessible without retirement
- Exposed internal or development API endpoints in production
- Missing inventory of third-party API integrations
- Inconsistent API versioning leading to confusion about active versions
- Microservice APIs without centralized discovery

**Prevention Strategies:**
- Maintain a centralized API inventory with ownership and lifecycle status
- Implement API gateway as a single entry point for all API traffic
- Use automated API discovery to identify shadow and undocumented APIs
- Define and enforce API versioning and retirement policies
- Restrict production deployments to documented and approved APIs
- Implement production runtime API discovery and inventory tools
- Integrate API security testing with inventory management
- Review and decommission deprecated API versions on schedule

## API10:2023 — Unsafe Consumption of APIs

**Description:** Developers tend to trust data received from third-party APIs more than user input. Attackers target integrated third-party services to indirectly compromise the API.

**Risk Scenarios:**
- Processing data from third-party APIs without validation (injection via upstream)
- Following redirects from third-party APIs to attacker-controlled servers
- Trusting third-party API responses without integrity verification
- Missing rate limiting on third-party API consumption
- Exposing sensitive data in requests to third-party APIs
- Insecure transport when communicating with third-party APIs

**Prevention Strategies:**
- Validate all data received from third-party APIs (same as user input)
- Implement schema validation on third-party API responses
- Use TLS and verify certificates for all third-party API communication
- Maintain an allowlist of known redirect targets
- Do not blindly follow third-party API redirections
- Implement circuit breakers for third-party API dependencies
- Implement timeouts and resource limits for third-party API calls
- Monitor third-party API behavior for anomalies
- Conduct security assessments of critical third-party API providers
