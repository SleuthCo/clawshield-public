---
framework: "LLM Security Controls"
version: "1.0"
domain: "AI Security Operations"
agent: "sentinel"
tags: ["llm-security", "input-filtering", "output-validation", "ai-governance", "sandboxing", "pii-detection"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# LLM Deployment Security Controls

This document covers practical security controls for deploying and operating Large Language Model applications, including input filtering, output validation, rate limiting, content safety, audit logging, sandboxing, and AI governance.

## Input Filtering

**Purpose:** Prevent malicious, harmful, or out-of-scope inputs from being processed by the LLM, reducing risk of prompt injection, abuse, and unintended behavior.

**Filtering Layers:**

**Syntactic Filtering:**
- Maximum input length enforcement (token limits appropriate to use case)
- Character set validation (block control characters, unusual Unicode)
- Encoding normalization (prevent Unicode and encoding-based bypasses)
- URL and code block detection and handling
- Template injection prevention for input that will be used in templates

**Semantic Filtering:**
- Topic classification: ensure requests are within the application's intended scope
- Intent detection: identify requests for harmful, illegal, or policy-violating content
- Toxicity scoring: use classifiers to detect abusive, hateful, or threatening language
- Prompt injection detection: classifier trained to identify injection attempts
- Language detection: restrict to supported languages if applicable

**Contextual Filtering:**
- User permission validation: verify the requesting user has authorization
- Session context analysis: detect multi-turn manipulation patterns
- Rate-based analysis: flag users with unusually high request volumes
- Behavioral analysis: detect deviation from normal user interaction patterns
- Source validation: verify requests originate from authorized applications/channels

**Implementation Patterns:**
- Pipeline architecture: sequential filter stages with fail-fast behavior
- Classifier ensemble: multiple detection models for increased coverage
- Allowlist approach for structured inputs: validate against expected patterns
- Denylist approach for known attacks: block known injection patterns
- Confidence thresholds: route uncertain inputs to human review

**Evasion Resistance:**
- Test filters against known bypass techniques (encoding, multilingual, adversarial)
- Regular adversarial testing and red teaming of filter effectiveness
- Monitor and update filters as new attack patterns emerge
- Avoid relying solely on pattern matching; use semantic understanding
- Defense in depth: multiple independent filtering mechanisms

## Output Validation

**Purpose:** Ensure LLM outputs do not contain harmful content, sensitive information, policy violations, or security risks before delivery to users or downstream systems.

**Validation Categories:**

**Content Safety Validation:**
- Harmful content detection: violence, self-harm, illegal activities
- Bias and fairness checking: detect discriminatory or stereotyping outputs
- Misinformation detection: flag outputs contradicting known facts
- Toxicity scoring on generated content
- Compliance checking: verify outputs comply with organizational policies

**Security Validation:**
- Sensitive information detection: scan for PII, credentials, API keys, internal URLs
- System information leakage: detect exposure of infrastructure details, model details
- Injection propagation: ensure outputs do not contain executable code intended for downstream systems
- Cross-site scripting prevention: sanitize outputs rendered in web contexts
- Command injection prevention: validate outputs used in system operations

**Structural Validation:**
- Schema validation: verify structured outputs (JSON, XML) conform to expected format
- Length constraints: ensure outputs are within acceptable bounds
- Format compliance: verify outputs match the expected response format
- Citation accuracy: validate that referenced sources exist and support claims
- Consistency checking: verify output is consistent with conversation context

**Grounding and Factuality:**
- RAG grounding verification: check that outputs are supported by retrieved documents
- Attribution checking: verify claims can be traced to source material
- Hallucination detection: identify confident assertions not supported by evidence
- Confidence scoring: flag low-confidence outputs for review
- Factual consistency: check for internal contradictions within the response

## Rate Limiting

**Purpose:** Prevent abuse, control costs, and ensure fair resource allocation across users and applications.

**Rate Limiting Dimensions:**
- Per-user rate limits: restrict individual user request volume
- Per-API-key rate limits: restrict application-level consumption
- Per-IP rate limits: prevent anonymous abuse
- Global rate limits: protect overall system capacity
- Per-model rate limits: different limits for different model capabilities

**Rate Limiting Strategies:**
- Token bucket: allows burst traffic within configured limits
- Sliding window: smooth rate enforcement over rolling time periods
- Fixed window: simple per-interval limits
- Adaptive rate limiting: adjust limits based on system load and health
- Cost-based limiting: weight limits by computational cost of requests

**Rate Limiting Parameters:**
- Requests per minute/hour for standard usage
- Tokens per minute for throughput control
- Concurrent request limits for resource management
- Daily/monthly quotas for cost management
- Burst allowance for legitimate usage spikes

**Abuse Detection:**
- Monitor for model extraction patterns: systematic, diverse queries
- Detect prompt injection automation: rapid, varied injection attempts
- Identify credential stuffing against authentication layer
- Flag unusual usage patterns: off-hours, geographic anomaly
- Detect resource exhaustion attempts: maximum-length inputs, complex reasoning

## Content Safety

**Safety Classification Framework:**

**Category Taxonomy:**
- Violence and graphic content
- Self-harm and suicide content
- Sexual content and exploitation
- Hate speech and discrimination
- Harassment and bullying
- Illegal activities and instructions
- Weapons and dangerous materials
- Misinformation and disinformation
- Privacy violations
- Intellectual property infringement

**Safety Implementation:**
- Multi-label classifiers for content categories
- Severity scoring: informational, advisory, warning, block
- Configurable thresholds per deployment context
- Appeal and feedback mechanism for false positive handling
- Regular calibration against human evaluations

**Content Safety Services:**
- Azure AI Content Safety: multi-modal content classification
- OpenAI Moderation API: text content safety scoring
- Perspective API (Google): toxicity and attribute scoring
- Custom safety classifiers trained on domain-specific data
- Ensemble approach combining multiple services for higher accuracy

**Age-Appropriate and Context-Appropriate Controls:**
- Audience-based content restrictions (public-facing vs. internal)
- Industry-specific content policies (healthcare, finance, education)
- Jurisdictional content requirements (regional legal compliance)
- Brand safety guidelines enforcement

## PII Detection

**Purpose:** Identify and protect personally identifiable information in both inputs and outputs to maintain privacy compliance and prevent data exposure.

**PII Categories:**
- Direct identifiers: names, email addresses, phone numbers, SSN, passport numbers
- Quasi-identifiers: date of birth, ZIP code, gender (combinable for identification)
- Sensitive categories: medical data, financial data, racial/ethnic data, biometric data
- Digital identifiers: IP addresses, device IDs, cookies, account numbers

**Detection Methods:**
- Named Entity Recognition (NER): ML models trained to identify PII entities
- Regular expressions: pattern matching for structured PII (SSN, phone, email, credit card)
- Dictionary-based: matching against known name lists, location databases
- Context-aware detection: using surrounding text to identify ambiguous PII
- Custom entity models trained on organization-specific data formats

**PII Handling Actions:**
- Redaction: replace PII with placeholder tokens ([NAME], [EMAIL], etc.)
- Masking: partially obscure PII while preserving format (J*** D**, ***-**-1234)
- Encryption: encrypt PII fields for authorized access only
- Tokenization: replace PII with reversible tokens for processing
- Blocking: reject requests containing PII above sensitivity threshold

**Compliance Requirements:**
- GDPR: minimize PII processing, enforce data subject rights
- CCPA/CPRA: disclose PII collection, honor opt-out requests
- HIPAA: protect Protected Health Information (PHI) in healthcare contexts
- PCI DSS: protect cardholder data, never store CVV
- SOC 2: implement controls for PII protection

## Audit Logging

**Purpose:** Maintain comprehensive records of all LLM interactions for security monitoring, compliance, debugging, and accountability.

**Log Contents:**
- Request metadata: timestamp, user ID, session ID, source IP, API key
- Input: full prompt text (or hash if content is sensitive)
- Output: full response text (or hash if content is sensitive)
- Model metadata: model ID, version, temperature, parameters
- Token usage: input tokens, output tokens, total cost
- Guardrail decisions: which filters triggered, actions taken
- Tool/function calls: what tools were invoked, with what parameters
- Latency metrics: time-to-first-token, total response time
- Error information: failures, retries, timeouts

**Log Security:**
- Encrypt logs at rest and in transit
- Implement access controls: restrict who can read interaction logs
- Tamper-evident storage: detect unauthorized log modification
- Retention policies: define based on regulatory and business requirements
- PII handling in logs: redact or hash sensitive data in log entries
- Separate logs for audit (immutable) and operational (searchable) purposes

**Monitoring Use Cases:**
- Security: detect prompt injection attempts, data exfiltration, abuse patterns
- Compliance: demonstrate policy adherence, support audit requests
- Quality: track hallucination rates, user satisfaction, output accuracy
- Cost: monitor token usage, identify optimization opportunities
- Operations: track latency, errors, and availability metrics

**Log Analysis:**
- Real-time alerting on security events (injection attempts, PII exposure)
- Trend analysis on content safety trigger rates
- User behavior analytics for abuse detection
- Cost optimization through usage pattern analysis
- Model performance monitoring for drift detection

## Sandboxing Tool Use

**Purpose:** When LLMs invoke external tools, functions, or APIs, sandboxing prevents the LLM from performing unintended or harmful actions through its tool access.

**Sandboxing Principles:**
- Least privilege: each tool has minimum required permissions
- Isolation: tool execution is isolated from the host system and other tools
- Validation: all tool inputs are validated against strict schemas
- Timeout: tool execution has maximum time limits
- Audit: all tool invocations are logged with full context
- Reversibility: prefer reversible actions; require confirmation for irreversible ones

**Tool Access Control:**
- Define explicit tool manifests declaring capabilities and permissions
- User-level tool authorization: different users can access different tools
- Per-session tool scoping: restrict available tools based on conversation context
- Dynamic permission elevation: require confirmation for sensitive tool operations
- Tool dependency chains: limit recursive or cascading tool invocations

**Code Execution Sandboxing:**
- Container-based isolation for LLM-generated code execution
- gVisor or similar kernel-level sandboxing for untrusted code
- Resource limits: CPU, memory, disk, network
- Network isolation: no internet access from execution sandbox by default
- Time limits: maximum execution duration with forced termination
- Output capture and validation before returning to LLM
- No persistent state between executions

**API Call Sandboxing:**
- API allowlisting: LLM can only call pre-approved APIs
- Parameter validation: strict schema validation on all API call parameters
- Rate limiting per tool per user per session
- Response filtering: sanitize API responses before returning to LLM
- Mock/dry-run mode for testing tool use before enabling live execution

## Human-in-the-Loop Controls

**Purpose:** Ensure human oversight for consequential or high-risk LLM actions, maintaining accountability and preventing harmful autonomous behavior.

**Approval Triggers:**
- Financial transactions above defined thresholds
- Data modifications (create, update, delete) in production systems
- External communications (emails, messages) on behalf of users
- Access control changes (permission grants, account modifications)
- Irreversible actions (deletion, submission, publication)
- Actions affecting multiple users or systems
- Actions in high-risk domains (healthcare, legal, financial)

**Approval Workflow Design:**
- Clear presentation of proposed action with context
- Risk assessment summary for the approver
- Time-limited approval windows with auto-expiry
- Escalation paths for unreviewed approvals
- Audit trail of all approval decisions
- Configurable approval policies by action type and risk level

**Human Review Patterns:**
- Pre-execution review: human approves before action is taken
- Post-execution review: action executes but is monitored; undo if problematic
- Spot-check review: random sampling of automated actions for quality assurance
- Escalation review: automated system flags uncertain cases for human decision
- Periodic batch review: regular review of accumulated automated actions

## AI Governance

**Governance Framework Components:**

**Policy:**
- Acceptable use policy for AI/LLM systems
- Data governance policy for AI training and inference data
- Model lifecycle management policy
- AI risk management policy aligned with NIST AI RMF
- Ethical AI principles and guidelines
- Third-party AI service evaluation criteria

**Process:**
- AI system registration and inventory
- Risk assessment for new AI deployments (AI Impact Assessment)
- Regular model evaluation and monitoring
- Incident response procedures for AI-related incidents
- Change management for model updates and retraining
- Vendor risk management for third-party AI services

**Roles:**
- AI Safety Officer / Responsible AI Lead
- Model owners responsible for lifecycle management
- Data stewards responsible for training data quality and compliance
- Security team responsible for AI security controls
- Legal/compliance team responsible for regulatory adherence
- Ethics review board for high-risk AI applications

**Compliance and Standards:**
- EU AI Act: risk-based regulation of AI systems
- NIST AI Risk Management Framework (AI RMF 1.0)
- ISO/IEC 42001: AI management system standard
- IEEE 7000 series: ethical AI design standards
- Industry-specific AI regulations (FDA for medical AI, financial regulators)
- State-level AI regulations (Colorado AI Act, NYC Local Law 144)

**AI Incident Response:**
- Classification of AI-specific incidents (bias events, hallucination impact, safety failures)
- Investigation procedures for AI incidents
- Rollback and containment procedures
- Communication protocols for AI-related incidents
- Root cause analysis incorporating model and data analysis
- Continuous improvement based on AI incident learnings
