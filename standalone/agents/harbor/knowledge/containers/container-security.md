---
framework: "Container Security"
version: "1.0"
domain: "Security"
agent: "nimbus"
tags: ["containers", "security", "scanning", "admission-control", "runtime", "supply-chain"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Container Security

Container security spans the entire lifecycle from build to deploy to runtime. This document covers image scanning, admission control, pod security, network policies, runtime security, and supply chain integrity.

## Image Scanning

Image scanning analyzes container images for known vulnerabilities (CVEs), misconfigurations, and exposed secrets before deployment.

### Trivy

Trivy (by Aqua Security) is the most widely adopted open-source vulnerability scanner for containers, filesystems, Git repositories, and IaC.

**Capabilities**:
- OS package vulnerabilities (Alpine, Debian, Ubuntu, RHEL, Amazon Linux)
- Language-specific package vulnerabilities (npm, pip, Go, Java, Ruby, Rust, .NET)
- IaC misconfigurations (Terraform, CloudFormation, Kubernetes, Dockerfile)
- Secret detection (API keys, passwords, tokens embedded in images)
- License scanning for open-source license compliance
- SBOM generation (CycloneDX, SPDX formats)

**Integration Points**:
- CI/CD pipelines: `trivy image --exit-code 1 --severity CRITICAL,HIGH myimage:latest`
- Container registries: Trivy Operator scans images in-cluster, Harbor has built-in Trivy integration
- IDE plugins: Scan during development before pushing images
- Kubernetes admission: Trivy Operator generates VulnerabilityReport CRDs that admission policies can reference

### Grype

Grype (by Anchore) is an open-source vulnerability scanner focused on container images and filesystems.

**Key Features**:
- Fast scanning using a pre-built vulnerability database
- Supports multiple distros and language ecosystems
- Integrates with Syft for SBOM generation
- Policy-based gating with `--fail-on` severity threshold
- JSON, CycloneDX, and table output formats

### Registry Scanning

- **Amazon ECR**: Built-in scanning with enhanced scanning (powered by Inspector) for continuous vulnerability monitoring. Basic scanning uses Clair.
- **Azure Container Registry**: Integrates with Microsoft Defender for Containers for vulnerability scanning on push and continuous re-scanning.
- **Google Artifact Registry**: Automated vulnerability scanning with Container Analysis. Integrates with Binary Authorization.
- **Harbor**: Open-source registry with built-in Trivy scanning, vulnerability policies, and image signing.

### Scanning Best Practices

- Scan images in CI before pushing to a registry (shift left)
- Enable continuous scanning in the registry for newly discovered CVEs in existing images
- Set severity thresholds: block CRITICAL in production, allow WARNING in development
- Maintain a vulnerability exception process for accepted risks with expiration dates
- Monitor base image vulnerabilities and rebuild when patches are available
- Scan both the base image and application dependencies

## Admission Controllers

Admission controllers intercept Kubernetes API requests after authentication and authorization but before persistence. They validate, mutate, or reject resource specifications.

### OPA Gatekeeper

Gatekeeper is the Kubernetes-native policy engine built on OPA. It uses CRDs (ConstraintTemplate, Constraint) to define and apply policies.

**ConstraintTemplate**: Defines a reusable policy template with Rego logic and parameters.

**Constraint**: An instance of a ConstraintTemplate applied to specific Kubernetes resources with specific parameters.

**Common Gatekeeper Policies**:
- Require container images from approved registries only
- Deny containers running as root (runAsNonRoot)
- Require resource requests and limits on all containers
- Deny privileged containers
- Require specific labels on all resources
- Restrict hostPath volumes
- Enforce allowed volume types
- Deny services of type LoadBalancer in non-production namespaces

**Gatekeeper Features**:
- Mutation support: Modify resources to meet policy requirements (add labels, set defaults)
- External data: Fetch data from external sources for policy evaluation (image signature verification, external allow lists)
- Audit: Evaluate existing resources against constraints and report violations without blocking
- Constraint Framework library: Pre-built constraint templates for common policies

### Kyverno

Kyverno is a Kubernetes-native policy engine that uses YAML-based policies instead of Rego, making it more accessible to Kubernetes administrators.

**Policy Types**:
- **Validate**: Check resource configurations against rules. Deny or audit on violation.
- **Mutate**: Modify resources to match desired state (add labels, inject sidecars, set defaults).
- **Generate**: Create companion resources automatically (create NetworkPolicy when a namespace is created).
- **Verify Images**: Validate container image signatures and attestations directly in admission control.

**Advantages over Gatekeeper**: YAML-based policies (no Rego), built-in image verification, resource generation, and a simpler learning curve for Kubernetes teams.

## Pod Security Standards

Pod Security Standards (PSS) define three profiles for pod security, replacing the deprecated PodSecurityPolicy (PSP).

### Profiles

- **Privileged**: Unrestricted. No security restrictions applied. For system-level workloads that require full access (CNI plugins, storage drivers). Should be limited to infrastructure namespaces.
- **Baseline**: Minimally restrictive. Prevents known privilege escalations. Allows common application patterns. Blocks: privileged containers, hostNetwork, hostPID, hostIPC, hostPath volumes, certain capabilities. Appropriate for most applications.
- **Restricted**: Heavily restricted. Follows security hardening best practices. Additionally blocks: running as root, all capabilities except NET_BIND_SERVICE, all volume types except configMap/emptyDir/projected/secret/PVC, privilege escalation. Appropriate for security-sensitive workloads.

### Enforcement Modes

- **enforce**: Reject pods violating the profile
- **warn**: Allow but emit a warning to the user
- **audit**: Allow but log the violation in the audit log

Apply via namespace labels: `pod-security.kubernetes.io/enforce: restricted`

### Migration Strategy

1. Audit first: Apply restricted profile in audit mode to all namespaces
2. Review audit logs to identify violations
3. Fix workloads that violate the restricted profile (set securityContext fields)
4. Apply baseline in enforce mode and restricted in warn/audit mode
5. Gradually move to restricted enforce as workloads are updated

## Network Policies

Network policies control traffic flow between pods, namespaces, and external endpoints. By default, all pod-to-pod traffic is allowed. Network policies implement a deny-by-default, allow-by-exception model.

### Default Deny All

Apply a deny-all ingress and egress policy to every namespace as a baseline. Then create specific allow policies for required traffic flows.

### Common Network Policy Patterns

- **Allow ingress from ingress controller only**: Pods receive traffic only from the ingress controller namespace, not directly from other pods
- **Allow intra-namespace traffic**: Pods within the same namespace can communicate freely
- **Allow specific cross-namespace traffic**: Frontend namespace can reach backend namespace on specific ports
- **Allow egress to DNS**: All pods need DNS resolution (port 53 to kube-dns)
- **Allow egress to specific external services**: Restrict egress to known external APIs and databases
- **Deny egress to metadata service**: Prevent pods from accessing cloud provider metadata (169.254.169.254) to mitigate SSRF attacks

### Network Policy Implementations

- **Calico**: Full NetworkPolicy support plus Calico-specific extensions (GlobalNetworkPolicy, DNS-based rules, application layer policies). Most feature-rich.
- **Cilium**: eBPF-based networking with NetworkPolicy support, CiliumNetworkPolicy CRD for L7 policies (HTTP, gRPC, Kafka), and transparent encryption.
- **Azure Network Policy**: Basic NetworkPolicy support for AKS.
- **Amazon VPC CNI Network Policy**: NetworkPolicy support for EKS.

## Runtime Security

Runtime security monitors container behavior during execution to detect anomalous or malicious activity.

### Falco

Falco (CNCF incubating) is the de facto standard for Kubernetes runtime security. It uses kernel system calls to detect unexpected behavior.

**Detection Examples**:
- Container spawning a shell (potential reverse shell)
- Writing to /etc or other sensitive directories
- Reading sensitive files (/etc/shadow, /etc/passwd)
- Unexpected network connections (outbound to suspicious IPs)
- Process privilege escalation (setuid, setgid)
- Filesystem modifications in containers that should be immutable
- Kubernetes API access from an unexpected source
- Cryptomining activity (based on process and network patterns)

**Architecture**: Falco uses a kernel module or eBPF probe to capture system calls. Rules define what constitutes a violation. Alerts are sent to stdout, syslog, HTTP webhook, gRPC, or message queues. Falco Sidekick provides integrations with Slack, PagerDuty, Elasticsearch, S3, and more.

**Falco Talon**: Automated response engine that takes actions based on Falco alerts (kill container, cordon node, create network policy, notify team).

### Tetragon (Cilium)

Tetragon provides eBPF-based security observability and runtime enforcement at the kernel level. Unlike Falco's detection-only model, Tetragon can enforce policies by terminating processes or blocking network connections at the kernel level before they complete.

## Supply Chain Security

### Container Image Signing (Sigstore/Cosign)

Cosign signs and verifies container images using keyless signing (OIDC identity) or traditional key-based signing.

**Keyless Signing Flow**:
1. Developer or CI system authenticates with an OIDC provider (GitHub, Google, Microsoft)
2. Cosign requests a short-lived certificate from Fulcio (Sigstore CA)
3. The image digest is signed with the ephemeral private key
4. The signature is stored in Rekor (transparency log) for auditing
5. Consumers verify the signature by checking the OIDC identity and the Rekor log entry

**Integration with Admission Control**: Kyverno and Sigstore Policy Controller can verify cosign signatures and attestations during admission. Only images signed by trusted identities are allowed into the cluster.

### Software Bill of Materials (SBOM)

An SBOM lists all components (packages, libraries, dependencies) in a software artifact. Critical for vulnerability management and license compliance.

**Generation Tools**:
- **Syft** (Anchore): Generates SBOMs from container images and filesystems. Supports CycloneDX, SPDX, and Syft JSON formats.
- **Trivy**: Generates SBOMs as part of vulnerability scanning.
- **Docker Scout**: Built into Docker Desktop for SBOM generation and analysis.

**SBOM Standards**:
- **CycloneDX**: OWASP standard. Rich metadata support. Widely adopted in security tooling.
- **SPDX**: Linux Foundation standard. Strong license compliance focus. ISO/IEC 5962:2021.

### Attestation

Attestations are signed statements about a software artifact (image). Beyond signing (proving who built it), attestations prove properties about how it was built.

- **SLSA (Supply-chain Levels for Software Artifacts)**: Framework for supply chain integrity. Levels 1-4 define increasing requirements for build integrity, provenance, and isolation.
- **In-Toto Attestations**: Standardized attestation format. Predicates include provenance (build info), vulnerability scan results, SBOM, and custom attestations.
- **Cosign Attestations**: `cosign attest` attaches in-toto attestations to container images. Verify with `cosign verify-attestation`.

### Supply Chain Best Practices

- Sign all container images in CI/CD with cosign (keyless with OIDC identity)
- Generate SBOMs for all images and store alongside the image in the registry
- Enforce signature verification at admission with Kyverno or Gatekeeper
- Use Binary Authorization (GCP) or Notation (AWS ECR) for cloud-native signature verification
- Pin base images by digest (not tag) to prevent tag mutation attacks
- Use minimal base images (distroless, scratch, Alpine) to reduce attack surface
- Implement SLSA Level 2+ build provenance for production images
