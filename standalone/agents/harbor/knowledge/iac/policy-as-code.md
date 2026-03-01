---
framework: "Policy as Code"
version: "1.0"
domain: "Cloud Governance"
agent: "nimbus"
tags: ["policy", "opa", "rego", "sentinel", "conftest", "checkov", "tfsec", "governance"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Policy as Code

Policy as Code (PaC) codifies organizational rules, security requirements, and compliance standards as machine-readable and version-controlled code. This enables automated enforcement, testing, and auditing of infrastructure policies across the software development lifecycle.

## Open Policy Agent (OPA)

OPA is an open-source, general-purpose policy engine that decouples policy decision-making from policy enforcement. It evaluates structured data (JSON) against policies written in the Rego language.

### Architecture

OPA follows a simple model: a policy consumer sends a query (input data) to OPA, which evaluates it against loaded policies and data, and returns a decision (allow/deny/structured result). OPA can run as a sidecar, daemon, library (Go), or WebAssembly module.

### Use Cases

- **Kubernetes Admission Control**: OPA Gatekeeper evaluates resource manifests before admission to the cluster
- **Terraform Plan Evaluation**: Conftest or OPA evaluates Terraform plan JSON to enforce infrastructure policies
- **API Authorization**: Microservices query OPA for fine-grained authorization decisions
- **CI/CD Pipeline Gates**: Evaluate infrastructure code, container images, and configurations against policies before deployment

## Rego Language

Rego is OPA's purpose-built declarative language for writing policies. Understanding Rego is essential for using OPA, Conftest, and Gatekeeper effectively.

### Key Concepts

- **Rules**: Define policy logic. Rules produce output values (boolean, string, object, array). A rule is true if all its body expressions are true.
- **Packages**: Organize rules into namespaces. Example: `package terraform.aws.security`
- **Input**: The data being evaluated. Accessed via the `input` keyword. For Terraform, this is the plan JSON. For Kubernetes, this is the admission review object.
- **Data**: External data loaded into OPA. Accessed via the `data` keyword. Can include reference lists (approved instance types, allowed regions), organizational metadata, and exception lists.
- **Iteration**: Rego uses implicit iteration over collections. `resource := input.resource_changes[_]` iterates over all resource changes. No explicit for loops.
- **Comprehensions**: Set, array, and object comprehensions for building collections. Example: `violations := {msg | some i; not input.resources[i].encrypted; msg := sprintf("Resource %v is not encrypted", [input.resources[i].name])}`

### Rego Example: Terraform Policy

```rego
package terraform.aws.security

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not be publicly readable", [resource.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
    resource.change.after.type == "ingress"
    msg := sprintf("Security group rule '%s' must not allow unrestricted ingress", [resource.name])
}
```

### Testing Rego Policies

OPA has a built-in test framework. Test files use the `test_` prefix convention:

```rego
package terraform.aws.security_test

import data.terraform.aws.security

test_deny_public_s3_bucket {
    result := security.deny with input as {
        "resource_changes": [{
            "type": "aws_s3_bucket",
            "name": "test-bucket",
            "change": {"after": {"acl": "public-read"}}
        }]
    }
    count(result) > 0
}
```

Run tests with `opa test . -v`. Integrate into CI for continuous policy validation.

## Conftest

Conftest is a tool that uses OPA/Rego to test structured configuration files (Terraform, Kubernetes, Dockerfiles, and more).

### Usage Patterns

- **Terraform**: `terraform show -json plan.tfplan > plan.json && conftest test plan.json`
- **Kubernetes**: `conftest test deployment.yaml --policy policy/k8s/`
- **Dockerfiles**: `conftest test Dockerfile --policy policy/docker/`
- **Helm Charts**: `helm template my-chart | conftest test -`

### Policy Organization

```
policy/
  terraform/
    deny_public_buckets.rego
    require_encryption.rego
    require_tags.rego
  kubernetes/
    deny_privileged.rego
    require_resource_limits.rego
  docker/
    deny_latest_tag.rego
    require_nonroot_user.rego
```

### CI/CD Integration

Run conftest in CI pipelines as a gate before terraform apply or kubectl apply. Fail the pipeline if any deny rules match. Use `--output` flag for structured output (JSON, TAP) for machine parsing.

## Sentinel (HashiCorp)

Sentinel is HashiCorp's policy as code framework, integrated natively with Terraform Cloud/Enterprise, Vault Enterprise, Consul Enterprise, and Nomad Enterprise.

### Key Differences from OPA

- **Commercial product**: Requires Terraform Cloud/Enterprise or other HashiCorp Enterprise products
- **Embedded integration**: Deep integration with Terraform plan, state, and configuration data via imports
- **Enforcement levels**: Advisory (warn), soft-mandatory (overridable by authorized users), hard-mandatory (cannot be overridden)
- **Language**: Sentinel has its own language (not Rego). More imperative than Rego, with main rule, named rules, and helper functions.

### Sentinel Terraform Imports

- **tfplan/v2**: Access the Terraform plan data (resource changes, output changes)
- **tfstate/v2**: Access the current Terraform state
- **tfconfig/v2**: Access the Terraform configuration (HCL source code parsed)
- **tfrun**: Access run metadata (workspace name, organization, VCS info)

### Sentinel Example

```sentinel
import "tfplan/v2" as tfplan

mandatory_tags = ["Environment", "Team", "CostCenter"]

s3_buckets = filter tfplan.resource_changes as _, rc {
    rc.type is "aws_s3_bucket" and
    (rc.change.actions contains "create" or rc.change.actions contains "update")
}

main = rule {
    all s3_buckets as _, bucket {
        all mandatory_tags as tag {
            bucket.change.after.tags contains tag
        }
    }
}
```

## AWS Config Rules

AWS Config Rules evaluate the compliance of AWS resource configurations continuously. They complement IaC policy checks by providing runtime enforcement.

### Types

- **AWS Managed Rules**: Pre-built rules covering common compliance checks. Over 200 available. Examples: `s3-bucket-server-side-encryption-enabled`, `ec2-instance-no-public-ip`, `iam-password-policy`, `rds-instance-public-access-check`.
- **Custom Rules (Lambda)**: Write custom evaluation logic in Lambda. Triggered by configuration changes or periodically. Full flexibility over evaluation logic.
- **Custom Rules (Guard)**: Use AWS CloudFormation Guard DSL to write rules without Lambda. Simpler for teams familiar with declarative policy languages.

### Remediation

Attach SSM Automation documents to Config Rules for automatic or manual remediation. Example: if a security group allows unrestricted SSH, automatically remove the rule. Use manual remediation requiring approval for production environments.

### Conformance Packs

Group related Config Rules into conformance packs. AWS provides sample packs for CIS Benchmarks, HIPAA, PCI DSS, NIST 800-53, and more. Deploy conformance packs across an organization using AWS Organizations. Track compliance scores per pack.

## Azure Policy

Azure Policy evaluates resource properties during creation and on existing resources. It provides both preventive (deny) and detective (audit) controls.

### Policy Effects

- **Deny**: Block resource creation or modification that violates policy
- **Audit**: Log non-compliance without blocking
- **Modify**: Add, update, or remove resource properties (e.g., add missing tags)
- **DeployIfNotExists**: Deploy companion resources automatically (e.g., deploy diagnostic settings)
- **AuditIfNotExists**: Log when expected companion resources are missing
- **DenyAction**: Block specific management operations (e.g., prevent deletion)
- **Disabled**: Temporarily disable a policy

### Policy Definition Structure

Azure policies are JSON documents with mode (All, Indexed), policy rule (if/then), and parameters. Group related policies into initiatives (policy sets). Assign policies or initiatives at management group, subscription, or resource group scope. Use exemptions for approved exceptions with expiration dates.

### Built-in Initiatives

Azure provides built-in initiatives mapped to compliance frameworks: CIS Microsoft Azure Foundations, NIST SP 800-53, PCI DSS, ISO 27001, HIPAA HITRUST, and more. These provide a comprehensive starting point for compliance. Customize by adding organization-specific policies.

## GCP Organization Policies

GCP Organization Policies use constraints to restrict resource configurations across the organization hierarchy.

### Constraint Types

- **Boolean Constraints**: Enable or disable a behavior. Example: `compute.disableSerialPortAccess` (true/false).
- **List Constraints**: Allow or deny specific values. Example: `gcp.resourceLocations` allows only `us-east1` and `us-west1`.
- **Custom Constraints**: Define custom constraints using CEL (Common Expression Language) on resource attributes. Example: require all GKE clusters to enable Workload Identity.

### Key Organization Policies

- Restrict resource locations for data residency
- Disable service account key creation to force workload identity usage
- Restrict VM external IP addresses to enforce private networking
- Enforce uniform bucket-level access on Cloud Storage
- Restrict shared VPC host and service project associations
- Disable default service account creation
- Require OS Login for Compute Engine instances

### Hierarchy and Inheritance

Policies are inherited from parent to child nodes (Organization to Folder to Project). Child nodes can merge with, replace, or restore the parent policy depending on the constraint type and configuration. Use tags for conditional policy enforcement: apply different policies to resources with specific tag values.

## Checkov

Checkov is an open-source static analysis tool for infrastructure as code. It supports Terraform, CloudFormation, Kubernetes, Helm, ARM templates, Bicep, Serverless Framework, and Dockerfiles.

### Capabilities

- Over 1,000 built-in policies covering AWS, Azure, GCP, and Kubernetes security best practices
- Scans Terraform HCL files and plan JSON output
- Supports custom policies written in Python or YAML
- Framework support for CIS Benchmarks, SOC2, HIPAA, and other compliance standards
- Graph-based policies for evaluating relationships between resources (e.g., database connected to public subnet)
- SBOM generation for infrastructure components
- Secrets scanning to detect hardcoded credentials

### Usage

Run `checkov -d .` to scan the current directory. Use `--check` to run specific checks and `--skip-check` to exclude specific checks. Use `--bc-api-key` to connect to Prisma Cloud (Bridgecrew) for centralized policy management and drift detection.

### Custom Policies

Write custom Checkov policies in Python (for complex logic) or YAML (for simple attribute checks). YAML policies use a declarative format with attribute conditions and connection state checks. Python policies extend the BaseResourceCheck class with a scan_resource_conf method.

## tfsec (now Trivy)

tfsec has been integrated into Trivy as `trivy config`. It performs static analysis of Terraform code for security misconfigurations.

### Key Features

- Fast execution (does not require terraform init)
- Supports Terraform HCL and plan JSON
- Over 400 built-in rules for AWS, Azure, GCP
- Custom rules via YAML or Rego
- Inline ignores (`#tfsec:ignore:aws-s3-enable-bucket-logging`) with required reason and optional expiry
- Sarif output for integration with GitHub Advanced Security, VS Code, and other tools

### Integration

Run as a pre-commit hook for immediate feedback. Run in CI for gate enforcement. Output as JUnit XML for CI reporting or SARIF for GitHub code scanning alerts. Combine with Terraform plan scanning for more accurate results (resolving variable values and data source lookups).

## KICS (Keeping Infrastructure as Code Secure)

KICS is an open-source tool by Checkmarx for detecting security vulnerabilities, compliance issues, and infrastructure misconfigurations.

### Supported Platforms

Terraform, CloudFormation, Ansible, Kubernetes, Docker, Helm, OpenAPI, ARM templates, Bicep, Pulumi, and more. One of the broadest platform coverages among IaC scanners.

### Key Differentiators

- Over 3,000 queries across all supported platforms
- Low false positive rate through precise query design
- Custom query support using Rego
- CIS Benchmark mapping for compliance reporting
- Detailed remediation guidance for each finding
- Can scan entire repositories or individual files
- Supports scanning of remote Terraform modules

## Policy as Code Strategy

### Layered Enforcement

Implement policy enforcement at multiple stages for defense in depth:

1. **IDE/Pre-commit**: Run tfsec/Checkov for immediate developer feedback. Fast, local execution.
2. **Pull Request/CI**: Run Conftest, Checkov, and tfsec on every pull request. Block merge on violations. Show policy violations as PR comments.
3. **Terraform Plan Gate**: Run OPA/Conftest or Sentinel against the Terraform plan JSON. Catches issues that static analysis misses (computed values, data source results).
4. **Cloud Provider Policies**: AWS Config Rules, Azure Policy, GCP Organization Policies. Catch resources created outside IaC or policy drift.
5. **Runtime**: OPA Gatekeeper for Kubernetes admission control. Cloud provider guardrails (SCPs, Organization Policies) for API-level enforcement.

### Policy Development Lifecycle

- Write policies as code in version control alongside infrastructure code
- Write unit tests for every policy (OPA test framework, Sentinel test framework)
- Review policies in pull requests like any other code change
- Use advisory/warning mode initially when deploying new policies to avoid disrupting teams
- Graduate policies to mandatory enforcement after a warning period
- Maintain exception processes with audit trails for approved deviations
- Review and update policies quarterly to align with evolving threats and compliance requirements
