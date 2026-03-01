---
framework: "Terraform Patterns"
version: "1.0"
domain: "Infrastructure as Code"
agent: "nimbus"
tags: ["terraform", "iac", "modules", "state", "testing", "hcl"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Terraform Patterns

Terraform by HashiCorp is the most widely adopted infrastructure as code tool for multi-cloud provisioning. This document covers module design, state management, advanced HCL patterns, testing strategies, and enterprise workflows.

## Module Design

Modules are the primary mechanism for code reuse and abstraction in Terraform. A well-designed module encapsulates a logical grouping of resources with a clean interface.

### Module Structure

A standard module directory layout should include: main.tf for core resource definitions, variables.tf for input variables with descriptions and validation rules, outputs.tf for output values that consumers need, and versions.tf for required providers and Terraform version constraints. Additionally, include an examples directory with basic and complete usage examples, and a tests directory for automated testing. Generate documentation with terraform-docs for the README.

### Module Design Principles

- **Single Responsibility**: Each module should manage one logical component (a VPC, a database cluster, an application deployment). Avoid god modules that create entire environments.
- **Composable**: Modules should be composable building blocks. A higher-level root module or composition layer wires smaller modules together. Example: a vpc module and an eks-cluster module are composed in a root module for a specific environment.
- **Opinionated with Escape Hatches**: Provide sensible defaults for common use cases but expose variables for customization. Use variable validation to enforce constraints.
- **Minimal Interface**: Expose only the inputs and outputs that consumers need. Internal implementation details should not leak through the interface.
- **Version Pinning**: Always pin module versions in the consumer. Use semantic versioning for published modules. Breaking changes require a major version bump. Never reference `ref=main` in production.

### Input Variable Best Practices

- Always include `description` for every variable for documentation and discoverability
- Use `type` constraints: string, number, bool, list(string), map(string), object({...})
- Use `validation` blocks for business logic constraints (CIDR format, name patterns, allowed values beyond simple types)
- Use `default` values for optional configuration; omit defaults for required inputs
- Group related variables into objects rather than having dozens of flat variables
- Use `sensitive = true` for variables containing secrets (prevents display in logs and plan output)
- Use `nullable = false` when a variable must always have a non-null value

### Output Best Practices

- Output all values that downstream consumers might need (IDs, ARNs, endpoints, DNS names)
- Include `description` for every output for clear documentation
- Use `sensitive = true` for outputs containing secrets
- Output structured data using objects for complex resources to avoid excessive individual outputs

## State Management

Terraform state maps real-world resources to your configuration. Proper state management is critical for team collaboration and production safety.

### Remote Backends

- **S3 + DynamoDB (AWS)**: The most common backend. S3 stores the state file with versioning enabled for history. DynamoDB provides state locking to prevent concurrent modifications. Enable server-side encryption with a dedicated KMS key. Use a dedicated S3 bucket per organization or team.
- **Azure Storage + Blob Lease**: Azure Storage Account with blob container for state files. Uses blob lease for state locking. Enable soft delete and versioning on the storage account for recovery.
- **GCS (GCP)**: Google Cloud Storage bucket for state. Built-in object versioning for state history. State locking via GCS object metadata.
- **Terraform Cloud/Enterprise**: Managed backend with built-in locking, versioning, encryption, and access control. Recommended for teams already using Terraform Cloud.

### State Locking

State locking prevents concurrent operations that could corrupt the state. When a Terraform operation begins, it acquires a lock. If another operation is already running, the new operation waits or fails. Always use a backend that supports locking. If a lock is stuck because a process crashed, use `terraform force-unlock <LOCK_ID>` carefully after verifying no operation is actually running. Never manually edit the state file directly. Use `terraform state` subcommands for state manipulation.

### Workspaces

Terraform workspaces allow multiple state files per configuration. Each workspace has its own state.

- **CLI Workspaces**: Useful for managing multiple environments (dev, staging, prod) from the same configuration. Access the workspace name via `terraform.workspace` for conditional logic. Workspaces share the same backend configuration, making it impossible to use different credentials per workspace. For production environments requiring different providers or credentials, separate root modules or Terraform Cloud workspaces per environment are preferred.
- **Terraform Cloud Workspaces**: More feature-rich. Each workspace has its own variables, state, run history, and access controls. Can be linked to VCS branches for GitOps workflows. Supports team-level permissions and approval workflows.

### State File Organization Strategies

- **Per-Environment State**: Separate state file per environment (dev, staging, prod). Provides blast radius isolation. A failed apply in dev cannot affect prod state.
- **Per-Component State**: Separate state for networking, compute, database, and other layers. Allows teams to manage their components independently. Use `terraform_remote_state` data source or SSM Parameter Store for cross-state references.
- **Per-Account/Subscription State**: In multi-account architectures, each account has its own state files. Aligns with cloud provider account boundaries.
- **Recommended Combination**: Combine per-environment and per-component. Example state key structure: `prod/networking/terraform.tfstate`, `prod/compute/terraform.tfstate`, `staging/networking/terraform.tfstate`.

## Provider Patterns

### Provider Configuration

- Pin provider versions to a specific minor version range using the pessimistic constraint operator (~> 5.0 allows 5.x but not 6.0)
- Use `required_providers` block in versions.tf for explicit provider source and version constraints
- Use provider aliases for multi-region or multi-account deployments

### Multi-Region Pattern

Define a default provider for the primary region and an aliased provider for each secondary region. Resources reference the specific provider using the `provider` meta-argument. This pattern enables deploying resources to multiple regions from a single configuration, which is essential for disaster recovery and global architectures.

### Multi-Account Pattern

Use provider aliases with different `assume_role` configurations to manage resources across multiple AWS accounts from a single Terraform configuration. The central pipeline assumes roles in target accounts with appropriate permissions. Alternatively, use separate root modules per account for stronger isolation. The assumed role approach works well for hub-and-spoke patterns where a central automation account manages resources in spoke accounts.

## Data Sources

Data sources allow Terraform to query existing infrastructure and use the returned data in configurations without managing those resources.

### Common Patterns

- **Look up AMI IDs**: Use the aws_ami data source with owner and filter arguments to find the latest AMI matching criteria. Avoids hardcoding AMI IDs that change between regions and over time.
- **Reference Existing Resources**: Use data sources like aws_vpc, aws_subnet, and aws_security_group to reference resources managed by other Terraform configurations or created outside Terraform.
- **Remote State**: Use `terraform_remote_state` to read outputs from another Terraform state file. Enables loose coupling between Terraform configurations while maintaining typed references.
- **External Data**: Use the external data source to run a script and consume its JSON output. Use sparingly; prefer native data sources. The script must output valid JSON to stdout.
- **SSM/Secrets Manager**: Query SSM Parameter Store or Secrets Manager as an alternative to remote state for cross-stack references. More flexible than remote state because it does not require knowledge of the backend configuration.

## Dynamic Blocks and Advanced HCL

### Dynamic Blocks

Dynamic blocks generate repeated nested blocks based on a collection. They are useful when the number of nested blocks (such as ingress rules in a security group or attribute mappings) is determined by input data. Use dynamic blocks when the repetition is genuinely variable. Avoid overusing them as they reduce readability. When a resource has a fixed set of nested blocks, prefer static blocks.

### for_each vs count

- **count**: Use when creating multiple identical resources or when the presence/absence of a resource is conditional (count = var.create_resource ? 1 : 0). Resources are identified by index (resource[0], resource[1]). Removing an item from the middle of a list causes all subsequent resources to be recreated due to index shift.
- **for_each**: Use when creating multiple resources from a map or set. Resources are identified by key (resource["key_name"]). Removing an item only affects that specific resource. Preferred over count for most use cases because it avoids index-based resource addressing.
- **Rule of thumb**: Use for_each with a map when each resource has a unique identifier. Use count only for simple conditional creation (0 or 1) or when creating truly identical resources where ordering does not matter.

### Key Functions and Expressions

- `for` expressions for transforming collections: create new lists or maps from existing ones with filtering and transformation
- `try()` for safely accessing nested values with a fallback default when the value might not exist
- `coalesce()` for selecting the first non-null and non-empty-string value from a list of candidates
- `merge()` for combining maps, commonly used for merging default tags with custom tags
- `templatefile()` for rendering template files with variable substitution, cleaner than inline heredocs for complex templates
- `cidrsubnet()` for calculating subnet CIDR blocks from a VPC CIDR programmatically, essential for automated network design
- `lookup()` for retrieving a value from a map with a default fallback
- `flatten()` for flattening nested lists, useful when combining outputs from multiple module instances

## Testing Terraform

### Static Analysis

- **terraform validate**: Syntax and basic configuration checking. Fast, run on every commit in CI.
- **terraform plan**: The most important gate. Review plans carefully. The diff should be explainable and expected. Automated plan output in pull requests enables team review.
- **Checkov/tfsec/KICS**: Static analysis for security misconfigurations. Catches common mistakes like public S3 buckets, unrestricted security groups, missing encryption. Run in CI on every pull request.
- **Infracost**: Cost estimation in CI to show the cost impact of every change before it is applied. Integrates with pull request workflows.

### Integration Testing with Terratest

Terratest is a Go library for provisioning real infrastructure, validating it, and tearing it down. The test pattern: configure Terraform options, defer terraform.Destroy for cleanup, run terraform.InitAndApply, read outputs, validate with assertions, and optionally make API calls to verify resource properties. Run against a dedicated test account, use unique names with random suffixes, and use t.Parallel() for concurrent tests.

### Terraform Native Testing (v1.6+)

Terraform 1.6 introduced native testing with .tftest.hcl files. Tests define run blocks that execute plan or apply commands and include assert blocks that validate conditions. Native tests support plan-only mode for fast validation and apply mode for full integration testing. They can mock providers and override resources for isolated testing. This is a lighter-weight alternative to Terratest for teams that do not want to write Go code. Test files can reference the module's examples directory as test fixtures.

## Terraform Cloud and Enterprise

### Key Features

- **VCS Integration**: Automatically trigger runs when code is pushed to version control repositories. Speculative plans on pull requests show what would change.
- **Remote Execution**: Plan and apply run in Terraform Cloud's managed environment for consistent execution across the team. Eliminates "works on my machine" issues.
- **Policy as Code (Sentinel)**: Define policies checked between plan and apply. Enforce organizational standards like mandatory tags, approved regions, encryption requirements. Policies have advisory, soft-mandatory, and hard-mandatory enforcement levels.
- **Private Registry**: Host private Terraform modules and providers with versioning and discovery. Teams find and consume approved modules.
- **Cost Estimation**: Estimate cost impact of changes before apply. Integrate with Sentinel for cost-based policies (e.g., block changes exceeding $500/month increase).
- **Run Tasks**: Integrate external tools (security scanners, compliance checks, custom validators) into the Terraform Cloud workflow at pre-plan, post-plan, or pre-apply stages.
- **Drift Detection**: Periodically check if real infrastructure matches the Terraform state. Alert when manual changes cause drift. Available in Terraform Cloud Plus tier.

### Workspace Organization

Create one workspace per environment per component for proper blast radius isolation. Use workspace variables for environment-specific configuration (region, instance sizes, replica counts). Use variable sets for shared configuration across workspaces (provider credentials, common tags, organization settings). Use run triggers to chain workspace executions when one component depends on another (networking completion triggers compute workspace). Implement team-based access controls to ensure teams can only modify their own workspaces.

## Import and State Migration

### Importing Existing Resources

The `terraform import` command brings an existing resource under Terraform management by writing it into the state file. You must write the corresponding resource configuration manually before running import. After import, run terraform plan to verify the configuration matches the actual resource. Terraform 1.5 introduced import blocks for declarative imports that can be planned and reviewed as part of normal workflow, which is safer than the imperative import command.

### State Manipulation Commands

- `terraform state mv`: Rename resources or move them between modules without destroying and recreating. Essential during refactoring.
- `terraform state rm`: Remove a resource from state without destroying it. Useful when moving resources to a different state file or when a resource was deleted outside Terraform.
- `terraform state pull/push`: Download or upload state for backup or advanced manipulation.
- Always backup state before any manipulation: `terraform state pull > backup.tfstate`

### Moved Blocks (Terraform 1.1+)

The `moved` block declaratively records resource renames and module refactoring. When you rename a resource or move it to a different module path, add a moved block to tell Terraform to update the state rather than destroy and recreate. This is safer than manual state manipulation, works in team environments without coordination, and serves as documentation of the refactoring history. Remove moved blocks after all state files have been updated (typically after one full deployment cycle).

## Anti-Patterns to Avoid

- **Monolithic state**: Putting everything in one state file. One bad apply can destroy everything. Split by layer and component.
- **Manual changes alongside Terraform**: Creates state drift. Enforce Terraform-only changes for managed resources through SCPs or organization policies.
- **Hardcoded values**: Every value that differs between environments or might change over time should be a variable or local.
- **Ignoring the plan**: Always review terraform plan output before applying. Automated applies without human review are dangerous in production.
- **Unpinned provider versions**: An unintended provider upgrade can change resource behavior or break configurations.
- **Excessive use of provisioners**: local-exec and remote-exec provisioners are a last resort. Prefer cloud-init, user data, or configuration management tools.
