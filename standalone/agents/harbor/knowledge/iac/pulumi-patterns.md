---
framework: "Pulumi Patterns"
version: "1.0"
domain: "Infrastructure as Code"
agent: "nimbus"
tags: ["pulumi", "iac", "typescript", "python", "automation-api", "crossguard"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Pulumi Patterns

Pulumi is an infrastructure as code platform that uses general-purpose programming languages (TypeScript, Python, Go, C#, Java, YAML) instead of domain-specific languages. This enables full use of programming constructs, IDE support, testing frameworks, and package ecosystems.

## Pulumi vs Terraform

### Key Differences

| Aspect | Pulumi | Terraform |
|--------|--------|-----------|
| Language | TypeScript, Python, Go, C#, Java, YAML | HCL (domain-specific) |
| State | Pulumi Cloud (default), S3, Azure Blob, GCS, local | Remote backends (S3, Azure, GCS, Terraform Cloud) |
| Secrets | Built-in encryption (per-stack) | External (Vault, AWS Secrets Manager) |
| Testing | Native language test frameworks | Terratest (Go), native .tftest.hcl |
| IDE Support | Full (autocomplete, type checking, refactoring) | HCL plugins (limited) |
| Loops/Conditions | Native language constructs | count, for_each, conditionals |
| Package Ecosystem | npm, PyPI, NuGet, Go modules | Terraform Registry |
| Policy | CrossGuard (TypeScript, Python, OPA) | Sentinel (Terraform Cloud), OPA external |
| Drift Detection | Pulumi Cloud | Terraform Cloud |

### When to Choose Pulumi

- Teams with strong programming skills who prefer TypeScript, Python, or Go over learning HCL
- Complex infrastructure logic requiring advanced programming constructs (loops, conditionals, async operations, error handling)
- Need for comprehensive unit testing of infrastructure code using familiar frameworks (Jest, pytest, Go testing)
- Desire for strong typing and IDE support (autocomplete, type checking, refactoring)
- Building reusable infrastructure components as packages distributed via npm, PyPI, or other package managers
- Greenfield projects where the team can choose their tooling

### When to Choose Terraform

- Large existing Terraform codebase and team expertise
- Need for the broadest provider ecosystem (some niche providers only have Terraform support)
- Teams with operations backgrounds who are comfortable with declarative DSLs
- Regulatory environments requiring simpler, more auditable configuration languages
- Want the largest community, most examples, and broadest hiring pool

## Programming Language Advantages

### TypeScript/JavaScript

- Strong typing with interfaces and generics
- async/await for complex orchestration
- npm ecosystem for shared libraries
- Familiar to full-stack developers
- Best IDE support (VS Code)
- Most popular Pulumi language by adoption

### Python

- Familiar to data engineering and ML teams
- Simple syntax for infrastructure definitions
- PyPI ecosystem for shared libraries
- Type hints for better IDE support

### Go

- Strong typing with compile-time checks
- Excellent performance for large stacks
- Natural fit for teams building Go-based microservices
- Concurrent operations with goroutines

### C# / .NET

- Strongly typed with excellent IDE support (Visual Studio)
- NuGet ecosystem
- Natural fit for organizations with .NET investments
- LINQ for collection operations on infrastructure resources

## Component Resources

Component resources are the primary abstraction mechanism in Pulumi, analogous to Terraform modules but implemented as classes in your chosen programming language.

### TypeScript Component Example

```typescript
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

interface VpcArgs {
    cidrBlock: string;
    azCount: number;
    tags?: Record<string, string>;
}

class Vpc extends pulumi.ComponentResource {
    public readonly vpcId: pulumi.Output<string>;
    public readonly publicSubnetIds: pulumi.Output<string>[];
    public readonly privateSubnetIds: pulumi.Output<string>[];

    constructor(name: string, args: VpcArgs, opts?: pulumi.ComponentResourceOptions) {
        super("custom:networking:Vpc", name, {}, opts);

        const vpc = new aws.ec2.Vpc(`${name}-vpc`, {
            cidrBlock: args.cidrBlock,
            enableDnsHostnames: true,
            enableDnsSupport: true,
            tags: { ...args.tags, Name: `${name}-vpc` },
        }, { parent: this });

        this.vpcId = vpc.id;

        // Create subnets, route tables, NAT gateways...
        // Full programming language available for complex logic

        this.registerOutputs({
            vpcId: this.vpcId,
        });
    }
}
```

### Design Principles

- Encapsulate related resources into a single component class
- Use typed interfaces/structs for input arguments with clear documentation
- Export output properties for consumers to reference
- Use `parent: this` for all child resources to establish correct resource hierarchy
- Components appear as a single resource in the Pulumi state and resource graph
- Distribute components as packages (npm, PyPI, NuGet) for organization-wide reuse

## Stack References

Stack references enable one Pulumi stack to read outputs from another stack. This is the mechanism for cross-stack dependencies.

### Usage

```typescript
// In networking stack: export outputs
export const vpcId = vpc.id;
export const privateSubnetIds = privateSubnets.map(s => s.id);

// In application stack: reference networking outputs
const networkStack = new pulumi.StackReference("org/networking/prod");
const vpcId = networkStack.getOutput("vpcId");
const subnetIds = networkStack.getOutput("privateSubnetIds");
```

### Best Practices

- Use stack references for well-defined interfaces between infrastructure layers
- Minimize the number of cross-stack references to reduce coupling
- Document the contract (expected outputs) between stacks
- Use the same organization and project naming conventions for consistent stack reference names
- Consider using Pulumi's stack output types for type-safe references

## Automation API

The Automation API allows you to embed Pulumi operations (up, preview, destroy, refresh) inside your own applications and scripts. It turns Pulumi into a library rather than a CLI tool.

### Use Cases

- Build custom deployment platforms and internal developer portals
- Implement multi-stack orchestration with custom logic between stack operations
- Create self-service infrastructure provisioning APIs
- Implement infrastructure testing frameworks that programmatically create and destroy stacks
- Build GitOps controllers that respond to repository events

### Example (TypeScript)

```typescript
import { LocalWorkspace } from "@pulumi/pulumi/automation";

async function deploy() {
    const stack = await LocalWorkspace.createOrSelectStack({
        stackName: "dev",
        projectName: "my-app",
        program: async () => {
            // Inline Pulumi program
            const bucket = new aws.s3.Bucket("my-bucket");
            return { bucketName: bucket.bucket };
        },
    });

    await stack.setConfig("aws:region", { value: "us-east-1" });
    const result = await stack.up({ onOutput: console.log });
    console.log(`Bucket: ${result.outputs.bucketName.value}`);
}
```

### Automation API Patterns

- **Inline Programs**: Define the Pulumi program as a function passed directly to the workspace. Useful for dynamic infrastructure generation.
- **Local Programs**: Point to a directory containing a Pulumi project. The Automation API drives CLI operations on the existing project.
- **Remote Programs**: Reference a Git repository containing the Pulumi program. Useful for centralized deployment management.

## Policy as Code with CrossGuard

CrossGuard is Pulumi's policy as code framework. Policies validate resource configurations before deployment and can enforce organizational standards.

### Policy Types

- **Resource Policies**: Validate individual resource properties. Example: ensure all S3 buckets have encryption enabled.
- **Stack Policies**: Validate the entire stack of resources together. Example: ensure the total estimated monthly cost is under a threshold, or ensure every stack has at least one monitoring resource.

### Writing Policies (TypeScript)

```typescript
import { PolicyPack, validateResourceOfType } from "@pulumi/policy";
import * as aws from "@pulumi/aws";

new PolicyPack("security-policies", {
    policies: [
        {
            name: "s3-encryption-required",
            description: "S3 buckets must have server-side encryption enabled",
            enforcementLevel: "mandatory",
            validateResource: validateResourceOfType(aws.s3.Bucket, (bucket, args, reportViolation) => {
                if (!bucket.serverSideEncryptionConfiguration) {
                    reportViolation("S3 bucket must have server-side encryption configured");
                }
            }),
        },
        {
            name: "require-tags",
            description: "All resources must have required tags",
            enforcementLevel: "mandatory",
            validateResource: (args, reportViolation) => {
                const tags = args.props.tags;
                if (tags && !tags["Environment"]) {
                    reportViolation("Resource must have an 'Environment' tag");
                }
            },
        },
    ],
});
```

### Enforcement Levels

- **advisory**: Warnings printed but deployment proceeds
- **mandatory**: Deployment blocked on violation
- **disabled**: Policy is not evaluated

### Deployment

- Publish policy packs to Pulumi Cloud for organization-wide enforcement
- Apply default policy packs to all stacks in an organization
- Override enforcement levels per stack if needed (e.g., relaxed policies for development)

## Secrets Management

Pulumi has built-in secrets management that encrypts sensitive values in the state file.

### Secret Providers

- **Pulumi Cloud (default)**: Keys managed by Pulumi Cloud. Simplest setup. Secrets are encrypted at rest in the Pulumi Cloud backend.
- **AWS KMS**: Use an AWS KMS key for encryption. `pulumi stack init --secrets-provider="awskms://alias/my-key"`
- **Azure Key Vault**: Use an Azure Key Vault key. `pulumi stack init --secrets-provider="azurekeyvault://my-vault/keys/my-key"`
- **GCP KMS**: Use a GCP KMS key. `pulumi stack init --secrets-provider="gcpkms://projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"`
- **HashiCorp Vault Transit**: Use Vault Transit secrets engine.
- **Passphrase**: Local encryption with a passphrase. Useful for local development or air-gapped environments.

### Using Secrets in Code

```typescript
const config = new pulumi.Config();
const dbPassword = config.requireSecret("dbPassword"); // Returns Output<string>, encrypted in state

const db = new aws.rds.Instance("mydb", {
    password: dbPassword, // Automatically treated as secret
});
```

- Secrets are encrypted in the state file and masked in logs and CLI output
- Mark outputs as secret: `pulumi.secret(value)` to ensure downstream consumers treat the value as secret
- All values derived from secrets are automatically treated as secrets (taint tracking)

## CI/CD Integration

### GitHub Actions

```yaml
- uses: pulumi/actions@v5
  with:
    command: preview  # or 'up' for apply
    stack-name: org/project/prod
    cloud-url: https://api.pulumi.com
  env:
    PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

### CI/CD Best Practices

- Run `pulumi preview` on pull requests to show planned changes as PR comments
- Run `pulumi up` on merge to main for automatic deployment
- Use OIDC (OpenID Connect) for cloud provider authentication instead of long-lived credentials
- Implement environment promotion: dev (auto-deploy) -> staging (auto-deploy + integration tests) -> prod (manual approval + deploy)
- Store Pulumi configuration in version control alongside the infrastructure code
- Use Pulumi Cloud Deployment Settings for centralized CI/CD configuration without per-repository pipeline setup

## Migration from Terraform

### tf2pulumi Tool

The `tf2pulumi` tool converts Terraform HCL configurations to Pulumi programs in TypeScript, Python, Go, or C#. It handles resources, data sources, variables, outputs, and most HCL expressions. Manual adjustments may be needed for complex configurations.

### Coexistence Pattern

During migration, Pulumi and Terraform can coexist:
- Use Pulumi's `terraform.state.RemoteStateReference` to read Terraform state outputs from Pulumi
- Migrate one component at a time (e.g., networking stays in Terraform, new application infrastructure uses Pulumi)
- Import existing resources into Pulumi state with `pulumi import`
