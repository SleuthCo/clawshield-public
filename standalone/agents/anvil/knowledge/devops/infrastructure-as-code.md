---
framework: "Infrastructure as Code"
version: "1.0"
domain: "DevOps"
agent: "friday"
tags: ["terraform", "pulumi", "cloudformation", "iac", "state-management", "policy-as-code"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Infrastructure as Code

## Terraform Patterns

Terraform uses HashiCorp Configuration Language (HCL) to define infrastructure declaratively. It manages a state file that maps declared resources to real infrastructure.

**Resource definition:**

```hcl
resource "aws_ecs_service" "api" {
  name            = "${var.environment}-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 3000
  }

  lifecycle {
    ignore_changes = [desired_count]  # Let autoscaler manage
  }

  tags = local.common_tags
}
```

**Data sources for referencing existing resources:**

```hcl
data "aws_vpc" "main" {
  filter {
    name   = "tag:Name"
    values = ["production-vpc"]
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
```

**Locals for computed values:**

```hcl
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  common_tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Service     = var.service_name
    Team        = var.team
  }
  name_prefix = "${var.environment}-${var.service_name}"
}
```

## Pulumi

Pulumi uses general-purpose programming languages (TypeScript, Python, Go, C#) for infrastructure definition. This provides full access to language features: loops, conditionals, functions, type checking, and testing.

```typescript
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const config = new pulumi.Config();
const environment = config.require("environment");

// VPC with subnets
const vpc = new aws.ec2.Vpc("main", {
  cidrBlock: "10.0.0.0/16",
  enableDnsHostnames: true,
  tags: { Name: `${environment}-vpc`, Environment: environment },
});

// Generate subnets programmatically
const azs = ["us-east-1a", "us-east-1b", "us-east-1c"];
const publicSubnets = azs.map((az, index) =>
  new aws.ec2.Subnet(`public-${az}`, {
    vpcId: vpc.id,
    cidrBlock: `10.0.${index}.0/24`,
    availabilityZone: az,
    mapPublicIpOnLaunch: true,
    tags: { Name: `${environment}-public-${az}` },
  })
);

// ECS cluster and service
const cluster = new aws.ecs.Cluster("api", {
  name: `${environment}-api`,
  settings: [{ name: "containerInsights", value: "enabled" }],
});

// Export outputs
export const vpcId = vpc.id;
export const subnetIds = publicSubnets.map(s => s.id);
export const clusterArn = cluster.arn;
```

**Advantages over Terraform:** Real programming languages enable abstraction through functions and classes, compile-time type checking catches errors before deployment, native testing with standard test frameworks, IDE support with autocomplete and refactoring.

**Component resources for reusable abstractions:**

```typescript
class DatabaseCluster extends pulumi.ComponentResource {
  public readonly endpoint: pulumi.Output<string>;
  public readonly port: pulumi.Output<number>;

  constructor(name: string, args: DatabaseArgs, opts?: pulumi.ComponentResourceOptions) {
    super("custom:database:Cluster", name, {}, opts);

    const cluster = new aws.rds.Cluster(`${name}-cluster`, {
      engine: "aurora-postgresql",
      masterUsername: args.username,
      masterPassword: args.password,
      vpcSecurityGroupIds: args.securityGroupIds,
      dbSubnetGroupName: args.subnetGroupName,
    }, { parent: this });

    this.endpoint = cluster.endpoint;
    this.port = cluster.port;
    this.registerOutputs({ endpoint: this.endpoint, port: this.port });
  }
}
```

## CloudFormation

AWS CloudFormation uses JSON or YAML templates. It is natively integrated with AWS and supports all AWS services immediately on launch.

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: API Service Stack

Parameters:
  Environment:
    Type: String
    AllowedValues: [development, staging, production]
  ImageUri:
    Type: String

Conditions:
  IsProduction: !Equals [!Ref Environment, production]

Resources:
  ECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Sub "${Environment}-api"
      ClusterSettings:
        - Name: containerInsights
          Value: enabled

  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Sub "${Environment}-api"
      Cpu: !If [IsProduction, '1024', '256']
      Memory: !If [IsProduction, '2048', '512']
      NetworkMode: awsvpc
      RequiresCompatibilities: [FARGATE]
      ContainerDefinitions:
        - Name: api
          Image: !Ref ImageUri
          PortMappings:
            - ContainerPort: 3000
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref LogGroup
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: api

Outputs:
  ClusterArn:
    Value: !GetAtt ECSCluster.Arn
    Export:
      Name: !Sub "${Environment}-cluster-arn"
```

**CloudFormation features:** Stack sets for multi-account/multi-region deployments, change sets for preview before applying, drift detection, custom resources for extending with Lambda functions, nested stacks for modularity.

## State Management

Terraform state maps declared resources to real infrastructure. Proper state management is critical for team workflows.

**Remote state backends:** Store state remotely for team access and locking. AWS S3 + DynamoDB (locking), Terraform Cloud, Google Cloud Storage, Azure Blob Storage.

```hcl
terraform {
  backend "s3" {
    bucket         = "myorg-terraform-state"
    key            = "services/api/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
```

**State file security:** The state file contains sensitive data (resource IDs, outputs, sometimes passwords). Encrypt at rest, restrict access, never commit to Git. Use state-level encryption and IAM policies.

**State operations:**

- `terraform state list` -- List all resources in state.
- `terraform state show <resource>` -- Show details of a specific resource.
- `terraform state mv` -- Rename a resource without destroying and recreating it.
- `terraform state rm` -- Remove a resource from state without destroying it (useful for imports or when moving resources between configurations).
- `terraform import` -- Import existing infrastructure into state.

**State file per environment:** Use separate state files for each environment (dev, staging, production). Never share state between environments. This prevents a mistake in dev from affecting production state.

## Module Design

Terraform modules are reusable, composable units of infrastructure. Good module design follows the same principles as good software design.

**Module structure:**

```
modules/
  ecs-service/
    main.tf          # Resource definitions
    variables.tf     # Input variables with descriptions and validation
    outputs.tf       # Output values
    versions.tf      # Provider version constraints
    README.md        # Usage documentation
```

**Variable validation:**

```hcl
variable "environment" {
  type        = string
  description = "Deployment environment"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "cpu" {
  type        = number
  description = "CPU units for the task (256, 512, 1024, 2048, 4096)"

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.cpu)
    error_message = "CPU must be a valid Fargate CPU value."
  }
}
```

**Module composition:**

```hcl
module "vpc" {
  source      = "./modules/vpc"
  environment = var.environment
  cidr_block  = "10.0.0.0/16"
}

module "api_service" {
  source          = "./modules/ecs-service"
  environment     = var.environment
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids
  container_image = var.api_image
  cpu             = 512
  memory          = 1024
}
```

**Module versioning:** For shared modules, publish to a module registry (Terraform Cloud, private registry, or Git tags). Pin module versions in consuming configurations.

## Testing Infrastructure as Code

Testing IaC prevents misconfigurations and catches issues before they reach production.

**Static analysis:**

- `terraform validate` -- Syntax and internal consistency checking.
- `terraform plan` -- Preview changes. Review plans in CI before applying.
- `tflint` -- Terraform linter for best practices and provider-specific rules.
- `checkov` -- Static analysis for security misconfigurations (open security groups, unencrypted buckets, missing logging).
- `tfsec` -- Security-focused static analysis for Terraform.

**Unit testing (Pulumi):**

```typescript
import * as pulumi from "@pulumi/pulumi";
import { describe, it, expect } from "vitest";

// Mock Pulumi runtime
pulumi.runtime.setMocks({
  newResource: (args) => ({ id: `${args.name}-id`, state: args.inputs }),
  call: (args) => args.inputs,
});

describe("Database module", () => {
  it("enables encryption at rest", async () => {
    const { cluster } = await import("./database");
    const encrypted = await new Promise<boolean>((resolve) =>
      cluster.storageEncrypted.apply(resolve)
    );
    expect(encrypted).toBe(true);
  });
});
```

**Integration testing with Terratest:**

```go
func TestECSService(t *testing.T) {
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../modules/ecs-service",
        Vars: map[string]interface{}{
            "environment": "test",
            "cpu":         256,
        },
    })

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    clusterArn := terraform.Output(t, terraformOptions, "cluster_arn")
    assert.Contains(t, clusterArn, "test-api")
}
```

## Policy as Code

Policy as code enforces organizational standards, security requirements, and compliance rules as automated checks.

**Open Policy Agent (OPA):** A general-purpose policy engine. Policies are written in Rego. Use with `conftest` for Terraform plan validation.

```rego
# policy/terraform.rego
package terraform

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' must have encryption enabled", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
    resource.change.after.type == "ingress"
    msg := sprintf("Security group rule '%s' must not allow ingress from 0.0.0.0/0", [resource.address])
}
```

**Sentinel (HashiCorp):** Policy-as-code framework native to Terraform Cloud/Enterprise. Policies run between plan and apply.

**Integration in CI:** Run policy checks as a pipeline stage after `terraform plan`. Fail the pipeline on policy violations. This catches issues before infrastructure changes are applied.

## Drift Detection

Drift occurs when actual infrastructure diverges from the IaC definition due to manual changes, external automation, or partial failures.

**Detection methods:**

- `terraform plan` -- Shows the difference between state and actual infrastructure. Run periodically (not just before changes) to detect drift.
- CloudFormation drift detection -- Built-in feature that compares stack resources to their expected configurations.
- AWS Config rules -- Continuously evaluate resource compliance against custom or managed rules.

**Remediation:** Either update the IaC to match the new reality (if the manual change was intentional) or reapply the IaC to revert the drift. For GitOps-managed infrastructure, the reconciliation is automatic.

**Prevention:** Restrict write access to infrastructure. Use IAM policies that deny manual changes to Terraform-managed resources (tag-based policies). Educate teams that manual changes will be reverted.
