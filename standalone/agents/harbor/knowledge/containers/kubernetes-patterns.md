---
framework: "Kubernetes Patterns"
version: "1.0"
domain: "Container Orchestration"
agent: "nimbus"
tags: ["kubernetes", "k8s", "pods", "deployments", "operators", "service-mesh", "gitops"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Kubernetes Patterns

Kubernetes is the de facto standard for container orchestration. This document covers pod design patterns, deployment strategies, stateful workloads, operators, service mesh, GitOps, and multi-tenancy patterns.

## Pod Design Patterns

### Sidecar Pattern

A sidecar container runs alongside the main application container in the same pod, extending or enhancing its functionality without modifying the main application.

**Common Sidecar Use Cases**:
- **Log shipping**: Sidecar reads log files from a shared volume and forwards them to a centralized logging system (Fluentd, Fluent Bit)
- **Service mesh proxy**: Envoy proxy sidecar intercepts all network traffic for mTLS, traffic management, and observability (Istio, Linkerd)
- **Configuration sync**: Sidecar watches a configuration source (ConfigMap, Vault) and updates shared configuration files
- **TLS termination**: Sidecar handles TLS termination so the application speaks plain HTTP internally
- **Monitoring agent**: Prometheus exporter sidecar exposes application metrics in Prometheus format

**Sidecar Containers (Kubernetes 1.28+)**: Native sidecar support via `initContainers` with `restartPolicy: Always`. These start before regular containers and run for the lifetime of the pod. They have proper lifecycle management (do not block pod startup, do not delay pod termination). This addresses the long-standing issue of sidecar container ordering with init containers.

### Ambassador Pattern

An ambassador container proxies network connections from the main container to external services. The main container connects to localhost, and the ambassador handles the complexity of connecting to external endpoints.

**Use Cases**:
- Database connection pooling (PgBouncer as ambassador for PostgreSQL)
- Service discovery and routing
- Retry and circuit-breaking logic for external services
- Protocol translation (main container speaks HTTP, ambassador translates to gRPC)

### Adapter Pattern

An adapter container transforms the output of the main container into a format expected by external consumers. It standardizes and normalizes heterogeneous output.

**Use Cases**:
- Prometheus metrics adapter: Converts application-specific metrics into Prometheus exposition format
- Log format adapter: Converts application logs into a standard structured format before shipping
- Data format transformation: Converts between JSON, XML, or protobuf formats

### Init Container Pattern

Init containers run to completion before any regular containers start. They perform setup tasks that must complete before the application starts.

**Use Cases**:
- Wait for dependent services to be available (database, message queue)
- Clone a Git repository or download configuration files
- Run database migrations before the application starts
- Set file ownership or permissions on volumes
- Register the instance with a service registry

## Deployment Strategies

### Rolling Update (Default)

The default deployment strategy. Gradually replaces old pods with new pods. Configurable via `maxSurge` (how many extra pods during update) and `maxUnavailable` (how many pods can be unavailable during update).

- Set `maxSurge: 1` and `maxUnavailable: 0` for zero-downtime updates with minimal extra resources
- Set `maxSurge: 25%` and `maxUnavailable: 25%` for faster updates with some capacity reduction
- Always configure proper readiness probes to prevent traffic routing to unready pods

### Blue-Green Deployment

Run two complete sets of pods (blue = current, green = new). Switch all traffic from blue to green instantaneously by updating the Service selector.

- **Advantages**: Instant rollback (switch Service selector back), full testing of green before switching
- **Disadvantages**: Requires double the resources during deployment, database schema changes must be backward-compatible
- Implementation: Use two Deployments with different labels. Service selector points to the active deployment.

### Canary Deployment

Route a small percentage of traffic to the new version while the majority continues to go to the old version. Gradually increase the canary traffic percentage as confidence grows.

- **Manual**: Run two Deployments with different replica counts. The Service selector matches both. Ratio of replicas determines traffic split. Coarse-grained control.
- **Service Mesh / Ingress**: Use Istio VirtualService, Linkerd TrafficSplit, or NGINX Ingress canary annotations for percentage-based traffic splitting. Fine-grained control independent of replica count.
- **Progressive Delivery**: Use Argo Rollouts or Flagger for automated canary deployments with analysis. Automatically promote or rollback based on metrics (error rate, latency).

### A/B Testing

Route traffic based on request attributes (headers, cookies, user agent, geographic location) rather than percentage. Requires a service mesh or intelligent ingress controller.

## StatefulSets

StatefulSets manage stateful applications requiring stable network identifiers, stable persistent storage, and ordered deployment and scaling.

### Key Properties

- Pods get a stable hostname: `<statefulset-name>-<ordinal>` (e.g., mysql-0, mysql-1, mysql-2)
- Each pod gets its own PersistentVolumeClaim via `volumeClaimTemplates`
- Pods are created in order (0, 1, 2) and terminated in reverse order (2, 1, 0)
- A headless Service provides DNS entries for each pod: `<pod-name>.<service-name>.<namespace>.svc.cluster.local`

### Use Cases

- Databases with primary-replica topology (MySQL, PostgreSQL): mysql-0 is primary, mysql-1 and mysql-2 are replicas
- Distributed systems requiring stable member identity (etcd, ZooKeeper, Kafka, Elasticsearch)
- Applications needing persistent storage tied to specific instances

### Best Practices

- Set `podManagementPolicy: Parallel` when pods do not need ordered startup (for faster scaling)
- Use `serviceName` to associate with a headless Service for stable DNS
- Configure appropriate `updateStrategy`: RollingUpdate for automatic updates, OnDelete for manual control
- Use partition-based rolling updates to canary StatefulSet updates (update only pods with ordinal >= partition value)

## Operators and Custom Resource Definitions (CRDs)

### CRDs

Custom Resource Definitions extend the Kubernetes API with custom resources. They define new resource types that Kubernetes stores and serves like built-in resources.

- Define the schema (OpenAPI v3) for your custom resource
- Custom resources are accessed via kubectl and the Kubernetes API
- CRDs are a schema definition only; they do not include business logic

### Operators

Operators combine CRDs with custom controllers that implement domain-specific operational knowledge. The operator pattern encodes human operational expertise (how to deploy, scale, backup, upgrade, and recover) into software.

**Operator Capabilities Levels** (Operator Framework):
1. **Basic Install**: Automated deployment and configuration
2. **Seamless Upgrades**: Automated version upgrades
3. **Full Lifecycle**: Backup, restore, failure recovery
4. **Deep Insights**: Metrics, alerts, log processing
5. **Auto Pilot**: Automatic scaling, tuning, anomaly detection

**Common Operators**:
- **Prometheus Operator**: Manages Prometheus, Alertmanager, and related monitoring components
- **Cert-Manager**: Automates TLS certificate management and renewal
- **Strimzi**: Manages Apache Kafka clusters on Kubernetes
- **CloudNativePG**: Manages PostgreSQL clusters with automated failover, backup, and recovery
- **Crossplane**: Provisions and manages cloud infrastructure resources as Kubernetes custom resources

### Building Operators

- **Kubebuilder**: Framework for building Kubernetes APIs and controllers in Go. Uses controller-runtime library. Generates CRD manifests, controllers, and webhooks.
- **Operator SDK**: Built on Kubebuilder with additional scaffolding and OLM (Operator Lifecycle Manager) integration. Supports Go, Ansible, and Helm-based operators.
- **Metacontroller**: Lightweight operator framework using Lambda-style hooks. Write controller logic in any language. Good for simple operators.

## Service Mesh

A service mesh provides infrastructure-level networking features (mTLS, traffic management, observability) to microservices without changing application code.

### Istio

Istio is the most feature-rich service mesh, using Envoy proxy sidecars for data plane traffic interception.

- **Traffic Management**: VirtualService (routing rules, traffic splitting, fault injection), DestinationRule (load balancing, connection pooling, circuit breaking), Gateway (ingress/egress)
- **Security**: Automatic mTLS between all meshed services. PeerAuthentication for mTLS modes. AuthorizationPolicy for fine-grained access control based on source identity, headers, or paths.
- **Observability**: Automatic metrics (request count, duration, size), distributed tracing (inject trace headers), and access logging for all meshed traffic. Integration with Prometheus, Grafana, Jaeger, Kiali.
- **Ambient Mesh (Istio 1.22+)**: Sidecar-less mesh using ztunnel (L4 zero-trust tunnel) and waypoint proxies (L7). Reduces resource overhead and operational complexity of sidecar injection.

### Linkerd

Linkerd is a lightweight, CNCF-graduated service mesh focused on simplicity and performance. Uses its own ultra-light Rust-based proxy (linkerd2-proxy) instead of Envoy.

- Automatic mTLS with zero configuration
- Per-route metrics and golden signals out of the box
- Service profiles for per-route retries, timeouts, and traffic shifting
- Smaller resource footprint and lower latency overhead than Istio
- Simpler operational model with fewer configuration options

### When to Use a Service Mesh

- Need mTLS between all services (zero-trust networking)
- Require fine-grained traffic management (canary deployments, traffic mirroring, fault injection)
- Need observability (metrics, tracing, access logs) for all service-to-service communication without instrumenting each service
- Operating at scale with many microservices where consistent network policies are required
- Avoid a service mesh for: fewer than 10 services, simple architectures where mTLS and traffic management are not needed, teams without dedicated platform engineering capacity

## GitOps with ArgoCD and Flux

GitOps uses Git as the single source of truth for declarative infrastructure and application configurations. A GitOps operator continuously reconciles the desired state in Git with the actual state in the cluster.

### ArgoCD

- Declarative GitOps continuous delivery tool for Kubernetes
- Web UI for visualizing application state, sync status, and resource health
- Application CRD defines the source (Git repo, path, target revision) and destination (cluster, namespace)
- ApplicationSet controller for managing multiple applications from templates (cluster generators, Git generators, matrix generators)
- Sync waves and hooks for ordered deployment of resources
- Supports Kustomize, Helm, plain YAML, and Jsonnet
- RBAC with SSO integration for multi-team access control

### Flux

- CNCF-graduated GitOps toolkit composed of specialized controllers
- **Source Controller**: Watches Git repositories, Helm repositories, S3 buckets, OCI registries
- **Kustomize Controller**: Reconciles Kustomization resources (applies kustomize overlays)
- **Helm Controller**: Reconciles HelmRelease resources (manages Helm chart installations)
- **Notification Controller**: Dispatches events to external systems (Slack, Teams, webhooks)
- **Image Automation Controllers**: Update Git repositories when new container images are available (auto-update image tags)

### GitOps Best Practices

- Separate application source code repositories from GitOps configuration repositories
- Use pull-based reconciliation (controller pulls from Git) rather than push-based (CI pushes to cluster)
- Implement progressive delivery with Argo Rollouts or Flagger alongside ArgoCD/Flux
- Encrypt secrets in Git using Sealed Secrets, SOPS, or External Secrets Operator. Never store plain-text secrets in Git.
- Use environment-specific overlays (Kustomize) or value files (Helm) for configuration differences across environments
- Implement drift detection and automatic reconciliation with appropriate sync intervals

## Multi-Tenancy

### Namespace-Level Isolation

The simplest multi-tenancy model. Each tenant gets a namespace with resource quotas, limit ranges, and network policies.

- **ResourceQuota**: Limit total CPU, memory, storage, and object counts per namespace
- **LimitRange**: Set default and maximum resource requests/limits for pods in a namespace
- **NetworkPolicy**: Restrict network traffic between namespaces (deny by default, allow specific flows)
- **RBAC**: Namespace-scoped roles and role bindings to restrict tenant access to their namespace only

### Cluster-Level Isolation

For stronger isolation, use virtual clusters (vCluster) or separate physical clusters per tenant.

- **vCluster**: Runs a lightweight virtual Kubernetes cluster inside a namespace of the host cluster. Each tenant gets a full Kubernetes API. Lower overhead than physical clusters. Suitable for development environments and CI/CD.
- **Physical Clusters**: Strongest isolation with dedicated control plane and worker nodes. Required for regulatory compliance or workloads with strict security boundaries. Higher operational cost.

### Hierarchical Namespaces (HNC)

Hierarchical Namespace Controller allows defining parent-child relationships between namespaces. Policies, RBAC, and resource quotas can be inherited from parent to child namespaces. Simplifies management for organizations with hierarchical team structures.
