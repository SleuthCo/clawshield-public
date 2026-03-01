---
framework: "GitOps"
version: "1.0"
domain: "DevOps"
agent: "friday"
tags: ["gitops", "argocd", "flux", "kubernetes", "declarative", "progressive-delivery"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# GitOps

## GitOps Principles

GitOps is an operational framework that uses Git as the single source of truth for declarative infrastructure and application configuration. Changes to infrastructure and applications are made through Git commits, and automated agents ensure the actual state matches the desired state in Git.

**Core principles:**

1. **Declarative configuration:** The entire system is described declaratively (YAML, HCL, JSON). The desired state is defined, not the steps to achieve it.
2. **Version controlled:** All configuration lives in Git. Git history provides an audit trail, rollback capability, and change review through pull requests.
3. **Automatically applied:** Approved changes are automatically applied to the system. No manual kubectl commands or SSH to production.
4. **Continuously reconciled:** Software agents continuously observe the actual system state and reconcile it with the desired state in Git. Drift is detected and corrected automatically.

**Push vs. pull model:**

- **Push model (traditional CI/CD):** The CI pipeline pushes changes to the cluster. The pipeline needs cluster credentials. Risk: credential exposure, pipeline is a single point of failure.
- **Pull model (GitOps):** An agent running inside the cluster polls the Git repository for changes and applies them. Credentials stay inside the cluster. The cluster pulls its own configuration.

## ArgoCD

ArgoCD is a declarative, GitOps continuous delivery tool for Kubernetes. It runs as a controller in the cluster and watches Git repositories for changes.

**Architecture:**

- **API Server:** Exposes the API and UI. Handles authentication and RBAC.
- **Repository Server:** Clones Git repos, generates Kubernetes manifests from Helm, Kustomize, or plain YAML.
- **Application Controller:** Continuously monitors running applications and compares them to the desired state in Git. Reconciles drift.

**Application definition:**

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-service
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/org/k8s-manifests.git
    targetRevision: main
    path: services/my-service/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true        # Delete resources removed from Git
      selfHeal: true     # Revert manual changes in cluster
    syncOptions:
      - CreateNamespace=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

**Sync strategies:**

- **Manual sync:** ArgoCD detects drift but requires manual approval to apply changes. Good for production environments requiring human review.
- **Automated sync:** Changes in Git are automatically applied. Use with `selfHeal: true` to revert any manual changes made directly to the cluster.
- **Sync waves:** Control the order of resource deployment using `argocd.argoproj.io/sync-wave` annotations. Lower numbers sync first. Use for dependencies (namespace before deployment, CRDs before custom resources).

**ApplicationSet:** Generate multiple ArgoCD Applications from a single template. Useful for multi-cluster deployments, multi-tenant platforms, and monorepo structures.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: cluster-addons
spec:
  generators:
    - clusters: {}  # Generate one Application per registered cluster
  template:
    metadata:
      name: '{{name}}-addons'
    spec:
      source:
        repoURL: https://github.com/org/cluster-addons.git
        path: addons
      destination:
        server: '{{server}}'
        namespace: kube-system
```

## Flux

Flux is a set of continuous delivery solutions for Kubernetes that are open and extensible. It is a CNCF graduated project.

**Core components:**

- **Source Controller:** Manages Git repositories, Helm repositories, OCI repositories, and S3 buckets as sources of configuration.
- **Kustomize Controller:** Reconciles Kustomization resources by applying kustomize overlays from Git.
- **Helm Controller:** Manages Helm chart releases declaratively.
- **Notification Controller:** Handles events and sends alerts to external systems (Slack, Teams, PagerDuty).
- **Image Automation Controllers:** Scans container registries for new image tags and updates Git repositories with new image references.

**GitRepository and Kustomization:**

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: my-app
  namespace: flux-system
spec:
  interval: 1m
  url: https://github.com/org/k8s-manifests.git
  ref:
    branch: main
  secretRef:
    name: git-credentials

---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: my-app
  namespace: flux-system
spec:
  interval: 5m
  sourceRef:
    kind: GitRepository
    name: my-app
  path: ./services/my-app/production
  prune: true
  healthChecks:
    - apiVersion: apps/v1
      kind: Deployment
      name: my-app
      namespace: production
  timeout: 3m
```

## Declarative Infrastructure

In GitOps, infrastructure is defined declaratively and stored in Git. The directory structure typically follows a pattern.

**Recommended repository structure:**

```
k8s-manifests/
  base/                       # Shared base manifests
    my-service/
      deployment.yaml
      service.yaml
      kustomization.yaml
  overlays/                   # Environment-specific patches
    development/
      my-service/
        kustomization.yaml    # Patches for dev
        replicas-patch.yaml
    staging/
      my-service/
        kustomization.yaml
    production/
      my-service/
        kustomization.yaml
        replicas-patch.yaml
        hpa.yaml
  infrastructure/             # Cluster-wide resources
    cert-manager/
    ingress-nginx/
    monitoring/
```

**Kustomize for environment-specific configuration:**

```yaml
# overlays/production/my-service/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../../base/my-service
patches:
  - path: replicas-patch.yaml
  - path: resources-patch.yaml
images:
  - name: my-service
    newName: registry.example.com/my-service
    newTag: v1.2.3
```

## Drift Detection

Drift occurs when the actual state of the system diverges from the desired state in Git. GitOps agents detect and remediate drift automatically.

**Causes of drift:** Manual kubectl commands, emergency hotfixes applied directly, Kubernetes controllers modifying resources (autoscaler changing replica counts), external systems updating secrets or configmaps.

**Detection mechanisms:** ArgoCD and Flux continuously compare the live cluster state with the Git state. ArgoCD shows resources as "OutOfSync" in its UI and API. Flux emits events when drift is detected.

**Remediation:** With `selfHeal: true` (ArgoCD) or `prune: true` (Flux), drift is automatically corrected. For cases where drift should be allowed (e.g., HPA-managed replica counts), use ignore-difference rules.

```yaml
# ArgoCD: ignore differences managed by HPA
spec:
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/replicas
```

## Progressive Delivery

Progressive delivery extends GitOps with gradual rollout strategies, automated analysis, and rollback.

**Argo Rollouts:** A Kubernetes controller that provides advanced deployment strategies (canary, blue-green) with automated analysis.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: my-service
spec:
  replicas: 10
  strategy:
    canary:
      steps:
        - setWeight: 5
        - pause: { duration: 5m }
        - analysis:
            templates:
              - templateName: success-rate
        - setWeight: 25
        - pause: { duration: 5m }
        - analysis:
            templates:
              - templateName: success-rate
        - setWeight: 50
        - pause: { duration: 10m }
        - setWeight: 100
```

**Flagger:** Works with Flux and Istio/Linkerd/NGINX to automate canary deployments. Monitors metrics and promotes or rolls back automatically.

## Environment Promotion

Environment promotion moves changes through environments (dev -> staging -> production) in a controlled manner.

**Git-based promotion:** Each environment has its own branch or directory. Promoting from staging to production means merging or updating the production directory/branch. Pull requests provide review and approval gates.

**Image tag promotion pattern:**

1. CI builds and pushes image with commit SHA tag.
2. Dev environment overlay is automatically updated with the new tag.
3. After testing in dev, a PR updates the staging overlay with the same tag.
4. After staging verification, a PR updates the production overlay.

**Automated image updates (Flux):** Flux Image Automation can scan a container registry for new tags matching a pattern and automatically create commits updating the image tag in Git. This automates the dev environment step while keeping staging and production manual.

## Secrets Management in GitOps

Secrets cannot be stored in Git in plain text. Several approaches solve this problem within the GitOps model.

**Sealed Secrets (Bitnami):** Encrypt secrets with a cluster-specific public key. Only the cluster's controller can decrypt them. Encrypted SealedSecret resources are safe to store in Git.

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  encryptedData:
    password: AgBy3i... # encrypted with cluster's public key
```

**External Secrets Operator:** Syncs secrets from external secret stores (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, GCP Secret Manager) into Kubernetes Secrets. Git stores the ExternalSecret reference, not the secret value.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: db-credentials
  data:
    - secretKey: password
      remoteRef:
        key: production/db/password
```

**SOPS (Mozilla):** Encrypts specific values within YAML/JSON files using AWS KMS, GCP KMS, Azure Key Vault, or PGP keys. The file structure remains readable; only the values are encrypted. Flux has native SOPS support for decryption during reconciliation.
