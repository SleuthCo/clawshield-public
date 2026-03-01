---
framework: "CI/CD"
version: "1.0"
domain: "DevOps"
agent: "friday"
tags: ["cicd", "github-actions", "gitlab-ci", "jenkins", "deployment", "blue-green", "canary", "feature-flags"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# CI/CD Pipeline Design

## Pipeline Design Patterns

**Fast feedback first:** Structure stages so the cheapest, fastest checks run first. Linting in seconds, unit tests in under two minutes, integration tests next, E2E tests last. If the linter fails, do not waste ten minutes running the full test suite.

**Fail fast, fail loud:** A failed pipeline should be impossible to ignore. Notify the author immediately. Block merges on failure.

**Reproducibility:** Every pipeline run on the same commit should produce the same result. Pin dependency versions. Use lock files. Use deterministic builds. Avoid external state that changes between runs.

**Pipeline-as-code:** Define pipelines in version-controlled files (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`). Review pipeline changes in pull requests like any other code change.

**Trunk-based development alignment:** Short-lived feature branches (hours to days). Merge to main frequently. Use feature flags to decouple deployment from release.

## GitHub Actions

GitHub Actions uses YAML workflow files in `.github/workflows/`. It provides hosted runners, a marketplace of reusable actions, and native GitHub integration.

```yaml
name: CI
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck

  test:
    needs: lint
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_DB: test
          POSTGRES_PASSWORD: test
        ports: ['5432:5432']
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm test -- --coverage
      - uses: codecov/codecov-action@v4

  build:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.sha }}
            ghcr.io/${{ github.repository }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**Reusable workflows:** Extract common logic into reusable workflows called with `uses: ./.github/workflows/reusable-build.yml`. Share across repositories with `uses: org/repo/.github/workflows/build.yml@main`.

**OIDC authentication:** Use GitHub's OIDC provider to authenticate with cloud providers without storing credentials. Configure `permissions: id-token: write` and use the cloud provider's official action (e.g., `aws-actions/configure-aws-credentials` with `role-to-assume`).

## GitLab CI

GitLab CI uses `.gitlab-ci.yml` with stages, jobs, and artifacts. It provides integrated container registry, environments, and review apps.

```yaml
stages:
  - lint
  - test
  - build
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

lint:
  stage: lint
  image: node:20-alpine
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths: [node_modules/]
  script:
    - npm ci
    - npm run lint
    - npm run typecheck

test:
  stage: test
  image: node:20-alpine
  services:
    - postgres:16
  variables:
    POSTGRES_DB: test
    POSTGRES_PASSWORD: test
    DATABASE_URL: postgresql://postgres:test@postgres:5432/test
  script:
    - npm ci
    - npm test -- --coverage
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
  artifacts:
    reports:
      junit: junit.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE
  only:
    - main

deploy_staging:
  stage: deploy
  environment:
    name: staging
    url: https://staging.example.com
  script:
    - kubectl set image deployment/app app=$DOCKER_IMAGE
  only:
    - main
```

## Jenkins

Jenkins uses `Jenkinsfile` (declarative or scripted pipeline). It offers maximum flexibility but requires more operational overhead.

```groovy
pipeline {
    agent any

    environment {
        DOCKER_REGISTRY = 'registry.example.com'
        IMAGE_NAME = "${DOCKER_REGISTRY}/myapp:${GIT_COMMIT}"
    }

    stages {
        stage('Lint') {
            steps {
                sh 'npm ci'
                sh 'npm run lint'
            }
        }

        stage('Test') {
            steps {
                sh 'npm test -- --ci --coverage'
            }
            post {
                always {
                    junit 'test-results/*.xml'
                    publishHTML([reportDir: 'coverage', reportFiles: 'index.html'])
                }
            }
        }

        stage('Build') {
            when { branch 'main' }
            steps {
                sh "docker build -t ${IMAGE_NAME} ."
                sh "docker push ${IMAGE_NAME}"
            }
        }

        stage('Deploy') {
            when { branch 'main' }
            input { message "Deploy to production?" }
            steps {
                sh "kubectl set image deployment/app app=${IMAGE_NAME}"
            }
        }
    }

    post {
        failure {
            slackSend(channel: '#deploys', message: "Build failed: ${BUILD_URL}")
        }
    }
}
```

## Multi-Stage Docker Builds

Multi-stage builds minimize image size, improve security, and speed up builds through layer caching.

```dockerfile
# Stage 1: Install dependencies
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production=false

# Stage 2: Build
FROM deps AS build
COPY . .
RUN npm run build
RUN npm prune --production

# Stage 3: Production runtime
FROM node:20-alpine AS runtime
RUN addgroup -g 1001 appgroup && adduser -u 1001 -G appgroup -D appuser
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./
USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O /dev/null http://localhost:3000/health
CMD ["node", "dist/server.js"]
```

**Best practices:** Pin base image digests, not just tags. Put least-frequently changing layers first. Run as non-root. Scan images with Trivy or Grype. Use `.dockerignore` to exclude unnecessary files.

## Artifact Management

Artifacts are the immutable outputs of a build pipeline. Every deployment should use a pre-built artifact, never rebuild from source.

**Principles:** Build once, deploy everywhere. Tag artifacts with the commit SHA. Use immutable tags (never overwrite `latest` in production). Store metadata (build time, commit, branch, test results) alongside the artifact.

**Storage:** Container registries (GitHub Container Registry, AWS ECR, Docker Hub) for images. Object storage (S3, GCS) for binaries and archives. Package registries (npm, PyPI, Maven Central) for libraries.

## Deployment Strategies

**Blue-green deployment:** Run two identical environments (blue and green). Deploy to the inactive environment, verify it, then switch traffic. Instant rollback by switching back. Requires double infrastructure during deployment.

**Canary deployment:** Deploy the new version to a small subset of traffic (1-5%). Monitor error rates, latency, and business metrics. Gradually increase traffic if metrics are healthy. Automated rollback if metrics degrade. Tools: Argo Rollouts, Flagger, AWS CodeDeploy.

**Rolling update:** Replace instances one at a time (or in batches). At any point, some instances run the old version and some run the new version. No extra infrastructure needed. Risk: incompatible versions running simultaneously. Default strategy in Kubernetes.

**Shadow deployment (dark launch):** Route a copy of production traffic to the new version without serving its responses to users. Compare responses between old and new versions. Useful for validating correctness before switching traffic.

**A/B testing deployment:** Route specific user segments to different versions. Primarily for measuring business metrics (conversion rate), not just technical correctness.

## Feature Flags

Feature flags decouple deployment from release. Deploy code to production behind a disabled flag, then enable it independently.

**Types of flags:**

- **Release flags:** Short-lived. Enable a feature when ready. Remove after full rollout.
- **Experiment flags:** A/B test flags with user segmentation. Remove after the experiment concludes.
- **Operational flags:** Circuit breakers, kill switches. Long-lived.
- **Permission flags:** Enable features for specific user tiers (premium, beta).

**Implementation principles:** Default to off (new features are disabled). Clean up flags promptly after rollout. Track flag age and alert on stale flags. Use a dedicated flag management service (LaunchDarkly, Unleash, Flagsmith) rather than config files for dynamic flags.

**Flag evaluation:** Evaluate flags server-side for security-sensitive features. Client-side evaluation is faster but exposes flag configuration. Use targeting rules (user ID, percentage, attribute-based) for gradual rollouts.
