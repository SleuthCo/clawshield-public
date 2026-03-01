---
framework: "Docker Best Practices"
version: "1.0"
domain: "Container Engineering"
agent: "nimbus"
tags: ["docker", "containers", "dockerfile", "multi-stage", "security", "buildkit"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Docker Best Practices

Docker remains the standard for building and packaging container images. This document covers Dockerfile optimization, security hardening, base image selection, multi-stage builds, and CI/CD integration patterns.

## Multi-Stage Builds

Multi-stage builds use multiple FROM statements in a single Dockerfile. Each stage creates a separate build layer, and only the final stage contributes to the output image. This dramatically reduces image size by excluding build tools, source code, and intermediate artifacts.

### Pattern: Build and Runtime Stages

```dockerfile
# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server ./cmd/server

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

### Pattern: Test Stage

Add a test stage between build and runtime. The test stage runs unit tests during the build. If tests fail, the build fails, preventing broken images from being created.

```dockerfile
FROM golang:1.22-alpine AS builder
# ... build steps ...

FROM builder AS tester
RUN go test ./...

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /app/server /server
```

### Pattern: Development and Production

Use different final stages for development (includes debug tools, hot-reload) and production (minimal, hardened):

```dockerfile
FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM base AS development
COPY . .
CMD ["npm", "run", "dev"]

FROM base AS production-build
COPY . .
RUN npm run build && npm prune --production

FROM gcr.io/distroless/nodejs20-debian12 AS production
COPY --from=production-build /app/dist /app/dist
COPY --from=production-build /app/node_modules /app/node_modules
WORKDIR /app
CMD ["dist/index.js"]
```

Build specific targets: `docker build --target development -t myapp:dev .`

## Minimal Base Images

### Distroless Images

Google's distroless images contain only the application runtime and its dependencies. No shell, no package manager, no other OS utilities.

- `gcr.io/distroless/static-debian12`: For statically compiled binaries (Go, Rust). Smallest possible image (approximately 2 MB).
- `gcr.io/distroless/base-debian12`: Adds glibc for dynamically linked binaries (C, C++).
- `gcr.io/distroless/java21-debian12`: Java runtime only.
- `gcr.io/distroless/nodejs20-debian12`: Node.js runtime only.
- `gcr.io/distroless/python3-debian12`: Python runtime only.

**Advantages**: Smallest attack surface (no shell means no shell exploits), smallest image size, reduced CVE count. **Disadvantages**: Cannot exec into container for debugging (no shell), harder to troubleshoot in production. Use the `:debug` tag variants during development (they include busybox shell).

### Alpine Linux

Alpine uses musl libc and BusyBox, producing very small images (approximately 5 MB base). Most language runtimes provide official Alpine variants.

- `node:20-alpine`: Approximately 130 MB vs 1 GB for the full image
- `python:3.12-alpine`: Approximately 50 MB vs 900 MB for the full image
- `golang:1.22-alpine`: Approximately 250 MB vs 800 MB for the full image

**Considerations**: musl libc can cause compatibility issues with some applications that depend on glibc-specific behavior. Python packages with C extensions may require additional build dependencies on Alpine. For Python, consider `python:3.12-slim` (Debian slim) as an alternative that balances size with compatibility.

### Scratch Image

The empty base image. Contains absolutely nothing. Only for statically compiled binaries that have zero runtime dependencies.

```dockerfile
FROM scratch
COPY --from=builder /app/server /server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/server"]
```

Remember to copy CA certificates if the application needs HTTPS connectivity.

### Chainguard Images

Chainguard provides minimal, hardened base images with zero known CVEs. Based on Wolfi (a Linux undistro designed for containers). Available for most popular runtimes and applications. Commercial product with some free developer images.

## Layer Optimization

Docker images are composed of layers. Each instruction in a Dockerfile creates a new layer. Optimizing layers reduces image size and build time.

### Leverage Build Cache

- Order instructions from least to most frequently changing. Put COPY of dependency files (package.json, go.mod, requirements.txt) before COPY of source code. Dependencies change less often than source code, so the dependency installation layer is cached across builds.
- Separate COPY and RUN instructions strategically. Combine related RUN commands with && to reduce layers.

### Reduce Layer Size

- Combine related operations in a single RUN instruction to avoid intermediate layer bloat:

```dockerfile
# Bad: Intermediate layer includes apt cache
RUN apt-get update
RUN apt-get install -y curl
RUN rm -rf /var/lib/apt/lists/*

# Good: Single layer, cache cleaned in same layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*
```

- Use `--no-install-recommends` with apt-get to avoid installing unnecessary packages
- Clean up caches, temporary files, and build artifacts in the same RUN instruction that creates them
- Use `.dockerignore` to exclude files from the build context

## .dockerignore

The .dockerignore file prevents unnecessary files from being sent to the Docker build context. This reduces build time and prevents sensitive files from being accidentally included in images.

### Essential .dockerignore Entries

```
.git
.gitignore
.dockerignore
Dockerfile*
docker-compose*
README.md
LICENSE
.env
.env.*
node_modules
__pycache__
*.pyc
.vscode
.idea
.DS_Store
coverage/
test/
tests/
*.test.*
*.spec.*
docs/
*.md
```

### Best Practices

- Always create a .dockerignore file for every project
- Exclude version control directories (.git can be very large)
- Exclude dependency directories (node_modules, vendor) since they are installed during the build
- Exclude test files and documentation that are not needed at runtime
- Exclude environment files (.env) that may contain secrets
- Use explicit includes with `!` prefix when the exclude list is shorter than the include list

## Health Checks

Docker health checks allow the container runtime to monitor application health and take action on unhealthy containers.

### Dockerfile HEALTHCHECK Instruction

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health" ]
```

- `--interval`: Time between health checks (default 30s)
- `--timeout`: Maximum time for a health check to complete (default 30s)
- `--start-period`: Grace period for container startup before health checks count as failures (default 0s)
- `--retries`: Number of consecutive failures before marking unhealthy (default 3)

### Best Practices

- Use the application's dedicated health endpoint, not the root path
- Set an appropriate start-period for applications with long startup times (JVM, large data loading)
- Use lightweight health check commands (curl, wget, or a custom binary) rather than complex scripts
- In Kubernetes, use Kubernetes probes (livenessProbe, readinessProbe, startupProbe) instead of Docker HEALTHCHECK since Kubernetes manages container lifecycle

## Security Scanning in CI

### Pipeline Integration Pattern

1. **Build**: Build the image in CI
2. **Scan**: Run Trivy, Grype, or Snyk against the built image
3. **Gate**: Fail the pipeline if critical or high vulnerabilities exceed the threshold
4. **Sign**: Sign the image with cosign if scanning passes
5. **Push**: Push the signed image to the registry
6. **Attest**: Attach vulnerability scan results as an attestation to the image

### GitHub Actions Example

```yaml
- name: Build image
  run: docker build -t myapp:${{ github.sha }} .

- name: Scan with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myapp:${{ github.sha }}
    exit-code: 1
    severity: CRITICAL,HIGH
    format: sarif
    output: trivy-results.sarif

- name: Upload scan results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trivy-results.sarif
```

### Continuous Scanning

Beyond CI scanning, enable continuous scanning in the container registry to detect new CVEs in existing images. AWS ECR enhanced scanning, Azure Defender for Containers, and GCP Container Analysis all support continuous re-scanning. Alert teams when new critical vulnerabilities affect their deployed images.

## Rootless Containers

Running containers as a non-root user is a fundamental security practice that limits the impact of container escape vulnerabilities.

### Dockerfile User Configuration

```dockerfile
# Create a non-root user
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

# Set ownership of application files
COPY --chown=appuser:appgroup --from=builder /app/server /server

# Switch to non-root user
USER appuser:appgroup
```

### Best Practices

- Always specify USER in the Dockerfile. Default is root, which is insecure.
- Use numeric UIDs instead of usernames for consistency across base images
- Set file ownership with COPY --chown to avoid permission issues
- Bind to ports above 1024 (non-root cannot bind to privileged ports). Use 8080 instead of 80, 8443 instead of 443. The container runtime or Kubernetes can map these to standard ports.
- Use `runAsNonRoot: true` in Kubernetes securityContext as an additional enforcement layer
- Distroless images provide a `nonroot` tag that runs as UID 65532

### Rootless Docker Daemon

Docker can run without root privileges using rootless mode. The Docker daemon itself runs as a regular user, providing an additional layer of isolation. Useful for CI/CD agents and development environments where Docker daemon security is a concern.

## BuildKit

BuildKit is the modern build engine for Docker (default since Docker 23.0). It provides significant improvements over the legacy builder.

### Key Features

- **Parallel build stages**: Independent stages build concurrently, reducing total build time
- **Better caching**: Content-addressable caching, inline cache export/import, registry-based caching
- **Build secrets**: Mount secrets during build without persisting them in image layers
- **SSH forwarding**: Forward SSH agent during build for private repository access
- **Cache mounts**: Persist build caches across builds (package manager caches, build tool caches)

### Build Secrets

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install
```

Build command: `docker build --secret id=npmrc,src=$HOME/.npmrc .`

The secret is available during the build step but never persisted in any image layer. This is the correct way to use credentials during builds. Never use ARG or ENV for secrets.

### Cache Mounts

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt
RUN --mount=type=cache,target=/root/.cache/go-build go build -o /app/server
```

Cache mounts persist build caches between builds, dramatically speeding up dependency installation. The cache is stored on the build host and not included in the image.

### Registry-Based Cache

Export and import build cache from a container registry for CI/CD environments where the build host changes between runs:

```bash
docker build --cache-from type=registry,ref=registry.example.com/myapp:cache \
             --cache-to type=registry,ref=registry.example.com/myapp:cache,mode=max \
             -t myapp:latest .
```

`mode=max` exports all intermediate layers for maximum cache utilization.

## Docker Compose for Development

Docker Compose defines multi-container development environments declaratively.

### Best Practices

- Use profiles to define service groups (dev, test, debug). Start specific profiles with `docker compose --profile dev up`.
- Use named volumes for persistent data (databases). Use bind mounts for source code (hot reload).
- Define health checks and dependencies (`depends_on` with `condition: service_healthy`) for proper startup ordering.
- Use `.env` file for environment-specific configuration. Do not commit .env files with secrets.
- Use `docker compose watch` (Compose 2.22+) for automatic rebuild/sync on file changes.
- Keep production images separate from development Compose files. Development Compose should mount source code and enable debug tools.

## Image Tagging Strategy

- **Never use `latest` in production**. The latest tag is mutable and non-deterministic. Always use specific, immutable tags.
- **Semantic versioning**: Tag releases with `v1.2.3`. Also tag as `v1.2` and `v1` for flexibility.
- **Git SHA**: Tag with the short commit SHA (`abc1234`) for traceability from image to source code.
- **Environment promotion**: Tag images with environment names (`staging`, `production`) as mutable tags that point to the currently deployed version, alongside the immutable version/SHA tags.
- **Pin by digest**: For maximum reproducibility, reference images by digest (`myimage@sha256:abc...`). Digests are immutable and content-addressable.
