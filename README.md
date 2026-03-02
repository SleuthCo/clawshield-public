# ClawShield

**Security proxy for AI agents.** Sits in front of [OpenClaw](https://github.com/openclaw/openclaw) and scans every message for prompt injection, PII leaks, and secrets — before they reach the model or leave the network.

Ships with 5 specialized AI agents, a built-in dashboard, and a YAML policy engine. One command to start.

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Browser    │────▶│  ClawShield      │────▶│   OpenClaw   │
│   (you)      │◀────│  Security Proxy  │◀────│   Gateway    │
└──────────────┘     └──────────────────┘     └──────────────┘
                      ▪ Prompt injection       ▪ Claude, GPT,
                        detection                LM Studio
                      ▪ PII/secrets redaction  ▪ Multi-agent
                      ▪ Policy enforcement       routing
                      ▪ Audit logging          ▪ RAG knowledge
```

---

## Quickstart (Docker)

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) and an [Anthropic API key](#getting-an-anthropic-api-key).

```bash
# 1. Clone the repo
git clone https://github.com/SleuthCo/clawshield-public.git
cd clawshield-public

# 2. Set your API key
cp standalone/.env.template standalone/.env
# Edit standalone/.env and paste your Anthropic API key

# 3. Start
cd standalone
docker compose up -d
```

Open **http://localhost:18801** in your browser. You'll see the ClawShield dashboard with 5 AI agents ready to chat.

That's it. ClawShield is scanning all traffic between you and the agents.

---

## Getting an Anthropic API Key

ClawShield uses Claude (via Anthropic's API) as the default language model. Here's how to get your key:

1. Go to [console.anthropic.com](https://console.anthropic.com/) and sign up (or log in)
2. Click **API Keys** in the left sidebar
3. Click **Create Key**
4. Give it a name (e.g., "clawshield") and click **Create**
5. Copy the key — it starts with `sk-ant-`
6. Paste it into your `standalone/.env` file:
   ```
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```

**Cost:** Anthropic charges per token. A typical chat session costs a few cents. New accounts get $5 in free credits. See [anthropic.com/pricing](https://www.anthropic.com/pricing) for details.

**Using a different model?** ClawShield works with any OpenAI-compatible API (GPT, LM Studio, Ollama, etc.). Edit `standalone/config/openclaw.json` to point at your preferred provider.

---

## Installation Options

### Option 1: Docker (recommended)

Everything runs in a single container — ClawShield proxy + OpenClaw gateway + 5 agents.

See [Quickstart](#quickstart-docker) above.

### Option 2: Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/SleuthCo/clawshield-public/releases):

| Platform | File |
|----------|------|
| Windows | `clawshield-proxy-windows-amd64.exe` |
| Linux x64 | `clawshield-proxy-linux-amd64` |
| Linux ARM64 | `clawshield-proxy-linux-arm64` |
| macOS Apple Silicon | `clawshield-proxy-darwin-arm64` |
| macOS Intel | `clawshield-proxy-darwin-amd64` |

Then run the interactive setup wizard:

```bash
# Download the setup wizard too
chmod +x clawshield-setup-*

# Run the wizard — it walks you through everything
./clawshield-setup-linux-amd64
```

The wizard will:
- Ask for your Anthropic API key
- Configure your agents
- Generate the OpenClaw config
- Create start/stop scripts

### Option 3: Build from Source

Requires [Go 1.24+](https://go.dev/dl/).

```bash
git clone https://github.com/SleuthCo/clawshield-public.git
cd clawshield-public

# Build the proxy
cd proxy/cmd/clawshield-proxy
go build -o clawshield-proxy

# Build the setup wizard
cd ../../clawshield-setup
go build -o clawshield-setup

# Run setup
./clawshield-setup
```

---

## What's Included

### Security Proxy

The core of ClawShield. An HTTP reverse proxy that intercepts all traffic between users and the AI gateway.

**Scanners:**
- **Prompt injection detection** — blocks jailbreak attempts, instruction override, role manipulation
- **PII redaction** — detects and redacts emails, phone numbers, SSNs, credit cards
- **Secrets detection** — catches API keys, tokens, passwords before they leak
- **Vulnerability scanning** — flags known-dangerous tool calls and arguments

**Policy engine** — YAML-based, deny-by-default:
```yaml
default_action: deny

scanners:
  prompt_injection:
    enabled: true
    action: block
  pii:
    enabled: true
    action: redact
  secrets:
    enabled: true
    action: block

domain_allowlist:
  - "api.anthropic.com"
  - "api.openai.com"
```

See [policy/examples/](policy/examples/) for more examples.

### 5 AI Agents

Each agent has a specialized role and its own RAG knowledge base:

| Agent | Role | Knowledge |
|-------|------|-----------|
| **Anvil** | Software Development | Languages, architecture, DevOps, testing, secure coding |
| **Shield** | Security Engineering | NIST, MITRE ATT&CK, OWASP, zero trust, threat modeling |
| **Harbor** | Cloud Engineering | AWS, Azure, GCP, Kubernetes, IaC, networking |
| **Beacon** | Communications | Crisis comms, content strategy, executive briefings |
| **Lens** | Research & Analysis | OSINT, structured analysis, cognitive biases, intelligence |

### Audit Logging

Every request and response is logged to a local SQLite database with:
- Timestamp, source IP, request method
- Scanner decisions (allow/block/redact) with reasons
- Full request/response payloads (configurable)
- Query via the built-in audit CLI:

```bash
clawshield-audit --db /var/lib/clawshield/audit.db --last 50
clawshield-audit --db /var/lib/clawshield/audit.db --blocked-only
```

### Network Firewall (optional)

iptables-based egress firewall that restricts which domains/IPs agents can reach:

```bash
cd firewall/cmd/clawshield-fw && go build -o clawshield-fw
sudo ./clawshield-fw apply --config firewall/examples/firewall.yaml
```

### eBPF Monitor (optional)

Kernel-level syscall monitoring for detecting suspicious agent behavior:

```bash
sudo python3 ebpf/cmd/clawshield-ebpf/main.py --config ebpf/config/default.yaml
```

Detects: fork bombs, sensitive file access, privilege escalation, anomalous network connections.

---

## Architecture

ClawShield uses **defense-in-depth** — three security layers connected by a cross-layer event bus:

```
Layer 1: Application (ClawShield Proxy)
  ▪ Scans message content
  ▪ Enforces YAML policies
  ▪ Logs all decisions

Layer 2: Network (ClawShield Firewall)
  ▪ iptables egress rules
  ▪ Domain/IP allowlist
  ▪ Blocks unapproved connections
  ▪ Dynamic temporary rules from cross-layer events

Layer 3: Kernel (ClawShield eBPF)
  ▪ Syscall monitoring
  ▪ Behavioral anomaly detection
  ▪ Real-time alerts
```

Each layer works independently. If one is bypassed, the others still protect.

### Cross-Layer Event Bus

The three layers communicate via a Unix socket-based event bus, enabling **adaptive security responses** across layers:

```
┌──────────────┐                          ┌──────────────┐
│  eBPF        │──── Unix Socket ────────▶│  Proxy       │
│  (Layer 3)   │  /tmp/clawshield-       │  (Layer 1)   │
│  Produces:   │   events.sock           │  Produces:   │
│  • privesc   │                          │  • injection │
│  • port_scan │◀── Adaptive Controller ──│  • malware   │
│  • file_access│                         │  • vuln_scan │
└──────────────┘                          └──────────────┘
                         │
                         ▼
                ┌──────────────┐
                │  Firewall    │
                │  (Layer 2)   │
                │  Consumes:   │
                │  • temp block│
                │    rules     │
                └──────────────┘
```

**Example adaptive reactions:**

| Trigger | Automatic Response |
|---------|-------------------|
| eBPF detects privilege escalation | Proxy elevates injection sensitivity to `high` for 5 min |
| eBPF detects port scanning | Proxy restricts domain access for 10 min |
| Proxy blocks 3+ injections in 60s | Default action forced to `deny` for 15 min |
| Proxy detects malware in response | Firewall adds temporary IP block rules |

Enable cross-layer integration by adding an `adaptive` section to your policy YAML. See [policy/examples/adaptive_crosslayer.yaml](policy/examples/adaptive_crosslayer.yaml) for a complete example.

---

## Production Deployment

For deploying on a real server with TLS, see [docs/install-guide.md](docs/install-guide.md).

The `deploy/` directory contains:
- `cloud-init.yaml` — Hardened VM provisioning (SSH lockdown, fail2ban, nftables, auditd)
- `docker-compose.yml` — Full production stack with nginx TLS termination
- `nginx/conf.d/` — Production nginx configs with rate limiting, security headers, WebSocket proxy
- `deploy.sh` — Automated deployment script
- `smoke-test.sh` — Post-deployment verification

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key (`sk-ant-...`) |
| `GATEWAY_AUTH_TOKEN` | No | Shared auth token (auto-generated if omitted) |
| `CLAWSHIELD_PORT` | No | Host port (default: 18801) |
| `CLAWSHIELD_STUDIO_URL` | No | Studio deep-link base URL |

### Files

| File | Purpose |
|------|---------|
| `standalone/config/openclaw.json` | OpenClaw gateway config (models, agents, auth) |
| `standalone/config/policy.yaml` | ClawShield security policy |
| `standalone/agents/*/` | Agent configs and knowledge bases |

---

## Testing

```bash
# Unit tests
go test ./proxy/...
go test ./firewall/...

# Integration tests
go test ./integration/...
```

---

## Contributing

Issues and pull requests welcome at [github.com/SleuthCo/clawshield-public](https://github.com/SleuthCo/clawshield-public).

## License

Apache 2.0

## Acknowledgments

Built on [OpenClaw](https://github.com/openclaw/openclaw). Inspired by traditional network security architectures applied to AI agent contexts.
