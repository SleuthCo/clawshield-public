# ClawShield - Defense-in-Depth Security for AI Agents

ClawShield is a comprehensive security framework for OpenClaw and MCP (Model Context Protocol) agents. It provides three layers of protection: application-level policy enforcement, network-level egress control, and kernel-level behavioral monitoring.

## 🛡️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         OpenClaw Agent                              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ MCP JSON-RPC
                    ┌───────────▼───────────┐
                    │   clawshield-proxy    │  ← Tool allowlist/denylist
                    │   (Application Layer) │     Argument filtering
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │   clawshield-fw       │  ← Domain/IP allowlist
                    │   (Network Layer)     │     iptables OUTPUT DROP
                    └───────────┬───────────┘
                                │
        ┌───────────────────────▼────────────────────────┐
        │                  Linux Kernel                   │
        │   ┌───────────────────────────────────────┐    │
        │   │         clawshield-ebpf               │    │  ← Syscall monitoring
        │   │         (Kernel Layer)                │    │     Behavioral detection
        │   └───────────────────────────────────────┘    │
        └────────────────────────────────────────────────┘
```

## 📦 Components

### 1. ClawShield Proxy (Application Layer)

Intercepts MCP JSON-RPC tool calls and enforces YAML-based policies.

**Features:**
- Tool allowlist/denylist
- Argument regex filtering (block API keys, sensitive paths)
- Domain allowlist for web requests
- Zero-trust by default
- Structured decision logging

**Quick Start:**
```bash
cd proxy/cmd/clawshield-proxy
go build -o clawshield-proxy
./clawshield-proxy --policy /etc/clawshield/policy.yaml
```

**See:** [proxy/README.md](proxy/README.md)

---

### 2. ClawShield Firewall (Network Layer)

Generates and applies iptables rules to restrict agent egress traffic to approved domains/IPs.

**Features:**
- YAML-configured allowlist (domains + direct IPs)
- DNS resolution with IPv4/IPv6 handling
- WSL2-optimized (auto-allows localhost, host bridge, DNS resolver)
- GitHub auto-allowed for git operations
- Default DROP policy with logging

**Quick Start:**
```bash
cd firewall/cmd/clawshield-fw
go build -o clawshield-fw

# Apply rules
sudo ./clawshield-fw apply --config /etc/clawshield/firewall.yaml

# Remove rules
sudo ./clawshield-fw uninstall
```

**Example config:**
```yaml
allowed_domains:
  - "api.telegram.org"
  - "api.anthropic.com"
  - "gateway.molt.bot"

allowed_ips:
  - "149.154.166.110"  # Telegram
  - "160.79.104.10"     # Anthropic

dns_resolvers:
  - "8.8.8.8"
  - "1.1.1.1"
```

**See:** [firewall/examples/firewall.yaml](firewall/examples/firewall.yaml)

---

### 3. ClawShield eBPF (Kernel Layer)

Uses BCC (BPF Compiler Collection) to monitor kernel syscalls and detect suspicious behavior.

**Features:**
- Process execution monitoring (fork bomb detection)
- Network connection tracking
- Sensitive file access alerts (shadow, sudoers, passwd)
- Privilege escalation detection (setuid/setgid)
- Real-time Telegram alerts

**Quick Start:**
```bash
cd ebpf/cmd/clawshield-ebpf
sudo python3 main.py --config /etc/clawshield/ebpf.yaml
```

**Systemd service:**
```bash
sudo cp ebpf/clawshield-ebpf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now clawshield-ebpf
```

**See:** [ebpf/README.md](ebpf/README.md)

---

## 🚀 Production Deployment

### Full Stack Installation

```bash
# 1. Build all components
cd proxy/cmd/clawshield-proxy && go build -o clawshield-proxy
cd ../../firewall/cmd/clawshield-fw && go build -o clawshield-fw

# 2. Install binaries
sudo cp proxy/cmd/clawshield-proxy/clawshield-proxy /usr/local/bin/
sudo cp firewall/cmd/clawshield-fw/clawshield-fw /usr/local/bin/
sudo cp ebpf/cmd/clawshield-ebpf/main.py /usr/local/bin/clawshield-ebpf
sudo chmod +x /usr/local/bin/clawshield-ebpf

# 3. Create config directory
sudo mkdir -p /etc/clawshield

# 4. Copy example configs
sudo cp policy/examples/dev_default.yaml /etc/clawshield/policy.yaml
sudo cp firewall/examples/firewall.yaml /etc/clawshield/firewall.yaml
sudo cp ebpf/config/default.yaml /etc/clawshield/ebpf.yaml

# 5. Apply firewall rules
sudo clawshield-fw apply --config /etc/clawshield/firewall.yaml

# 6. Start eBPF monitor
sudo cp ebpf/clawshield-ebpf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now clawshield-ebpf

# 7. Verify
sudo systemctl status clawshield-ebpf
sudo iptables -L OUTPUT -n
```

---

## 🔧 Configuration

### Proxy Policy (`/etc/clawshield/policy.yaml`)

```yaml
default_action: "deny"

allowlist:
  - "read"
  - "write"
  - "exec"
  - "web_search"

denylist:
  - "exec:rm"
  - "exec:shutdown"

arg_filters:
  - tool: "exec"
    regex: "(sk-[a-zA-Z0-9]{48})"  # Block OpenAI keys
  
domain_allowlist:
  - "*.anthropic.com"
  - "*.github.com"
  - "api.telegram.org"
```

### Firewall Config (`/etc/clawshield/firewall.yaml`)

See [firewall/examples/firewall.yaml](firewall/examples/firewall.yaml)

### eBPF Config (`/etc/clawshield/ebpf.yaml`)

```yaml
detectors:
  process_execution: true
  network_connections: true
  file_access: true
  privilege_escalation: true

telegram:
  enabled: true
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

thresholds:
  max_execs_per_second: 100
  max_network_connections_per_minute: 500
```

---

## 📊 Monitoring & Troubleshooting

### Check Firewall Status

```bash
# View active rules
sudo iptables -L OUTPUT -n -v

# Check blocked attempts (last 50)
sudo dmesg | grep CLAWSHIELD-BLOCKED | tail -50

# Test connectivity
curl -I https://api.telegram.org
```

### Check eBPF Monitor

```bash
# View service logs
sudo journalctl -u clawshield-ebpf -f

# Check if probes are attached
sudo bpftool prog list | grep clawshield

# Manual test
sudo python3 /usr/local/bin/clawshield-ebpf --config /etc/clawshield/ebpf.yaml
```

### Debug Proxy

```bash
# Run in foreground with verbose logging
./clawshield-proxy --policy /etc/clawshield/policy.yaml

# Test a specific request
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec","arguments":{"command":"ls"}}}' | ./clawshield-proxy
```

### Common Issues

**Firewall blocks everything:**
```bash
# Emergency disable
sudo clawshield-fw uninstall

# Check DNS resolution
dig api.anthropic.com +short

# Verify allowed IPs
grep allowed_ips /etc/clawshield/firewall.yaml
```

**eBPF monitor crashes:**
```bash
# Check kernel version (need 4.x+)
uname -r

# Install BCC if missing
sudo apt install bpfcc-tools python3-bpfcc

# Check permissions
sudo dmesg | grep BPF
```

**Proxy blocks legitimate tools:**
```bash
# Check policy
cat /etc/clawshield/policy.yaml

# Test with permissive policy
./clawshield-proxy --policy policy/examples/dev_default.yaml
```

---

## 🧪 Testing

### Unit Tests

```bash
# Proxy tests
cd proxy && go test -v ./...

# Firewall generator tests
cd firewall && go test -v ./...
```

### Integration Tests

```bash
# Test full stack
./tests/integration/test_full_stack.sh
```

---

## 📚 Documentation

- **Proxy**: [proxy/README.md](proxy/README.md)
- **Firewall**: [firewall/README.md](firewall/README.md) *(coming soon)*
- **eBPF**: [ebpf/README.md](ebpf/README.md)
- **Policy Examples**: [policy/examples/](policy/examples/)

---

## 🔒 Security Model

ClawShield uses a **defense-in-depth** approach:

1. **Application Layer (Proxy)** - First line of defense
   - Blocks malicious tool calls before execution
   - Filters sensitive arguments (API keys, passwords)
   - Enforces domain restrictions

2. **Network Layer (Firewall)** - Second line of defense
   - Blocks unauthorized network connections
   - Even if a tool bypasses the proxy, it can't reach unapproved IPs
   - Logs all blocked attempts

3. **Kernel Layer (eBPF)** - Final line of defense
   - Detects behavioral anomalies at the syscall level
   - Monitors process execution, file access, privilege escalation
   - Real-time alerting on suspicious activity

**Philosophy**: Assume breach at every layer. Each component should be able to operate independently if others fail.

---

## 🤝 Contributing

ClawShield is part of the SleuthCo security tools ecosystem.

**Issues & PRs**: https://github.com/SleuthCo/clawshield

---

## 📄 License

*(To be determined)*

---

## 🙏 Acknowledgments

Built for the OpenClaw community. Inspired by traditional network security architectures applied to AI agent contexts.

---

**Need help?** Open an issue on GitHub.
