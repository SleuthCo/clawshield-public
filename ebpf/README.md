# ClawShield eBPF Monitor (Layer 3)

Kernel-level security monitoring for ClawShield's defense-in-depth architecture.

## Architecture

The eBPF monitor is Layer 3 of ClawShield's three-layer defense:

| Layer | Component | Purpose |
|-------|-----------|---------|
| 1 | Proxy + Scanners | Application-level request/response scanning |
| 2 | iptables Firewall | Network-level egress filtering |
| **3** | **eBPF Monitor** | **Kernel-level process/network/file monitoring** |

## Backends

### eBPF (Production)
- CO-RE compiled eBPF programs via `cilium/ebpf`
- No kernel headers required at runtime
- Requires: Linux kernel 5.0+, BTF support, `CAP_BPF` or root
- Attaches kprobes to: `execve`, `tcp_v4_connect`, `do_sys_openat2`, `setuid`

### Procfs (Fallback)
- `/proc` filesystem polling when eBPF is unavailable
- Degraded but functional monitoring
- Works in containers without `CAP_BPF`
- Poll interval: 1 second (configurable)

## Detections

| Detection | Severity | Description |
|-----------|----------|-------------|
| Fork bomb | Critical | >50 new processes in 60s window |
| Suspicious exec | High | Matches patterns: `curl\|sh`, `nc -e`, `bash -i`, etc. |
| Privilege escalation | Critical | Process running as UID 0 (non-allowlisted) |
| Sensitive file access | High | Access to `/etc/shadow`, `/etc/sudoers`, etc. |
| Port scan | High | >20 unique destination ports in 60s |

## Usage

```bash
# Run with default settings
./clawshield-ebpf

# Custom socket path and poll interval
./clawshield-ebpf -socket /var/run/clawshield/events.sock -poll-interval 2s
```

## Graceful Degradation

At startup, the monitor checks eBPF availability:

```
[clawshield-ebpf] eBPF capability check: FAILED (kernel 4.19 < 5.0)
[clawshield-ebpf] Falling back to procfs-based monitoring (degraded mode)
[clawshield-ebpf] ProcFS monitor started (degraded mode: no eBPF)
```

The health check system reports Layer 3 as `degraded` when using procfs fallback.

## Health Check

The health system reports per-layer status:

```json
{
  "overall": "degraded",
  "layers": [
    {"name": "proxy", "layer": 1, "status": "healthy"},
    {"name": "firewall", "layer": 2, "status": "healthy"},
    {"name": "ebpf", "layer": 3, "status": "degraded", "backend": "procfs",
     "metrics": {"events_published": 142, "events_dropped": 0}}
  ]
}
```

## Event Pipeline

Events flow from the monitor to the proxy via Unix socket:

```
Monitor (eBPF/procfs) → Unix socket → EventBus → AdaptiveController → Proxy overrides
```

The event bus now tracks published and dropped events for pipeline health monitoring.
