# WSL2 Networking Constraints for ClawShield

## Overview

ClawShield enforces egress filtering at the kernel level via `iptables` on WSL2. Due to WSL2's architecture (Linux kernel in a lightweight VM with NAT), certain networking behaviors differ from native Linux.

## Key Constraints

### 1. **NAT Gateway & IP Range**
- WSL2 uses a virtualized network interface with NAT, assigning IPs in the `172.x.x.x` range (typically `172.28.x.x`, but varies by host).
- The Windows host is reachable via `172.XX.XX.1` (first IP of subnet). This is **not** a static address.
- ClawShield must allow traffic to the entire `172.16.0.0/12` range to ensure connectivity to host and DHCP services.

### 2. **DNS Resolution Behavior**
- WSL2 uses Windows-hosted DNS resolver (typically via `172.XX.XX.1`).
- DNS queries are forwarded from WSL2 → Windows → upstream DNS.
- ClawShield must allow outbound DNS traffic to the configured resolvers (e.g., 8.8.8.8, 1.1.1.1) — **not** the WSL2 gateway IP.

### 3. **IP Address Changes on Boot/Resume**
- The WSL2 network subnet changes after reboot or suspend/resume.
- The `172.x.x.x` range may shift (e.g., from `172.28.0.0/16` to `172.29.0.0/16`).
- **Solution**: ClawShield uses `/12` wildcard (`172.16.0.0/12`) to cover all possible WSL2 subnets.

### 4. **Loopback Interface**
- `127.0.0.1` is fully functional within WSL2 and should be permitted for local services (e.g., databases, dev servers).

### 5. **No Direct Access to Windows Network Stack**
- ClawShield cannot directly block or allow traffic originating from Windows.
- All rules apply only to outbound packets from the WSL2 Linux environment.

### 6. **iptables Persistence**
- WSL2 does not persist `iptables` rules across restarts by default.
- Use `clawshield-fw install` script to reapply on boot via `/etc/profile.d/` or systemd service (recommended).

## Recommended Configuration

```yaml
allowed_domains:
  - "example.com"
  - "api.github.com"
dns_resolvers:
  - "8.8.8.8"     # Google DNS
  - "1.0.0.1"     # Cloudflare DNS
```

Do **not** include `172.x.x.x` IPs in `dns_resolvers` — those are internal WSL2 gateways and not the target resolvers.

## Testing

Use `curl -v https://example.com` to verify connectivity, and `dmesg | grep CLAWSHIELD-BLOCKED` to check blocked attempts.