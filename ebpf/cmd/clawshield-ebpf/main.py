#!/usr/bin/env python3
"""
Sentinel eBPF Security Monitor

Kernel-level security monitoring using eBPF. Detects:
- Suspicious process execution
- Unauthorized network connections
- Sensitive file access
- Privilege escalation attempts
- Anomalous syscall patterns

Run with: sudo python3 security_monitor.py
"""

import os
import sys
import signal
import argparse
import yaml
import json
import re
import threading
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from queue import Queue

# BCC imports
from bcc import BPF

# Optional: Telegram alerts
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


# ============================================================================
# eBPF Programs
# ============================================================================

BPF_PROCESS_MONITOR = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct exec_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[64];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);
BPF_HASH(exec_count, u32, u64);

int trace_execve(struct pt_regs *ctx,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    struct exec_event event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;

    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    // Track exec count per parent (fork bomb detection)
    u64 *count = exec_count.lookup(&event.ppid);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        exec_count.update(&event.ppid, &one);
    }

    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

BPF_NETWORK_MONITOR = """
#include <uapi/linux/ptrace.h>
struct bpf_wq {};  /* Forward decl — fixes kernel 6.14+ / BCC 0.29 header mismatch */
#include <net/sock.h>
#include <bcc/proto.h>

struct conn_event {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[64];
};

BPF_PERF_OUTPUT(conn_events);
BPF_HASH(port_scan, u32, u64);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct conn_event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);
    event.dport = ntohs(event.dport);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Track unique ports per source (port scan detection)
    u64 *count = port_scan.lookup(&event.pid);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        port_scan.update(&event.pid, &one);
    }

    conn_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

BPF_FILE_MONITOR = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

struct file_event {
    u32 pid;
    u32 uid;
    int flags;
    char comm[64];
    char filename[256];
};

BPF_PERF_OUTPUT(file_events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct file_event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    file_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

BPF_PRIVESC_MONITOR = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct privesc_event {
    u32 pid;
    u32 old_uid;
    u32 new_uid;
    char comm[64];
};

BPF_PERF_OUTPUT(privesc_events);

int trace_setuid(struct pt_regs *ctx, uid_t uid) {
    struct privesc_event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.new_uid = uid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Only alert if changing to root (uid 0)
    if (uid == 0 && event.old_uid != 0) {
        privesc_events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
"""


# ============================================================================
# Alert Handler
# ============================================================================

class AlertHandler:
    def __init__(self, config: dict):
        self.config = config
        self.telegram_token = os.environ.get('SENTINEL_BOT_TOKEN')
        self.telegram_chat = os.environ.get('TELEGRAM_CHAT_ID')
        self.log_file = config.get('alerts', {}).get('log_file')
        self.console = config.get('alerts', {}).get('console', True)
        self._alert_queue = Queue()
        self._telegram_thread = None

        # Start telegram thread if configured
        if self.telegram_token and self.telegram_chat and HTTPX_AVAILABLE:
            self._start_telegram_thread()

    def _start_telegram_thread(self):
        def telegram_worker():
            with httpx.Client(timeout=10) as client:
                while True:
                    msg = self._alert_queue.get()
                    if msg is None:
                        break
                    try:
                        client.post(
                            f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                            json={
                                'chat_id': self.telegram_chat,
                                'text': msg,
                                'parse_mode': 'Markdown'
                            }
                        )
                    except Exception as e:
                        print(f"Telegram error: {e}")

        self._telegram_thread = threading.Thread(target=telegram_worker, daemon=True)
        self._telegram_thread.start()

    def _format_alert(self, severity: str, title: str, details: dict) -> str:
        icon = {'critical': '🚨', 'high': '⚠️', 'medium': '🔔', 'low': 'ℹ️'}.get(severity, '📢')
        lines = [f"{icon} **{severity.upper()}: {title}**", ""]
        for k, v in details.items():
            lines.append(f"• {k}: `{v}`")
        lines.append(f"\n_Detected at {datetime.now().strftime('%H:%M:%S')}_")
        return "\n".join(lines)

    def send(self, severity: str, title: str, details: dict):
        msg = self._format_alert(severity, title, details)

        # Console output
        if self.console:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {severity.upper()}: {title}")
            for k, v in details.items():
                print(f"  {k}: {v}")

        # Log file
        if self.log_file:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(json.dumps({
                        'timestamp': datetime.now().isoformat(),
                        'severity': severity,
                        'title': title,
                        'details': details
                    }) + '\n')
            except Exception as e:
                print(f"Log write error: {e}")

        # Telegram (async via queue)
        if self._telegram_thread:
            self._alert_queue.put(msg)

    def stop(self):
        if self._telegram_thread:
            self._alert_queue.put(None)
            self._telegram_thread.join(timeout=2)


# ============================================================================
# Security Monitor
# ============================================================================

class SecurityMonitor:
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.alerts = AlertHandler(self.config)
        self.bpf_objects = {}
        self.running = False

        # Detection state
        self.exec_history = defaultdict(list)  # pid -> [timestamps]
        self.conn_history = defaultdict(set)   # pid -> set of ports

        # Compile suspicious patterns
        self._suspicious_patterns = [
            re.compile(p) for p in
            self.config.get('suspicious', {}).get('commands', [])
        ]

    def _load_config(self, path: str) -> dict:
        if path and Path(path).exists():
            with open(path) as f:
                return yaml.safe_load(f)
        # Default config
        return {
            'detectors': {
                'process_execution': True,
                'network_connections': True,
                'file_access': True,
                'privilege_escalation': True,
            },
            'alerts': {'console': True},
            'thresholds': {
                'fork_bomb_threshold': 50,
                'port_scan_threshold': 20,
            },
            'allowlist': {'processes': [], 'users': []},
            'suspicious': {
                'commands': [r'curl.*\|.*sh', r'nc -e', r'bash -i'],
                'files': ['/etc/shadow', '/etc/sudoers'],
                'network': [4444, 5555, 31337],
            }
        }

    def _is_allowed_process(self, filename: str) -> bool:
        allowed = self.config.get('allowlist', {}).get('processes', [])
        return any(filename.startswith(p) for p in allowed)

    def _is_suspicious_command(self, cmd: str) -> bool:
        return any(p.search(cmd) for p in self._suspicious_patterns)

    def _is_sensitive_file(self, filename: str) -> bool:
        sensitive = self.config.get('suspicious', {}).get('files', [])
        return any(s in filename for s in sensitive)

    def _is_suspicious_port(self, port: int) -> bool:
        ports = self.config.get('suspicious', {}).get('network', [])
        return port in ports

    # --- Event Handlers ---

    def _handle_exec_event(self, cpu, data, size):
        event = self.bpf_objects['process']['exec_events'].event(data)
        filename = event.filename.decode('utf-8', errors='replace')
        comm = event.comm.decode('utf-8', errors='replace')

        if self._is_allowed_process(filename):
            return

        # Check for suspicious command patterns
        if self._is_suspicious_command(filename):
            self.alerts.send('high', 'Suspicious Command Execution', {
                'PID': event.pid,
                'Parent PID': event.ppid,
                'User': event.uid,
                'Command': comm,
                'Path': filename
            })

        # Fork bomb detection
        now = datetime.now().timestamp()
        self.exec_history[event.ppid].append(now)
        # Keep only last 60 seconds
        self.exec_history[event.ppid] = [
            t for t in self.exec_history[event.ppid] if now - t < 60
        ]
        threshold = self.config.get('thresholds', {}).get('fork_bomb_threshold', 50)
        if len(self.exec_history[event.ppid]) > threshold:
            self.alerts.send('critical', 'Possible Fork Bomb Detected', {
                'Parent PID': event.ppid,
                'Spawns in 60s': len(self.exec_history[event.ppid]),
                'Latest child': comm
            })

    def _handle_conn_event(self, cpu, data, size):
        event = self.bpf_objects['network']['conn_events'].event(data)
        comm = event.comm.decode('utf-8', errors='replace')
        daddr = self._int_to_ip(event.daddr)
        dport = event.dport

        # Suspicious port check
        if self._is_suspicious_port(dport):
            self.alerts.send('high', 'Connection to Suspicious Port', {
                'PID': event.pid,
                'Process': comm,
                'Destination': f"{daddr}:{dport}",
                'User': event.uid
            })

        # Port scan detection
        self.conn_history[event.pid].add(dport)
        threshold = self.config.get('thresholds', {}).get('port_scan_threshold', 20)
        if len(self.conn_history[event.pid]) > threshold:
            self.alerts.send('medium', 'Possible Port Scan', {
                'PID': event.pid,
                'Process': comm,
                'Unique ports': len(self.conn_history[event.pid])
            })

    def _handle_file_event(self, cpu, data, size):
        event = self.bpf_objects['file']['file_events'].event(data)
        filename = event.filename.decode('utf-8', errors='replace')
        comm = event.comm.decode('utf-8', errors='replace')

        # Show all file opens for debugging (filter to shadow/sudoers)
        if 'shadow' in filename or 'sudoers' in filename or 'passwd' in filename:
            flags = 'WRITE' if event.flags & 0x01 else 'READ'
            print(f"[FILE] {comm} ({event.pid}) -> {filename}")

            self.alerts.send('high', 'Sensitive File Access', {
                'PID': event.pid,
                'Process': comm,
                'File': filename,
                'Mode': flags,
                'User': event.uid
            })

    def _handle_privesc_event(self, cpu, data, size):
        event = self.bpf_objects['privesc']['privesc_events'].event(data)
        comm = event.comm.decode('utf-8', errors='replace')

        self.alerts.send('critical', 'Privilege Escalation to Root', {
            'PID': event.pid,
            'Process': comm,
            'From UID': event.old_uid,
            'To UID': event.new_uid
        })

    @staticmethod
    def _int_to_ip(addr: int) -> str:
        return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"

    # --- Main Loop ---

    def start(self):
        print("🛡️  Sentinel eBPF Security Monitor")
        print("=" * 50)

        detectors = self.config.get('detectors', {})

        if detectors.get('process_execution'):
            print("Loading process execution monitor...")
            b = BPF(text=BPF_PROCESS_MONITOR)
            b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
            b["exec_events"].open_perf_buffer(self._handle_exec_event, page_cnt=64)
            self.bpf_objects['process'] = b

        if detectors.get('network_connections'):
            print("Loading network connection monitor...")
            b = BPF(text=BPF_NETWORK_MONITOR)
            b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
            b["conn_events"].open_perf_buffer(self._handle_conn_event, page_cnt=64)
            self.bpf_objects['network'] = b

        if detectors.get('file_access'):
            print("Loading file access monitor...")
            b = BPF(text=BPF_FILE_MONITOR)
            b.attach_kprobe(event="do_sys_openat2", fn_name="trace_openat")
            b["file_events"].open_perf_buffer(self._handle_file_event, page_cnt=256)
            self.bpf_objects['file'] = b

        if detectors.get('privilege_escalation'):
            print("Loading privilege escalation monitor...")
            b = BPF(text=BPF_PRIVESC_MONITOR)
            b.attach_kprobe(event="__x64_sys_setuid", fn_name="trace_setuid")
            b["privesc_events"].open_perf_buffer(self._handle_privesc_event, page_cnt=16)
            self.bpf_objects['privesc'] = b

        print("=" * 50)
        print(f"Monitoring started. Press Ctrl+C to stop.")
        print("")

        self.running = True

        # Set up signal handler
        def signal_handler(sig, frame):
            print("\nShutting down...")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Main polling loop
        while self.running:
            for name, bpf in self.bpf_objects.items():
                bpf.perf_buffer_poll(timeout=100)

    def stop(self):
        self.running = False
        self.alerts.stop()
        for bpf in self.bpf_objects.values():
            bpf.cleanup()


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Sentinel eBPF Security Monitor')
    parser.add_argument('-c', '--config', help='Path to config.yaml')
    parser.add_argument('--no-telegram', action='store_true', help='Disable Telegram alerts')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script requires root privileges.")
        print("Run with: sudo python3 security_monitor.py")
        sys.exit(1)

    config_path = args.config or str(Path(__file__).parent / 'config.yaml')
    monitor = SecurityMonitor(config_path)

    try:
        monitor.start()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == '__main__':
    main()
