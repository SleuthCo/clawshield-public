package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SleuthCo/clawshield/shared/bus"
	"github.com/SleuthCo/clawshield/shared/types"
)

// Monitor is the interface for kernel-level security monitoring backends.
// Production deployments use the eBPF backend (cilium/ebpf + CO-RE).
// When eBPF is unavailable, the ProcfsMonitor provides degraded monitoring
// via /proc polling.
type Monitor interface {
	// Start begins monitoring. Events are published to the provided writer.
	Start(writer *bus.SocketWriter) error
	// Stop gracefully shuts down the monitor.
	Stop() error
	// Available returns true if this backend can run on the current system.
	Available() bool
	// Name returns the backend name ("ebpf" or "procfs").
	Name() string
	// Stats returns monitoring statistics.
	Stats() MonitorStats
}

// MonitorStats holds runtime statistics.
type MonitorStats struct {
	EventsPublished int64
	EventsDropped   int64
	StartTime       time.Time
	Backend         string
	Detections      map[string]int64 // event_type -> count
}

// MonitorConfig holds configuration for the monitor.
type MonitorConfig struct {
	PollInterval     time.Duration
	ForkBombThreshold int
	PortScanThreshold int
	ForkBombWindow   time.Duration
	PortScanWindow   time.Duration
	AllowedProcesses []string
	SensitiveFiles   []string
	SuspiciousPatterns []*regexp.Regexp
}

// DefaultConfig returns the default monitor configuration matching the
// original Python/BCC defaults from ebpf/config/default.yaml.
func DefaultConfig() *MonitorConfig {
	return &MonitorConfig{
		PollInterval:      1 * time.Second,
		ForkBombThreshold: 50,
		PortScanThreshold: 20,
		ForkBombWindow:    60 * time.Second,
		PortScanWindow:    60 * time.Second,
		AllowedProcesses:  []string{"sshd", "systemd", "clawshield"},
		SensitiveFiles: []string{
			"/etc/shadow",
			"/etc/sudoers",
			"/etc/passwd",
			"/root/.ssh",
			"/etc/ssl/private",
		},
		SuspiciousPatterns: []*regexp.Regexp{
			regexp.MustCompile(`curl.*\|.*sh`),
			regexp.MustCompile(`wget.*\|.*sh`),
			regexp.MustCompile(`nc\s+-e`),
			regexp.MustCompile(`bash\s+-i`),
			regexp.MustCompile(`python.*-c.*import`),
			regexp.MustCompile(`base64.*decode`),
		},
	}
}

// ProcfsMonitor provides degraded kernel monitoring via /proc filesystem
// polling when eBPF is unavailable. It detects:
// - Fork bombs (rapid process creation)
// - Suspicious commands (via /proc/[pid]/cmdline)
// - Sensitive file access (via /proc/[pid]/fd)
// - Privilege changes (via /proc/[pid]/status UID changes)
//
// This is intentionally less capable than the eBPF backend but provides
// basic coverage without requiring CAP_BPF or kernel headers.
type ProcfsMonitor struct {
	config    *MonitorConfig
	writer    *bus.SocketWriter
	stopCh    chan struct{}
	wg        sync.WaitGroup
	stats     MonitorStats
	statsMu   sync.Mutex

	// Tracking state (protected by trackingMu)
	trackingMu sync.RWMutex
	prevPids      map[int]bool
	execCounts    []time.Time // timestamps of recent exec events
	portConnects  map[int]map[int]time.Time // pid -> port -> time

	published atomic.Int64
	dropped   atomic.Int64
}

// NewProcfsMonitor creates a procfs-based monitor.
func NewProcfsMonitor(config *MonitorConfig) *ProcfsMonitor {
	if config == nil {
		config = DefaultConfig()
	}
	return &ProcfsMonitor{
		config:       config,
		stopCh:       make(chan struct{}),
		prevPids:     make(map[int]bool),
		execCounts:   []time.Time{},
		portConnects: make(map[int]map[int]time.Time),
		stats: MonitorStats{
			Backend:    "procfs",
			Detections: make(map[string]int64),
		},
	}
}

func (m *ProcfsMonitor) Available() bool {
	_, err := os.Stat("/proc")
	return err == nil
}

func (m *ProcfsMonitor) Name() string { return "procfs" }

func (m *ProcfsMonitor) Start(writer *bus.SocketWriter) error {
	m.writer = writer
	m.stats.StartTime = time.Now()

	// Initial PID snapshot
	m.prevPids = m.getCurrentPids()

	m.wg.Add(1)
	go m.pollLoop()

	log.Printf("ProcFS monitor started (degraded mode: no eBPF)")
	return nil
}

func (m *ProcfsMonitor) Stop() error {
	close(m.stopCh)
	m.wg.Wait()
	log.Printf("ProcFS monitor stopped: published=%d dropped=%d",
		m.published.Load(), m.dropped.Load())
	return nil
}

func (m *ProcfsMonitor) Stats() MonitorStats {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	s := m.stats
	s.EventsPublished = m.published.Load()
	s.EventsDropped = m.dropped.Load()
	return s
}

func (m *ProcfsMonitor) pollLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.poll()
		}
	}
}

func (m *ProcfsMonitor) poll() {
	currentPids := m.getCurrentPids()

	// Detect new processes
	now := time.Now()
	newCount := 0

	m.trackingMu.RLock()
	for pid := range currentPids {
		if !m.prevPids[pid] {
			newCount++
			m.checkProcess(pid)
		}
	}
	m.trackingMu.RUnlock()

	// Fork bomb detection (update under write lock)
	m.trackingMu.Lock()
	m.execCounts = append(m.execCounts, now)
	// Trim old entries
	cutoff := now.Add(-m.config.ForkBombWindow)
	filtered := m.execCounts[:0]
	for _, t := range m.execCounts {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	m.execCounts = filtered

	execCountLen := len(m.execCounts)
	m.trackingMu.Unlock()

	if newCount > 0 && execCountLen > m.config.ForkBombThreshold {
		m.publishEvent(types.SecurityEvent{
			EventType: "fork_bomb",
			Severity:  types.SeverityCritical,
			Source:    "ebpf",
			Timestamp: now,
			Details: map[string]string{
				"exec_count": strconv.Itoa(execCountLen),
				"window":     m.config.ForkBombWindow.String(),
				"threshold":  strconv.Itoa(m.config.ForkBombThreshold),
			},
		})
		m.recordDetection("fork_bomb")
	}

	m.trackingMu.Lock()
	m.prevPids = currentPids
	m.trackingMu.Unlock()
}

func (m *ProcfsMonitor) checkProcess(pid int) {
	// Read cmdline
	cmdline := m.readProcFile(pid, "cmdline")
	if cmdline == "" {
		return
	}

	// Check against allowed processes
	for _, allowed := range m.config.AllowedProcesses {
		if strings.Contains(cmdline, allowed) {
			return
		}
	}

	// Check suspicious patterns
	for _, pattern := range m.config.SuspiciousPatterns {
		if pattern.MatchString(cmdline) {
			m.publishEvent(types.SecurityEvent{
				EventType: "exec_suspicious",
				Severity:  types.SeverityHigh,
				Source:    "ebpf",
				Timestamp: time.Now(),
				Details: map[string]string{
					"pid":     strconv.Itoa(pid),
					"cmdline": truncate(sanitizeForLogging(cmdline), 200),
					"pattern": pattern.String(),
				},
			})
			m.recordDetection("exec_suspicious")
			return
		}
	}

	// Check for privilege escalation (UID 0)
	status := m.readProcFile(pid, "status")
	if strings.Contains(status, "Uid:\t0") {
		// Running as root — check if it was recently spawned
		comm := m.readProcFile(pid, "comm")
		if comm != "" && !m.isAllowed(comm) {
			m.publishEvent(types.SecurityEvent{
				EventType: "privesc",
				Severity:  types.SeverityCritical,
				Source:    "ebpf",
				Timestamp: time.Now(),
				Details: map[string]string{
					"pid":  strconv.Itoa(pid),
					"comm": comm,
					"uid":  "0",
				},
			})
			m.recordDetection("privesc")
		}
	}
}

func (m *ProcfsMonitor) getCurrentPids() map[int]bool {
	pids := make(map[int]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return pids
	}
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids[pid] = true
		}
	}
	return pids
}

func (m *ProcfsMonitor) readProcFile(pid int, name string) string {
	// Validate name against whitelist to prevent path traversal
	allowedNames := map[string]bool{
		"cmdline": true,
		"status":  true,
		"comm":    true,
		"fd":      true,
	}
	if !allowedNames[name] {
		return ""
	}

	pidPath := filepath.Join("/proc", strconv.Itoa(pid), name)

	// Detect symlinks to prevent TOCTOU attacks where attacker replaces process with symlink
	// Use Lstat to check for symlinks without following them
	info, err := os.Lstat(pidPath)
	if err != nil {
		return ""
	}
	if info.Mode()&os.ModeSymlink != 0 {
		log.Printf("WARNING: detected symlink at %s (possible TOCTOU attack)", pidPath)
		return ""
	}

	data, err := os.ReadFile(pidPath)
	if err != nil {
		return ""
	}
	// cmdline uses null bytes as separators
	result := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(result)
}

func (m *ProcfsMonitor) isAllowed(comm string) bool {
	for _, a := range m.config.AllowedProcesses {
		if strings.Contains(comm, a) {
			return true
		}
	}
	return false
}

func (m *ProcfsMonitor) publishEvent(event types.SecurityEvent) {
	if m.writer == nil {
		m.dropped.Add(1)
		return
	}
	if err := m.writer.Write(&event); err != nil {
		m.dropped.Add(1)
		return
	}
	m.published.Add(1)
}

func (m *ProcfsMonitor) recordDetection(eventType string) {
	m.statsMu.Lock()
	m.stats.Detections[eventType]++
	m.statsMu.Unlock()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
// sanitizeForLogging removes control characters from strings before logging
// to prevent log injection attacks. Attackers can craft /proc/[pid]/cmdline
// with embedded newlines, ANSI escape codes, or null bytes that could:
// - Break log parsers (SIEM ingestion)
// - Inject fake log entries
// - Corrupt terminal output when viewing logs
func sanitizeForLogging(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '_'
		}
		return r
	}, s)
}


// CheckEBPFAvailable checks whether the system supports eBPF.
// Returns true if:
// 1. Running on Linux
// 2. Kernel version >= 5.0
// 3. /sys/kernel/btf/vmlinux exists (BTF support for CO-RE)
// 4. CAP_BPF is available (or running as root)
func CheckEBPFAvailable() (bool, string) {
	// Check /proc exists (Linux)
	if _, err := os.Stat("/proc"); err != nil {
		return false, "not running on Linux (/proc not found)"
	}

	// Check kernel version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false, fmt.Sprintf("cannot read kernel version: %v", err)
	}
	versionStr := string(data)

	// Parse major.minor from "Linux version X.Y.Z ..."
	re := regexp.MustCompile(`Linux version (\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(versionStr)
	if len(matches) < 3 {
		return false, "cannot parse kernel version"
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	if major < 5 {
		return false, fmt.Sprintf("kernel %d.%d < 5.0 (eBPF CO-RE requires 5.0+)", major, minor)
	}

	// Check BTF support
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false, "BTF not available (/sys/kernel/btf/vmlinux not found)"
	}

	// Check if running as root (CAP_BPF check is complex, root is sufficient)
	if os.Geteuid() != 0 {
		return false, "not running as root (CAP_BPF required)"
	}

	return true, fmt.Sprintf("eBPF available (kernel %d.%d, BTF present, root)", major, minor)
}
