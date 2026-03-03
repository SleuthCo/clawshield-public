package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ProxyStatus represents the status returned by the ClawShield proxy.
type ProxyStatus struct {
	Version       string `json:"version"`
	PolicyHash    string `json:"policy_hash"`
	PolicyVersion string `json:"policy_version"`
	Status        string `json:"status"`
	Uptime        int64  `json:"uptime_seconds"`
}

// LocalStatus contains all locally-collected status information.
type LocalStatus struct {
	ProxyStatus    *ProxyStatus
	AuditDBSize    int64
	ProxyReachable bool
	CollectedAt    time.Time
}

// Collector gathers status from the local ClawShield proxy.
type Collector struct {
	ProxyURL    string // e.g., "http://localhost:18789"
	AuditDBPath string // e.g., "/var/lib/clawshield/audit.db"
	Client      *http.Client
}

// NewCollector creates a collector with sensible defaults.
func NewCollector(proxyURL, auditDBPath string) *Collector {
	return &Collector{
		ProxyURL:    proxyURL,
		AuditDBPath: auditDBPath,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Collect gathers all locally-available status information.
// It returns a LocalStatus with whatever data could be collected.
// It never returns an error — it always returns what it can collect.
func (c *Collector) Collect() *LocalStatus {
	status := &LocalStatus{
		CollectedAt: time.Now(),
	}

	// Try to collect proxy status
	proxyStatus, err := c.collectProxyStatus()
	if err == nil {
		status.ProxyStatus = proxyStatus
		status.ProxyReachable = true
	} else {
		status.ProxyReachable = false
	}

	// Always try to collect audit DB size
	status.AuditDBSize = c.collectAuditDBSize()

	return status
}

// collectProxyStatus retrieves the status from the ClawShield proxy via HTTP.
func (c *Collector) collectProxyStatus() (*ProxyStatus, error) {
	url := c.ProxyURL + "/api/v1/status"
	resp, err := c.Client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to reach proxy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned status %d", resp.StatusCode)
	}

	var status ProxyStatus
	limitedBody := io.LimitReader(resp.Body, 10*1024*1024) // 10MB limit
	if err := json.NewDecoder(limitedBody).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to parse proxy response: %w", err)
	}

	return &status, nil
}

// collectAuditDBSize returns the size of the audit database file,
// or 0 if the file does not exist.
func (c *Collector) collectAuditDBSize() int64 {
	info, err := os.Stat(c.AuditDBPath)
	if err != nil {
		return 0
	}
	return info.Size()
}
