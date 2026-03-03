package collector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestCollect_ProxyReachable verifies that collection works when proxy is reachable.
func TestCollect_ProxyReachable(t *testing.T) {
	// Create a mock proxy server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		status := ProxyStatus{
			Version:       "1.0.0",
			PolicyHash:    "abc123",
			PolicyVersion: "2024-01-15",
			Status:        "healthy",
			Uptime:        3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}))
	defer server.Close()

	// Create a temporary file for audit DB
	tmpFile, err := os.CreateTemp("", "audit*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write some data to the temp file
	if _, err := tmpFile.Write([]byte("test data")); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Create collector and collect
	c := NewCollector(server.URL, tmpFile.Name())
	status := c.Collect()

	// Verify results
	if !status.ProxyReachable {
		t.Error("expected proxy to be reachable")
	}
	if status.ProxyStatus == nil {
		t.Error("expected ProxyStatus to be set")
	}
	if status.ProxyStatus.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", status.ProxyStatus.Version)
	}
	if status.AuditDBSize != 9 {
		t.Errorf("expected audit DB size 9, got %d", status.AuditDBSize)
	}
	if status.CollectedAt.IsZero() {
		t.Error("expected CollectedAt to be set")
	}
}

// TestCollect_ProxyUnreachable verifies that collection works even when proxy is unreachable.
func TestCollect_ProxyUnreachable(t *testing.T) {
	// Create a temporary file for audit DB
	tmpFile, err := os.CreateTemp("", "audit*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write some data to the temp file
	if _, err := tmpFile.Write([]byte("test data")); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Create collector with invalid proxy URL
	c := NewCollector("http://invalid-host-that-does-not-exist:99999", tmpFile.Name())
	status := c.Collect()

	// Verify results
	if status.ProxyReachable {
		t.Error("expected proxy to be unreachable")
	}
	if status.ProxyStatus != nil {
		t.Error("expected ProxyStatus to be nil")
	}
	if status.AuditDBSize != 9 {
		t.Errorf("expected audit DB size 9, got %d", status.AuditDBSize)
	}
	if status.CollectedAt.IsZero() {
		t.Error("expected CollectedAt to be set")
	}
}

// TestCollect_AuditDBSize verifies that audit DB size is collected correctly.
func TestCollect_AuditDBSize(t *testing.T) {
	// Create a temporary file with known size
	tmpFile, err := os.CreateTemp("", "audit*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write exactly 1024 bytes
	data := make([]byte, 1024)
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Create a mock proxy server to avoid proxy errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create collector and collect
	c := NewCollector(server.URL, tmpFile.Name())
	status := c.Collect()

	// Verify DB size is correct
	if status.AuditDBSize != 1024 {
		t.Errorf("expected audit DB size 1024, got %d", status.AuditDBSize)
	}
}

// TestCollect_AuditDBMissing verifies that size is 0 when audit DB is missing.
func TestCollect_AuditDBMissing(t *testing.T) {
	// Create a mock proxy server to avoid proxy errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create collector with non-existent path
	c := NewCollector(server.URL, "/non/existent/path/audit.db")
	status := c.Collect()

	// Verify DB size is 0
	if status.AuditDBSize != 0 {
		t.Errorf("expected audit DB size 0, got %d", status.AuditDBSize)
	}
}
