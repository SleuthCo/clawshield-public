package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed static/*
var staticFS embed.FS

// serveDashboard serves the embedded dashboard HTML (static/index.html).
func (p *httpProxy) serveDashboard(w http.ResponseWriter, r *http.Request) {
	// Only serve index.html for the root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, err := fs.ReadFile(staticFS, "static/index.html")
	if err != nil {
		log.Printf("Failed to read embedded index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// serveFavicon serves the ClawShield favicon SVG, overriding OpenClaw's lobster logo.
func (p *httpProxy) serveFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(staticFS, "static/favicon.svg")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// serveControlUISkin serves the branded Control UI index.html (static/control-ui-index.html).
// This replaces OpenClaw's default index.html with ClawShield-skinned version.
func (p *httpProxy) serveControlUISkin(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(staticFS, "static/control-ui-index.html")
	if err != nil {
		log.Printf("Failed to read embedded control-ui-index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// serveStaticAsset serves embedded static assets (logo, etc.) from static/ directory.
func (p *httpProxy) serveStaticAsset(w http.ResponseWriter, r *http.Request) {
	// Strip /static/ prefix
	relPath := strings.TrimPrefix(r.URL.Path, "/static/")
	if relPath == "" || strings.Contains(relPath, "..") {
		http.NotFound(w, r)
		return
	}

	data, err := fs.ReadFile(staticFS, "static/"+relPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.HasSuffix(relPath, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(relPath, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(relPath, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	case strings.HasSuffix(relPath, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(relPath, ".css"):
		w.Header().Set("Content-Type", "text/css")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// serveControlUIAsset serves Control UI static assets (JS, CSS, images) from
// a local directory. Used when the gateway can't serve its own assets.
func (p *httpProxy) serveControlUIAsset(w http.ResponseWriter, r *http.Request) {
	if p.controlUIDir == "" {
		http.Error(w, "Control UI assets not configured", http.StatusNotFound)
		return
	}

	// Strip /control-ui/ prefix to get relative asset path
	relPath := strings.TrimPrefix(r.URL.Path, "/control-ui/")
	if relPath == "" || relPath == "/" {
		// Redirect bare /control-ui/ to our skinned index.html
		p.serveControlUISkin(w, r)
		return
	}

	// Sanitize: no .. traversal
	clean := filepath.Clean(relPath)
	if strings.Contains(clean, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	filePath := filepath.Join(p.controlUIDir, clean)
	if _, err := os.Stat(filePath); err != nil {
		// SPA fallback: non-file paths (no extension) serve the branded index.html
		if !strings.Contains(filepath.Base(clean), ".") {
			p.serveControlUISkin(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	// Set content type for known extensions
	switch {
	case strings.HasSuffix(filePath, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(filePath, ".css"):
		w.Header().Set("Content-Type", "text/css")
	case strings.HasSuffix(filePath, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(filePath, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(filePath, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	}

	// Cache hashed assets aggressively
	if strings.Contains(relPath, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	http.ServeFile(w, r, filePath)
}

// handleStatusAPI returns system status for the dashboard Status tab.
// GET /api/v1/status — loopback-only in standalone mode, auth required otherwise.
// SECURITY: Does not expose scanner details or session IDs to unauthenticated clients
// to prevent reconnaissance attacks that reveal which defenses are active.
func (p *httpProxy) handleStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine if this is an authenticated/trusted request
	isTrusted := false
	if p.standaloneMode {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host == "" {
			host = r.RemoteAddr
		}
		isTrusted = host == "127.0.0.1" || host == "::1" || host == "localhost"
	}
	if !isTrusted && p.authToken != "" {
		authHeader := r.Header.Get("Authorization")
		isTrusted = secureTokenCompare(authHeader, "Bearer "+p.authToken)
	}

	uptime := int64(0)
	if !p.startTime.IsZero() {
		uptime = int64(time.Since(p.startTime).Seconds())
	}

	// Unauthenticated clients only get basic health info — no internal details
	if !isTrusted {
		resp := map[string]interface{}{
			"status": "ok",
			"uptime": uptime,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Authenticated/trusted clients get full details
	agents := []string{"anvil", "harbor", "shield", "beacon", "lens"}

	// Check if policy has an explicit agent allowlist
	if p.evaluator != nil {
		if policyAgents := p.evaluator.AgentAllowlist(); len(policyAgents) > 0 {
			agents = policyAgents
		}
	}

	scanners := map[string]bool{
		"injection": p.evaluator != nil && p.evaluator.InjectionDetector() != nil,
		"vuln":      p.evaluator != nil && p.evaluator.VulnScanner() != nil,
		"malware":   p.evaluator != nil && p.evaluator.MalwareScanner() != nil,
		"secrets":   p.evaluator != nil && p.evaluator.SecretsScanner() != nil,
		"pii":       p.evaluator != nil && p.evaluator.PIIScanner() != nil,
	}

	resp := map[string]interface{}{
		"status":    "ok",
		"agents":    agents,
		"scanners":  scanners,
		"sessionId": p.sessionID,
		"uptime":    uptime,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
