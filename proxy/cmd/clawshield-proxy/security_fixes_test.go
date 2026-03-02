package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
)

// =============================================================================
// CRITICAL-1: Binary WebSocket frame blocking
// =============================================================================

func TestWebSocket_BinaryFramesBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		for {
			msgType, data, err := c.Read(context.Background())
			if err != nil {
				return
			}
			_ = c.Write(context.Background(), msgType, data)
		}
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL: mustParseURL(upstream.URL),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  200,
		maxBytes:   1048576,
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(p.handler))
	defer proxyServer.Close()

	wsURL := "ws" + strings.TrimPrefix(proxyServer.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial failed: %v", err)
	}
	defer client.Close(websocket.StatusNormalClosure, "")

	// Send a binary frame with a malicious JSON-RPC payload
	maliciousPayload := []byte(`{"method":"shell.exec","params":{"cmd":"rm -rf /"}}`)
	if err := client.Write(ctx, websocket.MessageBinary, maliciousPayload); err != nil {
		t.Fatalf("WS binary write failed: %v", err)
	}

	// We should get an error frame back (text), NOT our binary echoed
	_, data, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}

	var errResp map[string]interface{}
	if err := json.Unmarshal(data, &errResp); err != nil {
		t.Fatalf("Failed to parse response: %v (raw: %s)", err, string(data))
	}

	if _, hasError := errResp["error"]; !hasError {
		t.Errorf("Binary frame should have been blocked, got: %s", string(data))
	}

	// Verify text frames still work
	textMsg := `{"method":"read","params":{"path":"test.txt"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(textMsg)); err != nil {
		t.Fatalf("WS text write failed: %v", err)
	}
	_, data, err = client.Read(ctx)
	if err != nil {
		t.Fatalf("WS text read failed: %v", err)
	}
	if string(data) != textMsg {
		t.Logf("Text frame passed through (may be transformed): %s", string(data))
	}
}

// =============================================================================
// CRITICAL-2: HTTP request body scanning
// =============================================================================

func TestHTTPProxy_RequestBodyScanning_BlocksDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Request should not have reached upstream — it should have been blocked")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		Denylist:      []string{"shell.exec"},
	})

	p := &httpProxy{
		gatewayURL: mustParseURL(upstream.URL),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  200,
		maxBytes:   1048576,
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(p.handler))
	defer proxyServer.Close()

	// POST a JSON body containing a denied method
	body := `{"method":"shell.exec","params":{"cmd":"rm -rf /"}}`
	req, _ := http.NewRequest("POST", proxyServer.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for denied method in HTTP body, got %d", resp.StatusCode)
	}
}

func TestHTTPProxy_RequestBodyScanning_AllowsClean(t *testing.T) {
	var upstreamReached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReached = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		Denylist:      []string{"shell.exec"},
	})

	p := &httpProxy{
		gatewayURL: mustParseURL(upstream.URL),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  200,
		maxBytes:   1048576,
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(p.handler))
	defer proxyServer.Close()

	// POST a clean JSON body
	body := `{"method":"read","params":{"path":"test.txt"}}`
	req, _ := http.NewRequest("POST", proxyServer.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for clean body, got %d", resp.StatusCode)
	}
	if !upstreamReached {
		t.Error("Clean request should have been forwarded to upstream")
	}
}

func TestHTTPProxy_RequestBodyScanning_OversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Oversized request should not have reached upstream")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL: mustParseURL(upstream.URL),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  200,
		maxBytes:   1024, // Very small limit for testing
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(p.handler))
	defer proxyServer.Close()

	// POST a body that exceeds maxBytes
	bigBody := strings.Repeat("x", 2048)
	req, _ := http.NewRequest("POST", proxyServer.URL+"/test", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413 for oversized body, got %d", resp.StatusCode)
	}
}

func TestHTTPProxy_GETRequestsNotScanned(t *testing.T) {
	var upstreamReached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReached = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL: mustParseURL(upstream.URL),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  200,
		maxBytes:   1048576,
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(p.handler))
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/health")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET should pass through without body scanning, got %d", resp.StatusCode)
	}
	if !upstreamReached {
		t.Error("GET request should have been forwarded to upstream")
	}
}

// =============================================================================
// CRITICAL-4: Audit API auth in standalone mode
// =============================================================================

func TestAuditAPI_StandaloneMode_RequiresAuthFromNonLoopback(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL:     mustParseURL("http://localhost:8080"),
		authToken:      "test-secret-token",
		evaluator:      eval,
		sessionID:      "test-session",
		standaloneMode: true,
		timeoutMs:      200,
		maxBytes:       1048576,
	}

	// Test without auth token — should fail for non-loopback
	req := httptest.NewRequest("GET", "/api/v1/audit", nil)
	req.RemoteAddr = "192.168.1.100:12345" // Non-loopback address
	w := httptest.NewRecorder()

	p.handleAuditAPI(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for non-loopback without auth, got %d", w.Code)
	}

	// Test with correct auth token from non-loopback — should succeed (returns 503 since no DB)
	req2 := httptest.NewRequest("GET", "/api/v1/audit", nil)
	req2.RemoteAddr = "192.168.1.100:12345"
	req2.Header.Set("Authorization", "Bearer test-secret-token")
	w2 := httptest.NewRecorder()

	p.handleAuditAPI(w2, req2)

	// Should get past auth (503 because auditDB is nil, which is fine)
	if w2.Code == http.StatusUnauthorized {
		t.Error("Should have passed auth with correct token from non-loopback")
	}

	// Test with wrong auth token — should fail
	req3 := httptest.NewRequest("GET", "/api/v1/audit", nil)
	req3.RemoteAddr = "192.168.1.100:12345"
	req3.Header.Set("Authorization", "Bearer wrong-token")
	w3 := httptest.NewRecorder()

	p.handleAuditAPI(w3, req3)

	if w3.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong token, got %d", w3.Code)
	}
}

func TestAuditAPI_StandaloneMode_AllowsLoopback(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL:     mustParseURL("http://localhost:8080"),
		authToken:      "test-secret-token",
		evaluator:      eval,
		sessionID:      "test-session",
		standaloneMode: true,
		timeoutMs:      200,
		maxBytes:       1048576,
	}

	loopbackAddrs := []string{"127.0.0.1:12345", "[::1]:12345"}
	for _, addr := range loopbackAddrs {
		req := httptest.NewRequest("GET", "/api/v1/audit", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()

		p.handleAuditAPI(w, req)

		// Should get past auth — expect 503 (no DB) not 401
		if w.Code == http.StatusUnauthorized {
			t.Errorf("Loopback address %s should bypass auth, got 401", addr)
		}
	}
}

func TestAuditAPI_NonStandaloneMode_AlwaysRequiresAuth(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL:     mustParseURL("http://localhost:8080"),
		authToken:      "test-secret-token",
		evaluator:      eval,
		sessionID:      "test-session",
		standaloneMode: false,
		timeoutMs:      200,
		maxBytes:       1048576,
	}

	// Even from loopback, auth is required in non-standalone mode
	req := httptest.NewRequest("GET", "/api/v1/audit", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	p.handleAuditAPI(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth even from loopback in non-standalone mode, got %d", w.Code)
	}
}

// =============================================================================
// CRITICAL-5: Status API info hiding
// =============================================================================

func TestStatusAPI_UnauthenticatedHidesDetails(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		OpenClaw: &engine.OpenClawConfig{
			AgentAllowlist: []string{"friday", "pepper"},
		},
	})
	p := &httpProxy{
		gatewayURL:     mustParseURL("http://localhost:8080"),
		authToken:      "test-secret-token",
		evaluator:      eval,
		sessionID:      "secret-session-id",
		standaloneMode: true,
		startTime:      time.Now().Add(-60 * time.Second),
		timeoutMs:      200,
		maxBytes:       1048576,
	}

	// Unauthenticated request from non-loopback
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	p.handleStatusAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should NOT contain sensitive details
	if _, has := resp["sessionId"]; has {
		t.Error("Unauthenticated response should NOT contain sessionId")
	}
	if _, has := resp["scanners"]; has {
		t.Error("Unauthenticated response should NOT contain scanner details")
	}
	if _, has := resp["agents"]; has {
		t.Error("Unauthenticated response should NOT contain agent list")
	}

	// Should contain basic health info
	if resp["status"] != "ok" {
		t.Errorf("Expected status=ok, got %v", resp["status"])
	}
}

func TestStatusAPI_AuthenticatedShowsDetails(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		OpenClaw: &engine.OpenClawConfig{
			AgentAllowlist: []string{"friday", "pepper"},
		},
	})
	p := &httpProxy{
		gatewayURL:     mustParseURL("http://localhost:8080"),
		authToken:      "test-secret-token",
		evaluator:      eval,
		sessionID:      "secret-session-id",
		standaloneMode: true,
		startTime:      time.Now().Add(-60 * time.Second),
		timeoutMs:      200,
		maxBytes:       1048576,
	}

	// Authenticated request
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("Authorization", "Bearer test-secret-token")
	w := httptest.NewRecorder()

	p.handleStatusAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Authenticated response SHOULD contain full details
	if _, has := resp["sessionId"]; !has {
		t.Error("Authenticated response should contain sessionId")
	}
	if _, has := resp["scanners"]; !has {
		t.Error("Authenticated response should contain scanner details")
	}
	if _, has := resp["agents"]; !has {
		t.Error("Authenticated response should contain agent list")
	}
}

func TestStatusAPI_LoopbackShowsDetails(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	p := &httpProxy{
		gatewayURL:     mustParseURL("http://localhost:8080"),
		authToken:      "test-secret-token",
		evaluator:      eval,
		sessionID:      "secret-session-id",
		standaloneMode: true,
		startTime:      time.Now().Add(-60 * time.Second),
		timeoutMs:      200,
		maxBytes:       1048576,
	}

	// Loopback request without auth
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	p.handleStatusAPI(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if _, has := resp["sessionId"]; !has {
		t.Error("Loopback request should see full details including sessionId")
	}
}

// =============================================================================
// HIGH-9: Studio ticket expiry validation
// =============================================================================

func TestStudioTicketValidate_ValidTicket(t *testing.T) {
	studioToken := "test-studio-secret"
	p := &httpProxy{
		gatewayURL:  mustParseURL("http://localhost:8080"),
		studioToken: studioToken,
		sessionID:   "test-session",
		timeoutMs:   200,
		maxBytes:    1048576,
	}

	// Create a valid ticket manually
	agent := "friday"
	now := time.Now().Unix()
	expiry := now + 300
	nonce := "abcdef1234567890abcdef1234567890"
	payload := fmt.Sprintf("%s|%d|%d|%s", agent, now, expiry, nonce)

	mac := hmac.New(sha256.New, []byte(studioToken))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	ticketRaw := payload + "|" + sig
	ticket := base64.RawURLEncoding.EncodeToString([]byte(ticketRaw))

	req := httptest.NewRequest("GET", "/v1/studio/ticket/validate?ticket="+ticket, nil)
	w := httptest.NewRecorder()

	p.handleStudioTicketValidate(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["valid"] != true {
		t.Errorf("Expected valid=true for fresh ticket, got %v", resp)
	}
	if resp["agent"] != "friday" {
		t.Errorf("Expected agent=friday, got %v", resp["agent"])
	}
}

func TestStudioTicketValidate_ExpiredTicket(t *testing.T) {
	studioToken := "test-studio-secret"
	p := &httpProxy{
		gatewayURL:  mustParseURL("http://localhost:8080"),
		studioToken: studioToken,
		sessionID:   "test-session",
		timeoutMs:   200,
		maxBytes:    1048576,
	}

	// Create an expired ticket (expiry in the past)
	agent := "friday"
	now := time.Now().Unix() - 600 // 10 minutes ago
	expiry := now + 300            // expired 5 minutes ago
	nonce := "abcdef1234567890abcdef1234567890"
	payload := fmt.Sprintf("%s|%d|%d|%s", agent, now, expiry, nonce)

	mac := hmac.New(sha256.New, []byte(studioToken))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	ticketRaw := payload + "|" + sig
	ticket := base64.RawURLEncoding.EncodeToString([]byte(ticketRaw))

	req := httptest.NewRequest("GET", "/v1/studio/ticket/validate?ticket="+ticket, nil)
	w := httptest.NewRecorder()

	p.handleStudioTicketValidate(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["valid"] != false {
		t.Errorf("Expected valid=false for expired ticket, got %v", resp)
	}
	if resp["error"] != "ticket expired" {
		t.Errorf("Expected error='ticket expired', got %v", resp["error"])
	}
}

func TestStudioTicketValidate_TamperedSignature(t *testing.T) {
	studioToken := "test-studio-secret"
	p := &httpProxy{
		gatewayURL:  mustParseURL("http://localhost:8080"),
		studioToken: studioToken,
		sessionID:   "test-session",
		timeoutMs:   200,
		maxBytes:    1048576,
	}

	// Create a ticket with a tampered signature
	agent := "friday"
	now := time.Now().Unix()
	expiry := now + 300
	nonce := "abcdef1234567890abcdef1234567890"
	payload := fmt.Sprintf("%s|%d|%d|%s", agent, now, expiry, nonce)

	// Use wrong key to sign
	mac := hmac.New(sha256.New, []byte("wrong-secret"))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	ticketRaw := payload + "|" + sig
	ticket := base64.RawURLEncoding.EncodeToString([]byte(ticketRaw))

	req := httptest.NewRequest("GET", "/v1/studio/ticket/validate?ticket="+ticket, nil)
	w := httptest.NewRecorder()

	p.handleStudioTicketValidate(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["valid"] != false {
		t.Errorf("Expected valid=false for tampered signature, got %v", resp)
	}
	if resp["error"] != "invalid signature" {
		t.Errorf("Expected error='invalid signature', got %v", resp["error"])
	}
}

func TestStudioTicketValidate_TamperedExpiry(t *testing.T) {
	studioToken := "test-studio-secret"
	p := &httpProxy{
		gatewayURL:  mustParseURL("http://localhost:8080"),
		studioToken: studioToken,
		sessionID:   "test-session",
		timeoutMs:   200,
		maxBytes:    1048576,
	}

	// Create a legitimately expired ticket, then try to tamper the expiry
	agent := "friday"
	now := time.Now().Unix() - 600
	expiry := now + 300 // This is expired
	nonce := "abcdef1234567890abcdef1234567890"
	payload := fmt.Sprintf("%s|%d|%d|%s", agent, now, expiry, nonce)

	mac := hmac.New(sha256.New, []byte(studioToken))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	// Tamper the expiry in the raw ticket (change to future)
	tamperedPayload := fmt.Sprintf("%s|%d|%d|%s", agent, now, time.Now().Unix()+9999, nonce)
	ticketRaw := tamperedPayload + "|" + sig
	ticket := base64.RawURLEncoding.EncodeToString([]byte(ticketRaw))

	req := httptest.NewRequest("GET", "/v1/studio/ticket/validate?ticket="+ticket, nil)
	w := httptest.NewRecorder()

	p.handleStudioTicketValidate(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["valid"] != false {
		t.Errorf("Tampered expiry should be caught by HMAC verification, got %v", resp)
	}
}

func TestStudioTicketValidate_MissingTicket(t *testing.T) {
	p := &httpProxy{
		gatewayURL:  mustParseURL("http://localhost:8080"),
		studioToken: "test-studio-secret",
		sessionID:   "test-session",
		timeoutMs:   200,
		maxBytes:    1048576,
	}

	req := httptest.NewRequest("GET", "/v1/studio/ticket/validate", nil)
	w := httptest.NewRecorder()

	p.handleStudioTicketValidate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing ticket, got %d", w.Code)
	}
}

// =============================================================================
// HIGH-10: Constant-time token comparison
// =============================================================================

func TestSecureTokenCompare(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"equal tokens", "Bearer abc123", "Bearer abc123", true},
		{"different tokens", "Bearer abc123", "Bearer xyz789", false},
		{"empty vs non-empty", "", "Bearer abc123", false},
		{"both empty", "", "", true},
		{"partial match", "Bearer abc12", "Bearer abc123", false},
		{"case sensitive", "Bearer ABC123", "Bearer abc123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secureTokenCompare(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("secureTokenCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// =============================================================================
// HIGH-8: generateAuthToken fail-closed (no weak fallback)
// =============================================================================

func TestGenerateAuthToken_ProducesStrongToken(t *testing.T) {
	token := generateAuthToken()

	// Should be exactly 48 hex chars (24 random bytes)
	if len(token) != 48 {
		t.Errorf("Expected 48-char token, got %d chars", len(token))
	}

	// Should be valid hex
	if _, err := hex.DecodeString(token); err != nil {
		t.Errorf("Token should be valid hex: %v", err)
	}

	// Should NOT start with "tok-" (the old weak fallback pattern)
	if strings.HasPrefix(token, "tok-") {
		t.Error("Token should not use weak timestamp-based fallback")
	}

	// Two tokens should never be the same
	token2 := generateAuthToken()
	if token == token2 {
		t.Error("Two generated tokens should not be identical")
	}
}

// =============================================================================
// Ensure unused import is referenced
// =============================================================================

var _ = url.URL{}
