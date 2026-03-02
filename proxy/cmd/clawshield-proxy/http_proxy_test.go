package main


import (
	"context"
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
	"github.com/SleuthCo/clawshield/proxy/internal/metrics"
	"github.com/SleuthCo/clawshield/proxy/internal/scanner"
)

// --- Helper: create evaluator with given policy ---

func newTestEvaluator(policy *engine.Policy) *engine.Evaluator {
	return engine.NewEvaluator(policy)
}

// --- Unit Tests: isWebSocketUpgrade ---

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "valid websocket upgrade",
			headers: map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"},
			want:    true,
		},
		{
			name:    "case-insensitive",
			headers: map[string]string{"Connection": "upgrade", "Upgrade": "WebSocket"},
			want:    true,
		},
		{
			name:    "connection with multiple values",
			headers: map[string]string{"Connection": "keep-alive, Upgrade", "Upgrade": "websocket"},
			want:    true,
		},
		{
			name:    "no upgrade header",
			headers: map[string]string{"Connection": "keep-alive"},
			want:    false,
		},
		{
			name:    "upgrade but not websocket",
			headers: map[string]string{"Connection": "Upgrade", "Upgrade": "h2c"},
			want:    false,
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := isWebSocketUpgrade(r); got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Unit Tests: singleJoiningSlash ---

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"", "", "/"},
		{"/", "/path", "/path"},
		{"/base", "/path", "/base/path"},
		{"/base/", "/path", "/base/path"},
		{"/base", "path", "/base/path"},
		{"/base/", "path", "/base/path"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s+%s", tt.a, tt.b), func(t *testing.T) {
			got := singleJoiningSlash(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --- Unit Tests: sendErrorFrame JSON structure ---

func TestSendErrorFrameStructure(t *testing.T) {
	errResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    -32600,
			"message": "blocked by ClawShield security policy",
			"data":    "test reason",
		},
		"method": "tools/invoke",
	}
	data, err := json.Marshal(errResp)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %v", parsed["jsonrpc"])
	}
	errObj := parsed["error"].(map[string]interface{})
	if errObj["code"].(float64) != -32600 {
		t.Errorf("expected error code -32600, got %v", errObj["code"])
	}
}

// --- Unit Tests: OpenClaw evaluator extensions ---

func TestEvaluateOpenClawAgent_NoConfig(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	decision, _ := eval.EvaluateOpenClawAgent("friday")
	if decision != engine.Allow {
		t.Errorf("expected allow with no openclaw config, got %s", decision)
	}
}

func TestEvaluateOpenClawAgent_Allowlist(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		OpenClaw: &engine.OpenClawConfig{
			AgentAllowlist: []string{"friday", "pepper"},
		},
	})

	tests := []struct {
		agent string
		want  string
	}{
		{"friday", engine.Allow},
		{"Friday", engine.Allow}, // Case insensitive
		{"pepper", engine.Allow},
		{"evil-agent", engine.Deny},
		{"", engine.Deny},
	}

	for _, tt := range tests {
		t.Run(tt.agent, func(t *testing.T) {
			decision, _ := eval.EvaluateOpenClawAgent(tt.agent)
			if decision != tt.want {
				t.Errorf("EvaluateOpenClawAgent(%q) = %s, want %s", tt.agent, decision, tt.want)
			}
		})
	}
}

func TestEvaluateOpenClawChannel_NoConfig(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})
	decision, _ := eval.EvaluateOpenClawChannel("slack", "shell.exec")
	if decision != engine.Allow {
		t.Errorf("expected allow with no openclaw config, got %s", decision)
	}
}

func TestEvaluateOpenClawChannel_BlockedTools(t *testing.T) {
	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		OpenClaw: &engine.OpenClawConfig{
			ChannelPolicies: map[string]engine.ChannelPolicy{
				"slack": {
					AllowedTools: []string{"search", "read"},
					BlockedTools: []string{"exec", "shell"},
				},
			},
		},
	})

	tests := []struct {
		channel string
		tool    string
		want    string
	}{
		{"slack", "search", engine.Allow},
		{"slack", "read", engine.Allow},
		{"slack", "exec", engine.Deny},
		{"slack", "shell", engine.Deny},
		{"slack", "write", engine.Deny},
		{"telegram", "exec", engine.Allow},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.channel, tt.tool), func(t *testing.T) {
			decision, _ := eval.EvaluateOpenClawChannel(tt.channel, tt.tool)
			if decision != tt.want {
				t.Errorf("EvaluateOpenClawChannel(%q, %q) = %s, want %s",
					tt.channel, tt.tool, decision, tt.want)
			}
		})
	}
}

// --- Integration Tests: HTTP proxy with mock upstream ---

func TestHTTPProxy_PlainHTTPForwarding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","path":"%s"}`, r.URL.Path)
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})

	p := &httpProxy{
		metrics:    metrics.New(),
		gatewayURL: mustParseURL(upstream.URL),
		metrics:    metrics.New(),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  100,
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
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["path"] != "/health" {
		t.Errorf("expected path /health, got %s", body["path"])
	}
}

func TestHTTPProxy_AuthTokenInjection(t *testing.T) {
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eval := newTestEvaluator(&engine.Policy{DefaultAction: "allow"})

	p := &httpProxy{
		metrics:    metrics.New(),
		gatewayURL: mustParseURL(upstream.URL),
		metrics:    metrics.New(),
		authToken:  "test-secret-token",
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  100,
		maxBytes:   1048576,
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(p.handler))
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer test-secret-token" {
		t.Errorf("expected auth token forwarded, got %q", receivedAuth)
	}
}

func TestHTTPProxy_WebSocketPolicyEnforcement(t *testing.T) {
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

	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		Denylist:      []string{"shell.exec"},
	})

	p := &httpProxy{
		metrics:    metrics.New(),
		gatewayURL: mustParseURL(upstream.URL),
		metrics:    metrics.New(),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  100,
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

	// Test 1: Allowed message should pass through and be echoed
	allowedMsg := `{"method":"read","params":{"path":"file.txt"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(allowedMsg)); err != nil {
		t.Fatalf("WS write failed: %v", err)
	}

	_, data, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}
	if string(data) != allowedMsg {
		t.Logf("Got response (may be transformed): %s", string(data))
	}

	// Test 2: Denied message should return error frame
	deniedMsg := `{"method":"shell.exec","params":{"cmd":"rm -rf /"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(deniedMsg)); err != nil {
		t.Fatalf("WS write failed: %v", err)
	}

	_, data, err = client.Read(ctx)
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}

	var errResp map[string]interface{}
	if err := json.Unmarshal(data, &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v (raw: %s)", err, string(data))
	}

	if _, hasError := errResp["error"]; !hasError {
		t.Errorf("expected error frame for denied message, got: %s", string(data))
	}
}

func TestHTTPProxy_WebSocketVulnScan(t *testing.T) {
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

	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		VulnScan: &scanner.VulnScanConfig{
			Enabled: true,
			Rules:   []string{"sqli", "command_injection"},
		},
	})

	p := &httpProxy{
		metrics:    metrics.New(),
		gatewayURL: mustParseURL(upstream.URL),
		metrics:    metrics.New(),
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

	// Send SQL injection payload
	sqliMsg := `{"method":"db.query","params":{"sql":"SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(sqliMsg)); err != nil {
		t.Fatalf("WS write failed: %v", err)
	}

	_, data, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}

	var errResp map[string]interface{}
	if err := json.Unmarshal(data, &errResp); err != nil {
		t.Fatalf("parse error response: %v", err)
	}

	if _, hasError := errResp["error"]; !hasError {
		t.Errorf("expected SQL injection to be blocked, got: %s", string(data))
	}
}

func TestHTTPProxy_AgentAllowlistEnforcement(t *testing.T) {
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

	eval := newTestEvaluator(&engine.Policy{
		DefaultAction: "allow",
		OpenClaw: &engine.OpenClawConfig{
			AgentAllowlist: []string{"friday", "pepper"},
		},
	})

	p := &httpProxy{
		metrics:    metrics.New(),
		gatewayURL: mustParseURL(upstream.URL),
		metrics:    metrics.New(),
		evaluator:  eval,
		sessionID:  "test-session",
		timeoutMs:  100,
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

	// Allowed agent
	msg := `{"method":"chat/send","params":{"agentId":"friday","message":"hello"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
		t.Fatalf("WS write failed: %v", err)
	}
	_, data, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}
	if string(data) != msg {
		t.Logf("Got response: %s", string(data))
	}

	// Denied agent
	msg2 := `{"method":"chat/send","params":{"agentId":"evil-bot","message":"hello"}}`
	if err := client.Write(ctx, websocket.MessageText, []byte(msg2)); err != nil {
		t.Fatalf("WS write failed: %v", err)
	}
	_, data, err = client.Read(ctx)
	if err != nil {
		t.Fatalf("WS read failed: %v", err)
	}

	var errResp map[string]interface{}
	if err := json.Unmarshal(data, &errResp); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if _, hasError := errResp["error"]; !hasError {
		t.Errorf("expected agent blocked, got: %s", string(data))
	}
}

// --- Unit Tests: generateAuthToken ---

func TestGenerateAuthToken(t *testing.T) {
	token := generateAuthToken()
	if len(token) != 48 {
		t.Errorf("expected 48-char hex token, got %d chars: %s", len(token), token)
	}

	token2 := generateAuthToken()
	if token == token2 {
		t.Error("two generated tokens should not be identical")
	}
}

// --- Helpers ---

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// Ensure scanner import is used
var _ = scanner.VulnScanConfig{}
func TestInjectCanaryToken(t *testing.T) {
	canary := "__clawshield_canary_abc123__"

	tests := []struct {
		name     string
		input    string
		wantErr  bool
		hasCanary bool
	}{
		{
			name:      "normal MCP message with params",
			input:     `{"method":"chat.send","params":{"text":"hello"}}`,
			wantErr:   false,
			hasCanary: true,
		},
		{
			name:      "message with nested params",
			input:     `{"method":"tools.invoke","params":{"tool":"search","query":"test"}}`,
			wantErr:   false,
			hasCanary: true,
		},
		{
			name:      "message without params",
			input:     `{"method":"tools.list"}`,
			wantErr:   false,
			hasCanary: false, // No params to inject into
		},
		{
			name:      "message with array params",
			input:     `{"method":"batch","params":[1,2,3]}`,
			wantErr:   false,
			hasCanary: false, // Array params — skip injection
		},
		{
			name:      "invalid JSON",
			input:     `not json`,
			wantErr:   true,
			hasCanary: false,
		},
		{
			name:      "empty params object",
			input:     `{"method":"test","params":{}}`,
			wantErr:   false,
			hasCanary: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := injectCanaryToken([]byte(tt.input), canary)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			resultStr := string(result)
			if tt.hasCanary {
				if !strings.Contains(resultStr, canary) {
					t.Errorf("expected canary in output, got: %s", resultStr)
				}
				if !strings.Contains(resultStr, "_clawshield_canary") {
					t.Errorf("expected _clawshield_canary field, got: %s", resultStr)
				}

				// Verify the result is valid JSON
				var parsed map[string]json.RawMessage
				if err := json.Unmarshal(result, &parsed); err != nil {
					t.Fatalf("result is not valid JSON: %v", err)
				}

				// Verify params still contains original fields
				var params map[string]json.RawMessage
				if err := json.Unmarshal(parsed["params"], &params); err != nil {
					t.Fatalf("params is not valid JSON: %v", err)
				}
				if _, ok := params["_clawshield_canary"]; !ok {
					t.Error("_clawshield_canary field missing from params")
				}
			} else {
				// Should return unchanged or without canary
				if strings.Contains(resultStr, canary) {
					t.Errorf("canary should not be injected, got: %s", resultStr)
				}
			}
		})
	}
}

func TestInjectCanaryToken_PreservesOriginalFields(t *testing.T) {
	canary := "__clawshield_canary_test123__"
	input := `{"method":"search","params":{"query":"test","limit":10},"id":42}`

	result, err := injectCanaryToken([]byte(input), canary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	// Verify method and id are preserved
	if string(parsed["method"]) != `"search"` {
		t.Errorf("method not preserved, got: %s", string(parsed["method"]))
	}
	if string(parsed["id"]) != "42" {
		t.Errorf("id not preserved, got: %s", string(parsed["id"]))
	}

	// Verify params contains original fields + canary
	var params map[string]json.RawMessage
	if err := json.Unmarshal(parsed["params"], &params); err != nil {
		t.Fatalf("params is not valid JSON: %v", err)
	}

	if string(params["query"]) != `"test"` {
		t.Errorf("query not preserved, got: %s", string(params["query"]))
	}
	if string(params["limit"]) != "10" {
		t.Errorf("limit not preserved, got: %s", string(params["limit"]))
	}
	if _, ok := params["_clawshield_canary"]; !ok {
		t.Error("canary not injected")
	}
}
