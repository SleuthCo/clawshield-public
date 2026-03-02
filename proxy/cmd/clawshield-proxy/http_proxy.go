package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/hashlined"
	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/SleuthCo/clawshield/proxy/internal/engine"
	"github.com/SleuthCo/clawshield/proxy/internal/metrics"
	"github.com/SleuthCo/clawshield/shared/bus"
	"github.com/SleuthCo/clawshield/shared/types"
)

// wsRateLimiter tracks WebSocket connection counts per source IP to prevent
// resource exhaustion attacks via rapid connection cycling.
type wsRateLimiter struct {
	mu       sync.Mutex
	counts   map[string]int
	maxConns int
}

func newWSRateLimiter(maxConnsPerIP int) *wsRateLimiter {
	if maxConnsPerIP <= 0 {
		maxConnsPerIP = 10
	}
	rl := &wsRateLimiter{
		counts:   make(map[string]int),
		maxConns: maxConnsPerIP,
	}
	// Periodic cleanup of stale entries every 60 seconds
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.mu.Lock()
			for k, v := range rl.counts {
				if v <= 0 {
					delete(rl.counts, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *wsRateLimiter) acquire(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.counts[ip] >= rl.maxConns {
		return false
	}
	rl.counts[ip]++
	return true
}

func (rl *wsRateLimiter) release(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.counts[ip]--
	if rl.counts[ip] <= 0 {
		delete(rl.counts, ip)
	}
}

// httpProxy runs ClawShield as an HTTP/WebSocket reverse proxy in front of
// an OpenClaw gateway (or any HTTP-based tool server).
type httpProxy struct {
	gatewayURL     *url.URL
	authToken      string
	studioToken    string // HMAC signing key for Studio tickets (same as STUDIO_ACCESS_TOKEN)
	evaluator      *engine.Evaluator
	auditWriter    *sqlite.Writer
	auditDB        *sql.DB
	sessionID      string
	timeoutMs      int
	maxBytes       int64
	standaloneMode bool
	startTime      time.Time
	controlUIDir   string
	metrics        *metrics.Collector
	eventBus       *bus.EventBus // Cross-layer event bus (nil if not configured)
	wsLimiter      *wsRateLimiter
}

// runHTTPProxy starts the HTTP reverse proxy mode.
func runHTTPProxy(cfg *engine.Policy, evaluator *engine.Evaluator, auditWriter *sqlite.Writer, auditDB *sql.DB,
	gatewayURL, authToken, studioToken, listenAddr string, sessionID string, standalone bool, controlUIDir string, eventBus *bus.EventBus) error {

	gw, err := url.Parse(gatewayURL)
	if err != nil {
		return fmt.Errorf("invalid --gateway-url: %w", err)
	}

	timeoutMs := 100
	if cfg.EvaluationTimeoutMs > 0 {
		timeoutMs = cfg.EvaluationTimeoutMs
	}
	maxBytes := cfg.MaxMessageBytes
	if maxBytes <= 0 {
		maxBytes = 1048576
	}

	p := &httpProxy{
		gatewayURL:     gw,
		authToken:      authToken,
		studioToken:    studioToken,
		evaluator:      evaluator,
		auditWriter:    auditWriter,
		auditDB:        auditDB,
		sessionID:      sessionID,
		timeoutMs:      timeoutMs,
		maxBytes:       maxBytes,
		standaloneMode: standalone,
		startTime:      time.Now(),
		controlUIDir:   controlUIDir,
		metrics:        metrics.New(),
		eventBus:       eventBus,
		wsLimiter:      newWSRateLimiter(10), // Max 10 concurrent WS connections per IP
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/audit", p.handleAuditAPI)          // M3: Audit query API
	mux.HandleFunc("/api/v1/status", p.handleStatusAPI)        // Status API (dashboard)
	mux.Handle("/metrics", p.metrics.Handler())                                // Prometheus metrics endpoint
	mux.HandleFunc("/v1/studio/ticket", p.handleStudioTicket)                  // Studio deep-link ticket generation
	mux.HandleFunc("/v1/studio/ticket/validate", p.handleStudioTicketValidate) // Studio ticket validation with expiry check

	if standalone {
		// Standalone mode: serve dashboard at root, branded Control UI skin
		mux.HandleFunc("/static/", p.serveStaticAsset) // Embedded static assets (logo, etc.)
		mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
		mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
		mux.HandleFunc("/favicon-32.png", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
		mux.HandleFunc("/control-ui/index.html", p.serveControlUISkin)
		if controlUIDir != "" {
			// Serve Control UI assets directly from local directory
			mux.HandleFunc("/control-ui/", p.serveControlUIAsset)
			log.Printf("Serving Control UI assets from %s", controlUIDir)
		} else {
			// Proxy Control UI assets to gateway, but intercept root to serve our skin
			mux.HandleFunc("/control-ui/", func(w http.ResponseWriter, r *http.Request) {
				// Bare /control-ui/ or /control-ui → serve our branded skin
				path := strings.TrimPrefix(r.URL.Path, "/control-ui")
				if path == "" || path == "/" {
					p.serveControlUISkin(w, r)
					return
				}
				// Serve favicons from embedded static assets (gateway SPA catch-all returns HTML for these)
				if strings.HasSuffix(path, "favicon.svg") || strings.HasSuffix(path, "favicon-32.png") || strings.HasSuffix(path, "favicon.ico") {
					// Rewrite to /static/ path and serve from embedded FS
					idx := strings.LastIndex(path, "favicon")
					r.URL.Path = "/static/" + path[idx:]
					p.serveStaticAsset(w, r)
					return
				}
				// Everything else (JS, CSS, assets) → proxy to OpenClaw
				p.handler(w, r)
			})
		}
		mux.HandleFunc("/", p.standaloneRootHandler)
		log.Println("Standalone mode enabled — dashboard at /")
	} else {
		mux.HandleFunc("/", p.handler)
	}

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("ClawShield HTTP proxy listening on %s → %s", listenAddr, gatewayURL)
	return server.ListenAndServe()
}

// standaloneRootHandler serves the dashboard at "/" and proxies everything else.
func (p *httpProxy) standaloneRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && !isWebSocketUpgrade(r) {
		p.serveDashboard(w, r)
		return
	}
	p.handler(w, r)
}

// handler dispatches to WebSocket or HTTP reverse proxy based on upgrade headers.
// SECURITY: Validates the Host header to prevent DNS rebinding attacks where a
// malicious website's DNS resolves to localhost, allowing browser-based SSRF.
func (p *httpProxy) handler(w http.ResponseWriter, r *http.Request) {
	// Host header validation — reject requests with unexpected Host values
	if !p.isValidHost(r.Host) {
		log.Printf("BLOCKED: invalid Host header %q from %s", r.Host, r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if isWebSocketUpgrade(r) {
		p.handleWebSocket(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// isValidHost checks if the Host header matches the expected proxy listen address.
// This prevents DNS rebinding attacks where an attacker's domain resolves to
// 127.0.0.1, allowing a malicious browser page to send requests to the proxy.
func (p *httpProxy) isValidHost(host string) bool {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // No port in Host header
	}

	// Allow localhost variants (the proxy always listens on loopback)
	allowedHosts := []string{"localhost", "127.0.0.1", "::1", ""}
	for _, allowed := range allowedHosts {
		if strings.EqualFold(h, allowed) {
			return true
		}
	}

	// Allow the gateway's own hostname (for reverse proxy setups)
	if p.gatewayURL != nil && strings.EqualFold(h, p.gatewayURL.Hostname()) {
		return true
	}

	return false
}

// handleHTTP forwards non-WebSocket requests via a standard reverse proxy.
// Applies request scanning, response scanning (M4), session isolation (M2), and audit correlation (M3).
func (p *httpProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// M3: Extract bridge headers for audit correlation
	correlationID := r.Header.Get("X-Correlation-ID")
	classification := r.Header.Get("X-Data-Classification")
	sessionMode := r.Header.Get("X-Session-Mode")

	// Layer 3: Extract agent identity + scope headers
	agentName := r.Header.Get("X-Agent-Name")
	agentScopeRaw := r.Header.Get("X-Agent-Scope")
	var agentScopes []string
	if agentScopeRaw != "" {
		var scopes []struct {
			Platform string `json:"platform"`
		}
		if json.Unmarshal([]byte(agentScopeRaw), &scopes) == nil {
			for _, s := range scopes {
				agentScopes = append(agentScopes, s.Platform)
			}
		}
	}

	// Determine source for audit
	source := "direct"
	if correlationID != "" {
		source = "forge-bridge"
	}

	// SECURITY: Scan HTTP request bodies through the policy engine before proxying.
	// This ensures the same protections applied to WebSocket messages also apply to
	// HTTP REST API requests (e.g., POST /v1/chat/completions).
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, p.maxBytes+1))
		r.Body.Close()
		if err != nil {
			log.Printf("HTTP request body read error: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Enforce max message size
		if int64(len(bodyBytes)) > p.maxBytes {
			log.Printf("BLOCKED: HTTP request body exceeds max size (%d > %d)", len(bodyBytes), p.maxBytes)
			p.logBridgeDecision(r.Method+" "+r.URL.Path, fmt.Sprintf("body_size=%d", len(bodyBytes)),
				"deny", "request body exceeds max size", correlationID, classification, source, agentName)
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}

		// Run policy evaluation on JSON request bodies
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/json") && len(bodyBytes) > 0 {
			evalCtx, evalCancel := context.WithTimeout(r.Context(), time.Duration(p.timeoutMs)*time.Millisecond)
			decision, reason, details := p.evaluator.EvaluateWithDetails(evalCtx, string(bodyBytes))
			evalCancel()

			p.logBridgeDecisionWithDetails(r.Method+" "+r.URL.Path, string(bodyBytes), decision, reason,
				correlationID, classification, source, agentName, details)

			if decision == engine.Deny {
				log.Printf("BLOCKED HTTP REQUEST: %s %s reason=%s agent=%s", r.Method, r.URL.Path, reason, agentName)
				http.Error(w, `{"error":{"message":"blocked by security policy","code":-32600}}`, http.StatusForbidden)
				return
			}
		}

		// Restore the body for the proxy to forward
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = p.gatewayURL.Scheme
			req.URL.Host = p.gatewayURL.Host
			req.URL.Path = singleJoiningSlash(p.gatewayURL.Path, req.URL.Path)
			req.Host = p.gatewayURL.Host
			// Inject auth token for upstream gateway
			if p.authToken != "" {
				req.Header.Set("Authorization", "Bearer "+p.authToken)
			}
			// Remove bridge headers — don't leak to upstream
			req.Header.Del("X-Correlation-ID")
			req.Header.Del("X-Data-Classification")
			req.Header.Del("X-Session-Mode")
			req.Header.Del("X-Agent-Name")
			req.Header.Del("X-Agent-Scope")

			// M2: Rewrite user field for ephemeral sessions (defense-in-depth)
			if sessionMode == "ephemeral" && req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err == nil {
					var bodyMap map[string]interface{}
					if json.Unmarshal(bodyBytes, &bodyMap) == nil {
						// Replace user with random UUID
						bodyMap["user"] = generateAuthToken()[:32]
						bodyMap["store"] = false
						rewritten, err := json.Marshal(bodyMap)
						if err == nil {
							req.Body = io.NopCloser(bytes.NewReader(rewritten))
							req.ContentLength = int64(len(rewritten))
						}
					}
				}
			}
		},
		// M4: Scan HTTP responses before returning to client
		ModifyResponse: func(resp *http.Response) error {
			// Only scan JSON responses from chat completions
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "application/json") || resp.StatusCode != 200 {
				return nil
			}

			// SECURITY: Limit response body read to prevent unbounded memory allocation
			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, p.maxBytes))
			resp.Body.Close()
			if err != nil {
				resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				return nil
			}

			// Extract response content for scanning
			var chatResp struct {
				Choices []struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				} `json:"choices"`
			}
			if json.Unmarshal(bodyBytes, &chatResp) == nil && len(chatResp.Choices) > 0 {
				content := chatResp.Choices[0].Message.Content

				// Run injection + malware scanning on response
				respBlocked := false
				respReason := "response clean"
				scannerType := ""

				evalCtx, evalCancel := context.WithTimeout(r.Context(), time.Duration(p.timeoutMs)*time.Millisecond)
				respResult := p.evaluator.EvaluateResponse(evalCtx, "chat/completions", content)
				evalCancel()

				if respResult.Decision == engine.Deny {
					respBlocked = true
					respReason = respResult.Reason
					if strings.HasPrefix(respResult.Reason, "prompt_injection") {
						scannerType = "injection"
					} else if strings.HasPrefix(respResult.Reason, "malware") {
						scannerType = "malware"
					}
				} else if respResult.WasRedacted {
					content = respResult.RedactedBody
					respReason = respResult.Reason
					scannerType = "redaction"

					// Re-marshal the response with redacted content so the
					// HTTP client receives the sanitized version, not the original.
					chatResp.Choices[0].Message.Content = content
					redactedBytes, err := json.Marshal(chatResp)
					if err == nil {
						bodyBytes = redactedBytes
					} else {
						log.Printf("WARNING: failed to re-marshal redacted response: %v", err)
					}
				}

				// Layer 3: Agent scope validation
				if !respBlocked && len(agentScopes) > 0 {
					scopeD, scopeR := p.evaluator.EvaluateAgentScope(content, agentScopes)
					if scopeD == engine.Deny {
						respBlocked = true
						respReason = scopeR
						scannerType = "scope"
					}
				}

				// Audit log the response scan (enriched with agent name)
				if p.auditWriter != nil {
					dec := types.Decision{
						Timestamp:       time.Now(),
						SessionID:       p.sessionID,
						Tool:            "chat/completions_response",
						ArgumentsHash:   fmt.Sprintf("http_response_size=%d", len(bodyBytes)),
						Decision:        respResult.Decision,
						Reason:          respReason,
						PolicyVersion:   "1.0",
						ScannerType:     scannerType,
						CorrelationID:   correlationID,
						Classification:  classification,
						Source:          source,
						ResponseBlocked: respBlocked,
						AgentName:       agentName,
						Details:         respResult.Details,
					}
					if err := p.auditWriter.Write(&dec); err != nil {
						log.Printf("SECURITY WARNING: audit write failed for HTTP response scan: %v", err)
					}
				}

				if respBlocked {
					log.Printf("BLOCKED HTTP RESPONSE: reason=%s correlationId=%s agent=%s", respReason, correlationID, agentName)
					blockedResp := map[string]interface{}{
						"error": map[string]interface{}{
							"message": "blocked by security policy",
							"code":    -32600,
						},
					}
					blocked, _ := json.Marshal(blockedResp)
					resp.Body = io.NopCloser(bytes.NewReader(blocked))
					resp.ContentLength = int64(len(blocked))
					resp.Header.Set("Content-Length", strconv.Itoa(len(blocked)))
					return nil
				}
			}

			// Response clean (or redacted) — restore body with potentially modified bytes
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			resp.ContentLength = int64(len(bodyBytes))
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("HTTP proxy error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Audit log the HTTP request with bridge metadata
	p.logBridgeDecision(r.Method+" "+r.URL.Path, "http_request", "allow", "http pass-through",
		correlationID, classification, source, agentName)

	proxy.ServeHTTP(w, r)
}

// handleWebSocket upgrades the client connection and the upstream connection,
// then bidirectionally proxies messages with policy evaluation on each frame.
func (p *httpProxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Rate-limit WebSocket connections per source IP to prevent
	// resource exhaustion via rapid connection cycling.
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if p.wsLimiter != nil && !p.wsLimiter.acquire(clientIP) {
		log.Printf("BLOCKED: WebSocket rate limit exceeded for IP %s", clientIP)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	if p.wsLimiter != nil {
		defer p.wsLimiter.release(clientIP)
	}

	// Build upstream URL
	upstreamURL := *p.gatewayURL
	if upstreamURL.Scheme == "https" {
		upstreamURL.Scheme = "wss"
	} else {
		upstreamURL.Scheme = "ws"
	}
	upstreamURL.Path = singleJoiningSlash(upstreamURL.Path, r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery

	// Build upstream headers
	upstreamHeaders := http.Header{}
	if p.authToken != "" {
		upstreamHeaders.Set("Authorization", "Bearer "+p.authToken)
	}
	// Forward relevant headers, rewriting Origin to match the gateway
	for _, h := range []string{"Cookie", "User-Agent"} {
		if v := r.Header.Get(h); v != "" {
			upstreamHeaders.Set(h, v)
		}
	}
	// Rewrite Origin to match gateway URL so the gateway doesn't reject it
	upstreamHeaders.Set("Origin", p.gatewayURL.Scheme+"://"+p.gatewayURL.Host)

	// Connect to upstream gateway
	ctx := r.Context()
	upstreamConn, _, err := websocket.Dial(ctx, upstreamURL.String(), &websocket.DialOptions{
		HTTPHeader: upstreamHeaders,
	})
	if err != nil {
		log.Printf("Failed to connect to upstream WebSocket: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close(websocket.StatusNormalClosure, "proxy shutdown")
	upstreamConn.SetReadLimit(p.maxBytes)

	// Accept client WebSocket upgrade
	clientConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow any origin (policy handles security)
	})
	if err != nil {
		log.Printf("Failed to accept WebSocket upgrade: %v", err)
		return
	}
	defer clientConn.Close(websocket.StatusNormalClosure, "proxy shutdown")
	clientConn.SetReadLimit(p.maxBytes)

	// Bidirectional proxy with policy evaluation
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Upstream (request path)
	go func() {
		defer wg.Done()
		p.proxyClientToUpstream(ctx, clientConn, upstreamConn)
	}()

	// Upstream → Client (response path)
	go func() {
		defer wg.Done()
		p.proxyUpstreamToClient(ctx, upstreamConn, clientConn)
	}()

	wg.Wait()
}

// proxyClientToUpstream reads from the client, evaluates each message, and forwards allowed ones.
func (p *httpProxy) proxyClientToUpstream(ctx context.Context, client, upstream *websocket.Conn) {
	for {
		msgType, data, err := client.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) != -1 || ctx.Err() != nil {
				return // Normal close or context cancelled
			}
			log.Printf("Client WS read error: %v", err)
			return
		}

		if msgType == websocket.MessageBinary {
			// SECURITY: Block binary frames — they could carry malicious payloads
			// that bypass text-based policy evaluation. Binary WebSocket frames are
			// not expected in the JSON-RPC protocol used by OpenClaw.
			log.Printf("BLOCKED: binary WebSocket frame rejected (size=%d bytes) — binary frames are not permitted", len(data))
			p.logDecision("<binary_frame>", fmt.Sprintf("binary_frame_size=%d", len(data)), "deny", "binary WebSocket frames are not permitted")
			p.sendErrorFrame(ctx, client, "", "binary WebSocket frames are not permitted by security policy")
			continue
		}

		// Text frame: evaluate as JSON
		message := string(data)

		// Size check
		if int64(len(data)) > p.maxBytes {
			log.Printf("BLOCKED: WebSocket message exceeds max size (%d > %d)", len(data), p.maxBytes)
			p.sendErrorFrame(ctx, client, "", "message too large")
			continue
		}

		// Extract method and agent info for OpenClaw-specific checks
		var rpc struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Type   string          `json:"type"`
			Event  string          `json:"event"`
		}
		_ = json.Unmarshal(data, &rpc)

		// Pass through OpenClaw protocol messages (connection handshake)
		// Events use {type:"event", event:"connect.*"} format
		// Connect request uses {type:"req", method:"connect"} format
		isProtocol := (rpc.Type == "event" && strings.HasPrefix(rpc.Event, "connect.")) ||
			(rpc.Type == "req" && rpc.Method == "connect") ||
			(rpc.Type == "res")
		if isProtocol {
			label := rpc.Event
			if label == "" {
				label = rpc.Method
			}
			if label == "" {
				label = "response"
			}
			p.logDecision("protocol:"+label, "", "allow", "protocol handshake")
			log.Printf("ALLOWED: protocol %s=%s", rpc.Type, label)

			// In standalone mode, inject auth token into connect request
			// so the Control UI doesn't need to know the gateway credentials
			outData := data
			if p.standaloneMode && p.authToken != "" && rpc.Type == "req" && rpc.Method == "connect" {
				outData = p.injectConnectAuth(data)
			}

			if err := upstream.Write(ctx, msgType, outData); err != nil {
				log.Printf("Upstream WS write error: %v", err)
				return
			}
			continue
		}

		// OpenClaw agent allowlist check
		if rpc.Method != "" {
			var params struct {
				AgentID string `json:"agentId"`
				Channel string `json:"channel"`
				Tool    string `json:"tool"`
			}
			_ = json.Unmarshal(rpc.Params, &params)

			if params.AgentID != "" {
				decision, reason := p.evaluator.EvaluateOpenClawAgent(params.AgentID)
				if decision == engine.Deny {
					log.Printf("BLOCKED: agent=%s reason=%s", params.AgentID, reason)
					p.logDecision(rpc.Method, "agent:"+params.AgentID, "deny", reason)
					p.sendErrorFrame(ctx, client, rpc.Method, reason)
					continue
				}
			}

			// Channel-specific tool check
			if params.Channel != "" && params.Tool != "" {
				decision, reason := p.evaluator.EvaluateOpenClawChannel(params.Channel, params.Tool)
				if decision == engine.Deny {
					log.Printf("BLOCKED: channel=%s tool=%s reason=%s", params.Channel, params.Tool, reason)
					p.logDecision(rpc.Method, "channel:"+params.Channel+"/"+params.Tool, "deny", reason)
					p.sendErrorFrame(ctx, client, rpc.Method, reason)
					continue
				}
			}
		}

		// Full evaluator pipeline (denylist, allowlist, arg filters, vuln scan, injection scan)
		evalStart := time.Now()
		evalCtx, evalCancel := context.WithTimeout(ctx, time.Duration(p.timeoutMs)*time.Millisecond)
		decision, reason, details := p.evaluator.EvaluateWithDetails(evalCtx, message)
		evalCancel()

		method := rpc.Method
		if method == "" {
			method = "<unknown>"
		}

		// Audit log
		p.logDecisionWithDetails(method, string(rpc.Params), decision, reason, details)

		p.metrics.RecordRequest()
		p.metrics.RecordEvaluationLatency(time.Since(evalStart))

		if decision == engine.Deny {
			log.Printf("BLOCKED: method=%s reason=%s", method, reason)
			p.metrics.RecordDeny(method, reason)
			// Publish cross-layer event for blocked requests
			evtType, sev := classifyDenyReason(reason)
			p.publishSecurityEvent(evtType, sev, method, reason)
			p.sendErrorFrame(ctx, client, method, reason)
			continue
		}

		p.metrics.RecordAllow()
		log.Printf("ALLOWED: method=%s", method)

		// Inject canary token into outbound params if enabled.
		// If the canary leaks back in a response, the injection scanner's
		// Tier 3 check detects cross-tool data exfiltration.
		outData := data
		if injector := p.evaluator.InjectionDetector(); injector != nil {
			if canary := injector.GetCanaryToken(); canary != "" {
				if injected, err := injectCanaryToken(data, canary); err == nil {
					outData = injected
				}
			}
		}

		if err := upstream.Write(ctx, msgType, outData); err != nil {
			log.Printf("Upstream WS write error: %v", err)
			return
		}
	}
}

// proxyUpstreamToClient reads from upstream, scans responses, and forwards clean ones.
func (p *httpProxy) proxyUpstreamToClient(ctx context.Context, upstream, client *websocket.Conn) {
	for {
		msgType, data, err := upstream.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) != -1 || ctx.Err() != nil {
				return
			}
			log.Printf("Upstream WS read error: %v", err)
			return
		}

		if msgType == websocket.MessageBinary {
			// SECURITY: Block binary response frames — they could carry malicious
			// payloads that bypass text-based response scanning.
			log.Printf("BLOCKED: binary WebSocket response frame rejected (size=%d bytes)", len(data))
			if p.auditWriter != nil {
				auditDec := types.Decision{
					Timestamp:     time.Now(),
					SessionID:     p.sessionID,
					Tool:          "<binary_frame_response>",
					ArgumentsHash: fmt.Sprintf("binary_response_size=%d", len(data)),
					Decision:      "deny",
					Reason:        "binary WebSocket frames are not permitted",
					PolicyVersion: "1.0",
				}
				_ = p.auditWriter.Write(&auditDec)
			}
			continue
		}

		// Response scanning
		message := string(data)
		var rpc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(data, &rpc)
		respMethod := rpc.Method
		if respMethod == "" {
			respMethod = "<response>"
		}

		respDecision := "allow"
		respReason := "response clean"
		scannerType := ""
		var respResult engine.ResponseResult
		hasRespResult := false

		if p.evaluator.InjectionDetector() != nil || p.evaluator.MalwareScanner() != nil || p.evaluator.SecretsScanner() != nil || p.evaluator.PIIScanner() != nil {
			p.metrics.RecordResponseScanned()
			evalCtx, evalCancel := context.WithTimeout(ctx, time.Duration(p.timeoutMs)*time.Millisecond)
			respResult = p.evaluator.EvaluateResponse(evalCtx, respMethod, message)
			hasRespResult = true
			evalCancel()
			respDecision = respResult.Decision
			respReason = respResult.Reason
			if respResult.Decision == engine.Deny {
				p.metrics.RecordResponseBlocked()
				if len(respResult.Reason) > 0 {
					if respResult.Reason[0] == 'p' {
						scannerType = "injection"
						p.metrics.RecordInjectionBlocked()
					} else if respResult.Reason[0] == 'm' {
						scannerType = "malware"
						p.metrics.RecordMalwareBlocked()
					} else if respResult.Reason[0] == 's' {
						scannerType = "secrets"
						p.metrics.RecordSecretsBlocked()
					}
				}
			} else if respResult.WasRedacted {
				p.metrics.RecordResponseRedacted()
				// Replace the response data with the redacted version
				message = respResult.RedactedBody
				data = []byte(respResult.RedactedBody)
				scannerType = "redaction"
				log.Printf("REDACTED RESPONSE: method=%s reason=%s", respMethod, respResult.Reason)
			}
		}

		// Audit log response
		if p.auditWriter != nil {
			auditDec := types.Decision{
				Timestamp:     time.Now(),
				SessionID:     p.sessionID,
				Tool:          respMethod,
				ArgumentsHash: fmt.Sprintf("ws_response_size=%d", len(data)),
				Decision:      respDecision,
				Reason:        respReason,
				PolicyVersion: "1.0",
				ScannerType:   scannerType,
			}
			if hasRespResult {
				auditDec.Details = respResult.Details
			}
			if err := p.auditWriter.Write(&auditDec); err != nil {
				log.Printf("SECURITY WARNING: audit write failed for WS response: %v", err)
			}
		}

		if respDecision == engine.Deny {
			log.Printf("BLOCKED RESPONSE: method=%s reason=%s", respMethod, respReason)
			// Publish cross-layer event for blocked responses
			evtType, sev := classifyDenyReason(respReason)
			p.publishSecurityEvent(evtType, sev, respMethod, respReason)
			p.sendErrorFrame(ctx, client, respMethod, "response blocked by security policy")
			continue
		}

		if err := client.Write(ctx, msgType, data); err != nil {
			log.Printf("Client WS write error: %v", err)
			return
		}
	}
}

// injectCanaryToken adds a hidden canary token field into the params of an
// outbound MCP JSON-RPC message. The canary is injected as a
// "_clawshield_canary" field in the params object. If the canary later
// appears in a response from a different tool, it indicates cross-tool
// data exfiltration (a sign of prompt injection).
//
// The function is a no-op if the message has no params object.
func injectCanaryToken(data []byte, canary string) ([]byte, error) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}

	paramsRaw, ok := msg["params"]
	if !ok || len(paramsRaw) == 0 || paramsRaw[0] != '{' {
		// No params or params is not an object — skip injection
		return data, nil
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return nil, err
	}

	// Inject the canary as a hidden metadata field
	canaryJSON, _ := json.Marshal(canary)
	params["_clawshield_canary"] = canaryJSON

	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	msg["params"] = newParams
	return json.Marshal(msg)
}

// classifyDenyReason maps a deny reason string to an event type and severity
// for cross-layer event publishing.
func classifyDenyReason(reason string) (types.EventType, types.Severity) {
	switch {
	case strings.HasPrefix(reason, "prompt_injection"):
		return types.EventInjectionBlocked, types.SeverityHigh
	case strings.HasPrefix(reason, "malware_scan"):
		return types.EventMalwareBlocked, types.SeverityCritical
	case strings.HasPrefix(reason, "vuln_scan"):
		return types.EventVulnBlocked, types.SeverityHigh
	case strings.HasPrefix(reason, "sensitive data"):
		return types.EventArgFilterMatch, types.SeverityMedium
	case strings.HasPrefix(reason, "cross_scope"):
		return types.EventPolicyDeny, types.SeverityHigh
	default:
		return types.EventPolicyDeny, types.SeverityLow
	}
}

// injectConnectAuth modifies a WebSocket connect message to include the gateway auth token.
// This allows standalone mode to transparently authenticate the Control UI without
// the user needing to know or enter the gateway token.
func (p *httpProxy) injectConnectAuth(data []byte) []byte {
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return data
	}

	params, _ := msg["params"].(map[string]interface{})
	if params == nil {
		params = map[string]interface{}{}
		msg["params"] = params
	}

	auth, _ := params["auth"].(map[string]interface{})
	if auth == nil {
		auth = map[string]interface{}{}
		params["auth"] = auth
	}

	// Inject the gateway token
	auth["token"] = p.authToken

	modified, err := json.Marshal(msg)
	if err != nil {
		return data
	}
	log.Printf("Injected auth token into WS connect message")
	return modified
}

// logDecision writes an audit entry for a request evaluation.
func (p *httpProxy) logDecision(method, params, decision, reason string) {
	if p.auditWriter == nil {
		return
	}
	argsHash := params
	if h, err := hashlined.HashArguments(params); err == nil {
		argsHash = h
	}
	scanType := ""
	if decision == engine.Deny && len(reason) > 0 {
		if strings.HasPrefix(reason, "vuln_scan:") {
			scanType = "vuln"
		} else if strings.HasPrefix(reason, "prompt_injection:") {
			scanType = "injection"
		}
	}
	auditDec := types.Decision{
		Timestamp:     time.Now(),
		SessionID:     p.sessionID,
		Tool:          method,
		ArgumentsHash: argsHash,
		Decision:      decision,
		Reason:        reason,
		PolicyVersion: "1.0",
		ScannerType:   scanType,
	}
	if err := p.auditWriter.Write(&auditDec); err != nil {
		log.Printf("Audit write error: %v", err)
	}
}

// sendErrorFrame sends a JSON-RPC error frame back to the client.
// SECURITY: The detailed deny reason is logged server-side but NOT sent to
// the client — exposing policy internals (e.g. "tool not in allowlist",
// "regex matched /etc/passwd") enables reconnaissance attacks.
func (p *httpProxy) sendErrorFrame(ctx context.Context, conn *websocket.Conn, method, reason string) {
	// Log the detailed reason server-side for debugging/audit
	log.Printf("DENY DETAIL: method=%s reason=%s", method, reason)

	errResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    -32600,
			"message": "blocked by security policy",
		},
	}
	if method != "" {
		errResp["method"] = method
	}
	data, err := json.Marshal(errResp)
	if err != nil {
		return
	}
	_ = conn.Write(ctx, websocket.MessageText, data)
}

// publishSecurityEvent sends a security event to the cross-layer event bus.
// This enables other layers (firewall, eBPF monitor) to react to proxy-level detections.
func (p *httpProxy) publishSecurityEvent(eventType types.EventType, severity types.Severity, tool, reason string) {
	if p.eventBus == nil {
		return
	}
	p.eventBus.Publish(&types.SecurityEvent{
		EventType: eventType,
		Severity:  severity,
		Source:    types.SourceProxy,
		Timestamp: time.Now(),
		SessionID: p.sessionID,
		Tool:      tool,
		Reason:    reason,
	})
}

// logBridgeDecision writes an audit entry with bridge-specific metadata (M3).
func (p *httpProxy) logBridgeDecision(method, params, decision, reason, correlationID, classification, source, agentName string) {
	if p.auditWriter == nil {
		return
	}
	argsHash := params
	if h, err := hashlined.HashArguments(params); err == nil {
		argsHash = h
	}
	scanType := ""
	if decision == engine.Deny && len(reason) > 0 {
		if strings.HasPrefix(reason, "vuln_scan:") {
			scanType = "vuln"
		} else if strings.HasPrefix(reason, "prompt_injection:") {
			scanType = "injection"
		}
	}
	dec := types.Decision{
		Timestamp:      time.Now(),
		SessionID:      p.sessionID,
		Tool:           method,
		ArgumentsHash:  argsHash,
		Decision:       decision,
		Reason:         reason,
		PolicyVersion:  "1.0",
		ScannerType:    scanType,
		CorrelationID:  correlationID,
		Classification: classification,
		Source:         source,
		AgentName:      agentName,
	}
	if err := p.auditWriter.Write(&dec); err != nil {
		log.Printf("Audit write error: %v", err)
	}
}

// logDecisionWithDetails writes an audit entry for a request evaluation with details.
func (p *httpProxy) logDecisionWithDetails(method, params, decision, reason string, details *types.DecisionDetail) {
	if p.auditWriter == nil {
		return
	}
	argsHash := params
	if h, err := hashlined.HashArguments(params); err == nil {
		argsHash = h
	}
	scanType := ""
	if decision == engine.Deny && len(reason) > 0 {
		if strings.HasPrefix(reason, "vuln_scan:") {
			scanType = "vuln"
		} else if strings.HasPrefix(reason, "prompt_injection:") {
			scanType = "injection"
		}
	}
	auditDec := types.Decision{
		Timestamp:     time.Now(),
		SessionID:     p.sessionID,
		Tool:          method,
		ArgumentsHash: argsHash,
		Decision:      decision,
		Reason:        reason,
		PolicyVersion: "1.0",
		ScannerType:   scanType,
		Details:       details,
	}
	if err := p.auditWriter.Write(&auditDec); err != nil {
		log.Printf("Audit write error: %v", err)
	}
}

// logBridgeDecisionWithDetails writes an audit entry with bridge-specific metadata and details.
func (p *httpProxy) logBridgeDecisionWithDetails(method, params, decision, reason, correlationID, classification, source, agentName string, details *types.DecisionDetail) {
	if p.auditWriter == nil {
		return
	}
	argsHash := params
	if h, err := hashlined.HashArguments(params); err == nil {
		argsHash = h
	}
	scanType := ""
	if decision == engine.Deny && len(reason) > 0 {
		if strings.HasPrefix(reason, "vuln_scan:") {
			scanType = "vuln"
		} else if strings.HasPrefix(reason, "prompt_injection:") {
			scanType = "injection"
		}
	}
	dec := types.Decision{
		Timestamp:      time.Now(),
		SessionID:      p.sessionID,
		Tool:           method,
		ArgumentsHash:  argsHash,
		Decision:       decision,
		Reason:         reason,
		PolicyVersion:  "1.0",
		ScannerType:    scanType,
		CorrelationID:  correlationID,
		Classification: classification,
		Source:         source,
		AgentName:      agentName,
		Details:        details,
	}
	if err := p.auditWriter.Write(&dec); err != nil {
		log.Printf("Audit write error: %v", err)
	}
}

// handleStudioTicket generates an HMAC-signed, time-limited ticket for Studio deep-link access.
// POST /v1/studio/ticket {"agent": "friday", "context": "optional message", "correlationId": "uuid"}
func (p *httpProxy) handleStudioTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Authenticate with constant-time comparison to prevent timing attacks
	authHeader := r.Header.Get("Authorization")
	if p.authToken != "" && !secureTokenCompare(authHeader, "Bearer "+p.authToken) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if p.studioToken == "" {
		http.Error(w, `{"error":"Studio token not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Parse request body
	var req struct {
		Agent         string `json:"agent"`
		Context       string `json:"context"`
		CorrelationID string `json:"correlationId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	allowedAgents := map[string]bool{
		"friday": true, "nimbus": true, "sentinel": true, "pepper": true, "coda": true,
	}
	agent := strings.ToLower(strings.TrimSpace(req.Agent))
	if agent == "" || !allowedAgents[agent] {
		http.Error(w, `{"error":"invalid agent name"}`, http.StatusBadRequest)
		return
	}

	// SECURITY: Generate ticket with explicit expiry: agent|timestamp|expiry|nonce
	// The expiry is embedded in the signed payload so it cannot be tampered with.
	const ticketTTLSeconds = 300 // 5 minutes
	now := time.Now().Unix()
	expiry := now + ticketTTLSeconds
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	nonceHex := hex.EncodeToString(nonce)
	payload := fmt.Sprintf("%s|%d|%d|%s", agent, now, expiry, nonceHex)

	// HMAC-SHA256 sign
	mac := hmac.New(sha256.New, []byte(p.studioToken))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	// Encode ticket as base64url(payload|signature)
	ticketRaw := payload + "|" + sig
	ticket := base64.RawURLEncoding.EncodeToString([]byte(ticketRaw))

	studioBase := os.Getenv("CLAWSHIELD_STUDIO_URL")
	if studioBase == "" {
		studioBase = "https://studio.example.com"
	}
	studioURL := fmt.Sprintf("%s/?ticket=%s&agent=%s", studioBase, ticket, agent)

	// Audit log
	p.logBridgeDecision("studio/ticket", fmt.Sprintf("agent=%s", agent), "allow", "studio ticket generated",
		req.CorrelationID, "", "forge-bridge", agent)

	log.Printf("STUDIO TICKET: agent=%s correlationId=%s expiresIn=%ds", agent, req.CorrelationID, ticketTTLSeconds)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":       studioURL,
		"agent":     agent,
		"expiresIn": ticketTTLSeconds,
	})
}

// validateStudioTicket validates an HMAC-signed Studio ticket, checking signature
// integrity and expiry. Returns the agent name if valid, or an error.
// GET /v1/studio/ticket/validate?ticket=<base64url>
func (p *httpProxy) handleStudioTicketValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.studioToken == "" {
		http.Error(w, `{"error":"Studio token not configured"}`, http.StatusServiceUnavailable)
		return
	}

	ticketB64 := r.URL.Query().Get("ticket")
	if ticketB64 == "" {
		http.Error(w, `{"valid":false,"error":"missing ticket parameter"}`, http.StatusBadRequest)
		return
	}

	ticketBytes, err := base64.RawURLEncoding.DecodeString(ticketB64)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "error": "invalid ticket encoding"})
		return
	}

	// Ticket format: agent|timestamp|expiry|nonce|signature
	parts := strings.SplitN(string(ticketBytes), "|", 5)
	if len(parts) != 5 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "error": "invalid ticket format"})
		return
	}

	agent := parts[0]
	// parts[1] = issued timestamp (informational)
	expiryStr := parts[2]
	// parts[3] = nonce
	providedSig := parts[4]

	// Verify HMAC signature over payload (everything before the last |)
	payloadEnd := strings.LastIndex(string(ticketBytes), "|")
	payload := string(ticketBytes)[:payloadEnd]

	mac := hmac.New(sha256.New, []byte(p.studioToken))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !secureTokenCompare(providedSig, expectedSig) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "error": "invalid signature"})
		return
	}

	// SECURITY: Check expiry — the expiry timestamp is embedded in the signed payload
	// so it cannot be tampered with after HMAC verification passes.
	expiryUnix, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil || time.Now().Unix() > expiryUnix {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "error": "ticket expired"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"agent": agent,
	})
}

// handleAuditAPI serves the audit query endpoint (M3).
// GET /api/v1/audit?since=<ISO>&limit=<int>&source=forge-bridge
func (p *httpProxy) handleAuditAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Authenticate audit API requests even in standalone mode.
	// In standalone mode, allow requests from loopback addresses (dashboard)
	// but require auth from all other sources to prevent information disclosure.
	if p.standaloneMode {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host == "" {
			host = r.RemoteAddr
		}
		isLoopback := host == "127.0.0.1" || host == "::1" || host == "localhost"
		if !isLoopback {
			authHeader := r.Header.Get("Authorization")
			if p.authToken != "" && !secureTokenCompare(authHeader, "Bearer "+p.authToken) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
	} else {
		authHeader := r.Header.Get("Authorization")
		if p.authToken != "" && !secureTokenCompare(authHeader, "Bearer "+p.authToken) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if p.auditDB == nil {
		http.Error(w, "Audit database not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query params
	since := r.URL.Query().Get("since")
	limitStr := r.URL.Query().Get("limit")
	source := r.URL.Query().Get("source")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	query := `SELECT decision_id, timestamp, session_id, tool, arguments_hash, decision, reason,
		COALESCE(policy_version, '') as policy_version, COALESCE(scanner_type, '') as scanner_type,
		COALESCE(correlation_id, '') as correlation_id, COALESCE(classification, '') as classification,
		COALESCE(source, '') as source, COALESCE(response_blocked, 0) as response_blocked
		FROM decisions WHERE 1=1`
	args := []interface{}{}

	if since != "" {
		query += " AND timestamp >= ?"
		args = append(args, since)
	}
	if source != "" {
		query += " AND source = ?"
		args = append(args, source)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := p.auditDB.Query(query, args...)
	if err != nil {
		log.Printf("Audit query error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type auditEntry struct {
		DecisionID      int64  `json:"decision_id"`
		Timestamp       string `json:"timestamp"`
		SessionID       string `json:"session_id"`
		Tool            string `json:"tool"`
		ArgumentsHash   string `json:"arguments_hash"`
		Decision        string `json:"decision"`
		Reason          string `json:"reason"`
		PolicyVersion   string `json:"policy_version"`
		ScannerType     string `json:"scanner_type"`
		CorrelationID   string `json:"correlation_id"`
		Classification  string `json:"classification"`
		Source          string `json:"source"`
		ResponseBlocked int    `json:"response_blocked"`
	}

	var entries []auditEntry
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.DecisionID, &e.Timestamp, &e.SessionID, &e.Tool,
			&e.ArgumentsHash, &e.Decision, &e.Reason, &e.PolicyVersion, &e.ScannerType,
			&e.CorrelationID, &e.Classification, &e.Source, &e.ResponseBlocked); err != nil {
			log.Printf("Audit row scan error: %v", err)
			continue
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []auditEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	for _, v := range r.Header.Values("Connection") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
				return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
			}
		}
	}
	return false
}

// singleJoiningSlash joins two URL path segments with exactly one slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// secureTokenCompare performs a constant-time comparison of two token strings
// to prevent timing side-channel attacks on authentication tokens.
func secureTokenCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// generateAuthToken creates a cryptographically random 48-char hex token.
// SECURITY: Panics if crypto/rand fails rather than falling back to a
// predictable timestamp-based token that could be guessed by an attacker.
func generateAuthToken() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("FATAL: crypto/rand failed — refusing to generate insecure auth token: %v", err)
	}
	return hex.EncodeToString(buf)
}

// listenOnLoopback returns a listener bound to loopback only for the given port.
func listenOnLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}
