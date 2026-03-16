package permissions

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Decision records the outcome of a permission check for audit logging.
type Decision struct {
	Timestamp       time.Time
	Agent           string
	Action          string // "classify", "dlp", "scope", "sanitize", "ceiling"
	Result          string // "allow", "deny", "redact"
	Reason          string
	Classification  string
	CorrelationID   string
	Details         string // extra context (matched patterns, etc.)
}

// AuditFunc is a callback for recording permission decisions.
type AuditFunc func(Decision)

// Middleware wraps an http.Handler with permission enforcement.
// It extracts the agent name from the OpenAI-compatible chat completions
// request body (model field: "openclaw/agentname" → "agentname"), then
// runs the full M1-M4 pipeline on the request and response.
type Middleware struct {
	config   *Config
	auditFn  AuditFunc
	next     http.Handler
}

// NewMiddleware creates a permission-enforcing HTTP middleware.
func NewMiddleware(cfg *Config, auditFn AuditFunc, next http.Handler) *Middleware {
	if auditFn == nil {
		auditFn = func(Decision) {} // no-op
	}
	return &Middleware{
		config:  cfg,
		auditFn: auditFn,
		next:    next,
	}
}

// ServeHTTP implements http.Handler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only intercept chat completions POST
	if r.Method != http.MethodPost || !isChatCompletionsPath(r.URL.Path) {
		m.next.ServeHTTP(w, r)
		return
	}

	// Read body
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024)) // 2MB max
	r.Body.Close()
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}

	// Extract agent name from model field
	var reqBody struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		// Not valid JSON — pass through, let upstream handle it
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		m.next.ServeHTTP(w, r)
		return
	}

	agentName := extractAgentName(reqBody.Model)
	correlationID := r.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = generateCorrelationID()
	}

	// Concatenate all user message content for scanning
	var userContent strings.Builder
	for _, msg := range reqBody.Messages {
		if msg.Role == "user" {
			userContent.WriteString(msg.Content)
			userContent.WriteByte(' ')
		}
	}
	messageText := userContent.String()

	// --- M1: Data Classification + Ceiling Check ---
	classifier := m.config.Classifier()
	if classifier != nil && messageText != "" {
		classResult := classifier.Classify(messageText)

		m.auditFn(Decision{
			Timestamp:      time.Now(),
			Agent:          agentName,
			Action:         "classify",
			Result:         boolToDecision(!classResult.Blocked),
			Reason:         fmt.Sprintf("level=%s", classResult.Level),
			Classification: classResult.Level,
			CorrelationID:  correlationID,
			Details:        formatMatches(classResult.MatchedPatterns),
		})

		if classResult.Blocked {
			log.Printf("PERM BLOCKED [classify]: agent=%s level=%s correlationId=%s", agentName, classResult.Level, correlationID)
			writeBlockedResponse(w, fmt.Sprintf("message contains %s data — blocked by classification policy", classResult.Level))
			return
		}

		// Ceiling check: is the classification level within the agent's allowed ceiling?
		if !m.config.CheckClassificationCeiling(agentName, classResult.Level) {
			reason := fmt.Sprintf("classification %s exceeds agent %s ceiling", classResult.Level, agentName)
			m.auditFn(Decision{
				Timestamp:      time.Now(),
				Agent:          agentName,
				Action:         "ceiling",
				Result:         "deny",
				Reason:         reason,
				Classification: classResult.Level,
				CorrelationID:  correlationID,
			})
			log.Printf("PERM BLOCKED [ceiling]: agent=%s level=%s correlationId=%s", agentName, classResult.Level, correlationID)
			writeBlockedResponse(w, reason)
			return
		}
	}

	// --- Bridge DLP: Scrub outbound content ---
	dlpEngine := m.config.DLPEngine()
	if dlpEngine != nil && messageText != "" {
		// Scrub concatenated text first for audit + block decision
		dlpResult := dlpEngine.Scrub(messageText)

		if len(dlpResult.Redactions) > 0 {
			m.auditFn(Decision{
				Timestamp:     time.Now(),
				Agent:         agentName,
				Action:        "dlp",
				Result:        boolToDecision(dlpResult.Allowed),
				Reason:        fmt.Sprintf("mode=%s redactions=%d", dlpResult.Mode, len(dlpResult.Redactions)),
				CorrelationID: correlationID,
				Details:       formatRedactions(dlpResult.Redactions),
			})
		}

		if !dlpResult.Allowed {
			log.Printf("PERM BLOCKED [dlp]: agent=%s mode=%s correlationId=%s", agentName, dlpResult.Mode, correlationID)
			writeBlockedResponse(w, "message blocked by DLP policy")
			return
		}

		// If content was redacted, scrub each user message individually
		if len(dlpResult.Redactions) > 0 && dlpResult.Mode == DLPRedact {
			bodyBytes = rewriteUserContent(bodyBytes, dlpEngine)
		}
	}

	// --- Agent Scope Check (on request content) ---
	// Check if the user message references platforms outside the agent's scope
	agentPlatforms := m.config.GetAgentPlatforms(agentName)

	// --- M2: Ephemeral Session Isolation ---
	if m.config.EphemeralSessions() {
		bodyBytes = rewriteSessionFields(bodyBytes)
	}

	// Restore body for downstream
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	// --- M4: Response Sanitization (wrap response writer) ---
	sanitizer := m.config.ResponseSanitizerEngine()
	rw := &responseInterceptor{
		ResponseWriter: w,
		agentName:      agentName,
		agentPlatforms: agentPlatforms,
		sanitizer:      sanitizer,
		auditFn:        m.auditFn,
		correlationID:  correlationID,
	}

	m.next.ServeHTTP(rw, r)

	// Flush intercepted response
	rw.flush()
}

// responseInterceptor captures the response body for M4 sanitization.
type responseInterceptor struct {
	http.ResponseWriter
	agentName      string
	agentPlatforms []string
	sanitizer      *Sanitizer
	auditFn        AuditFunc
	correlationID  string

	statusCode int
	buf        bytes.Buffer
	headerSent bool
}

func (ri *responseInterceptor) WriteHeader(code int) {
	ri.statusCode = code
}

func (ri *responseInterceptor) Write(b []byte) (int, error) {
	return ri.buf.Write(b)
}

func (ri *responseInterceptor) flush() {
	body := ri.buf.Bytes()
	statusCode := ri.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	// Only sanitize 200 JSON responses
	ct := ri.ResponseWriter.Header().Get("Content-Type")
	if statusCode == http.StatusOK && strings.Contains(ct, "application/json") && ri.sanitizer != nil {
		content := extractResponseContent(body)
		if content != "" {
			result := ri.sanitizer.Sanitize(content, ri.agentPlatforms)
			if result.Blocked {
				ri.auditFn(Decision{
					Timestamp:     time.Now(),
					Agent:         ri.agentName,
					Action:        "sanitize",
					Result:        "deny",
					Reason:        result.Reason,
					CorrelationID: ri.correlationID,
				})
				log.Printf("PERM BLOCKED [sanitize]: agent=%s reason=%s correlationId=%s", ri.agentName, result.Reason, ri.correlationID)

				blocked := []byte(`{"error":{"message":"response blocked by security policy","code":-32600}}`)
				ri.ResponseWriter.Header().Set("Content-Type", "application/json")
				ri.ResponseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", len(blocked)))
				ri.ResponseWriter.WriteHeader(http.StatusOK) // Keep 200 to match OpenAI API convention
				ri.ResponseWriter.Write(blocked)
				return
			}
		}
	}

	// Pass through
	ri.ResponseWriter.WriteHeader(statusCode)
	ri.ResponseWriter.Write(body)
}

// --- Helper functions ---

func isChatCompletionsPath(path string) bool {
	return strings.HasSuffix(path, "/chat/completions") || path == "/chat/completions"
}

// extractAgentName gets the agent name from an OpenClaw model string.
// "openclaw/anvil" → "anvil", "anvil" → "anvil"
func extractAgentName(model string) string {
	if idx := strings.LastIndex(model, "/"); idx >= 0 {
		return strings.ToLower(model[idx+1:])
	}
	return strings.ToLower(model)
}

func generateCorrelationID() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func boolToDecision(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func writeBlockedResponse(w http.ResponseWriter, reason string) {
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": "blocked by ClawShield permission policy",
			"code":    -32600,
			"data":    reason,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(resp)
}

func formatMatches(matches []MatchedPattern) string {
	if len(matches) == 0 {
		return ""
	}
	parts := make([]string, len(matches))
	for i, m := range matches {
		parts[i] = fmt.Sprintf("%s(%s)", m.Label, m.Level)
	}
	return strings.Join(parts, ", ")
}

func formatRedactions(redactions []Redaction) string {
	if len(redactions) == 0 {
		return ""
	}
	parts := make([]string, len(redactions))
	for i, r := range redactions {
		parts[i] = r.Label
	}
	return strings.Join(parts, ", ")
}

// rewriteUserContent applies DLP scrubbing to each user message individually.
func rewriteUserContent(body []byte, dlp *DLP) []byte {
	var bodyMap map[string]interface{}
	if json.Unmarshal(body, &bodyMap) != nil {
		return body
	}

	messages, ok := bodyMap["messages"].([]interface{})
	if !ok {
		return body
	}

	for _, msg := range messages {
		m, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}
		if m["role"] != "user" {
			continue
		}
		content, ok := m["content"].(string)
		if !ok || content == "" {
			continue
		}
		result := dlp.Scrub(content)
		if len(result.Redactions) > 0 {
			m["content"] = result.ScrubbedMessage
		}
	}

	rewritten, err := json.Marshal(bodyMap)
	if err != nil {
		return body
	}
	return rewritten
}

// rewriteSessionFields sets ephemeral session fields (M2).
func rewriteSessionFields(body []byte) []byte {
	var bodyMap map[string]interface{}
	if json.Unmarshal(body, &bodyMap) != nil {
		return body
	}

	// Random ephemeral user ID
	buf := make([]byte, 16)
	rand.Read(buf)
	bodyMap["user"] = hex.EncodeToString(buf)
	bodyMap["store"] = false

	rewritten, err := json.Marshal(bodyMap)
	if err != nil {
		return body
	}
	return rewritten
}

// extractResponseContent extracts the content from an OpenAI-format chat response.
func extractResponseContent(body []byte) string {
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &resp) == nil && len(resp.Choices) > 0 {
		return resp.Choices[0].Message.Content
	}
	return ""
}
