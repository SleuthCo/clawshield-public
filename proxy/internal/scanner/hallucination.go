package scanner

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HallucinationConfig holds policy configuration for hallucination detection.
type HallucinationConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Rules      []string `yaml:"rules"`       // Which rules to enable: count_mismatch, fabricated_id, phantom_field, summary_inflation, url_fabrication, status_mismatch
	BufferSize int      `yaml:"buffer_size"`  // Max tool results to buffer per session (default 20)
	LogAll     bool     `yaml:"log_all"`      // Log all checks (not just violations) for analysis
}

// HallucinationDetector compares agent claims against tool call ground truth.
type HallucinationDetector struct {
	enabledRules map[string]bool
	bufferSize   int
	logAll       bool

	// Per-session tool result buffer: sessionID -> []ToolResult
	mu      sync.RWMutex
	buffers map[string]*sessionBuffer
}

type sessionBuffer struct {
	results   []ToolResult
	createdAt time.Time
}

// ToolResult captures a tool call and its actual output for later comparison.
type ToolResult struct {
	ToolName   string          `json:"tool_name"`
	Params     json.RawMessage `json:"params"`
	Output     json.RawMessage `json:"output"`
	RecordedAt time.Time       `json:"recorded_at"`
}

// HallucinationReport is the result of scanning a response against tool results.
type HallucinationReport struct {
	Clean      bool                 `json:"clean"`
	Score      float64              `json:"score"`       // 0.0 (grounded) to 1.0 (hallucinated)
	Violations []HallucinationEntry `json:"violations"`
	Checks     int                  `json:"checks"`      // Total checks performed
}

// HallucinationEntry is a single detected hallucination.
type HallucinationEntry struct {
	Rule       string  `json:"rule"`
	Severity   string  `json:"severity"`   // low, medium, high
	Detail     string  `json:"detail"`
	ToolName   string  `json:"tool_name"`
	Expected   string  `json:"expected"`
	AgentClaim string  `json:"agent_claim"`
	Confidence float64 `json:"confidence"` // How confident we are this is a hallucination
}

// NewHallucinationDetector creates a detector from policy configuration.
func NewHallucinationDetector(cfg *HallucinationConfig) *HallucinationDetector {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	rules := make(map[string]bool)
	allRules := []string{"count_mismatch", "fabricated_id", "phantom_field", "summary_inflation", "url_fabrication", "status_mismatch"}

	if len(cfg.Rules) == 0 {
		// Enable all rules by default
		for _, r := range allRules {
			rules[r] = true
		}
	} else {
		for _, r := range cfg.Rules {
			rules[r] = true
		}
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 20
	}

	return &HallucinationDetector{
		enabledRules: rules,
		bufferSize:   bufSize,
		logAll:       cfg.LogAll,
		buffers:      make(map[string]*sessionBuffer),
	}
}

// RecordToolResult stores a tool call result for later comparison.
func (d *HallucinationDetector) RecordToolResult(sessionID, toolName string, params, output json.RawMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()

	buf, exists := d.buffers[sessionID]
	if !exists {
		buf = &sessionBuffer{createdAt: time.Now()}
		d.buffers[sessionID] = buf
	}

	// Evict old sessions (> 30 min)
	d.evictStale()

	// Ring buffer: drop oldest if full
	if len(buf.results) >= d.bufferSize {
		buf.results = buf.results[1:]
	}

	buf.results = append(buf.results, ToolResult{
		ToolName:   toolName,
		Params:     params,
		Output:     output,
		RecordedAt: time.Now(),
	})
}

// ScanResponse checks an agent response against buffered tool results.
// Returns a report (never blocks — hallucinations are logged, not denied).
func (d *HallucinationDetector) ScanResponse(sessionID, responseText string) *HallucinationReport {
	d.mu.RLock()
	buf, exists := d.buffers[sessionID]
	var results []ToolResult
	if exists {
		results = make([]ToolResult, len(buf.results))
		copy(results, buf.results)
	}
	d.mu.RUnlock()

	report := &HallucinationReport{Clean: true}

	if len(results) == 0 {
		return report
	}

	lower := strings.ToLower(responseText)

	for _, tr := range results {
		if d.enabledRules["count_mismatch"] {
			d.checkCountMismatch(tr, lower, report)
		}
		if d.enabledRules["fabricated_id"] {
			d.checkFabricatedID(tr, lower, report)
		}
		if d.enabledRules["phantom_field"] {
			d.checkPhantomField(tr, lower, report)
		}
		if d.enabledRules["url_fabrication"] {
			d.checkURLFabrication(tr, lower, report)
		}
		if d.enabledRules["status_mismatch"] {
			d.checkStatusMismatch(tr, lower, report)
		}
		if d.enabledRules["summary_inflation"] {
			d.checkSummaryInflation(tr, responseText, report)
		}
	}

	if len(report.Violations) > 0 {
		report.Clean = false
		// Score: weighted average of violation confidences
		var total float64
		for _, v := range report.Violations {
			total += v.Confidence
		}
		report.Score = math.Min(1.0, total/float64(len(report.Violations)))
		report.Score = math.Round(report.Score*100) / 100
	}

	return report
}

// ClearSession removes buffered tool results for a session.
func (d *HallucinationDetector) ClearSession(sessionID string) {
	d.mu.Lock()
	delete(d.buffers, sessionID)
	d.mu.Unlock()
}

// evictStale removes sessions older than 30 minutes. Must hold write lock.
func (d *HallucinationDetector) evictStale() {
	cutoff := time.Now().Add(-30 * time.Minute)
	for id, buf := range d.buffers {
		if buf.createdAt.Before(cutoff) {
			delete(d.buffers, id)
		}
	}
}

// --- Detection Rules ---

// count_mismatch: Agent claims a different count than what the tool returned.
// E.g., tool returned 5 Jira issues but agent says "I found 3 issues".
func (d *HallucinationDetector) checkCountMismatch(tr ToolResult, lowerResp string, report *HallucinationReport) {
	report.Checks++

	// Extract actual count from tool output
	actualCount := extractResultCount(tr.Output)
	if actualCount < 0 {
		return // Can't determine count from output
	}

	// Look for count claims in response
	countPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:found|returned|got|showing|there (?:are|were)|i (?:found|see|got))\s+(\d+)\s+(?:results?|issues?|items?|pages?|files?|messages?|records?|matches?|rows?|entries?|documents?)`),
		regexp.MustCompile(`(?i)(\d+)\s+(?:results?|issues?|items?|pages?|files?|messages?|records?|matches?|rows?|entries?|documents?)\s+(?:found|returned|matched|available)`),
	}

	for _, pat := range countPatterns {
		matches := pat.FindStringSubmatch(lowerResp)
		if len(matches) >= 2 {
			claimed, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			if claimed != actualCount {
				report.Violations = append(report.Violations, HallucinationEntry{
					Rule:       "count_mismatch",
					Severity:   severityForCountDiff(actualCount, claimed),
					Detail:     fmt.Sprintf("Agent claimed %d results but tool returned %d", claimed, actualCount),
					ToolName:   tr.ToolName,
					Expected:   strconv.Itoa(actualCount),
					AgentClaim: strconv.Itoa(claimed),
					Confidence: 0.9,
				})
			}
		}
	}
}

// fabricated_id: Agent references an ID (issue key, page ID, etc.) not in tool output.
func (d *HallucinationDetector) checkFabricatedID(tr ToolResult, lowerResp string, report *HallucinationReport) {
	report.Checks++

	// Extract all IDs from tool output (lowercase for comparison)
	outputStr := strings.ToLower(string(tr.Output))
	realIDs := extractIDs(outputStr)
	if len(realIDs) == 0 {
		return
	}

	// Extract IDs from agent response (already lowercase)
	claimedIDs := extractIDs(lowerResp)

	// Check if agent references IDs not in tool output
	realSet := make(map[string]bool, len(realIDs))
	for _, id := range realIDs {
		realSet[strings.ToLower(id)] = true
	}

	for _, claimed := range claimedIDs {
		claimedLower := strings.ToLower(claimed)
		if !realSet[claimedLower] {
			// Check if it's a plausible Jira key or similar structured ID
			if isStructuredID(claimed) {
				report.Violations = append(report.Violations, HallucinationEntry{
					Rule:       "fabricated_id",
					Severity:   "high",
					Detail:     fmt.Sprintf("Agent referenced ID %q not found in tool output", claimed),
					ToolName:   tr.ToolName,
					Expected:   fmt.Sprintf("One of: %s", strings.Join(firstN(realIDs, 5), ", ")),
					AgentClaim: claimed,
					Confidence: 0.85,
				})
			}
		}
	}
}

// phantom_field: Agent attributes a field value that doesn't exist in the tool output.
// E.g., tool output has no "priority" field but agent says "priority is High".
func (d *HallucinationDetector) checkPhantomField(tr ToolResult, lowerResp string, report *HallucinationReport) {
	report.Checks++

	// Parse tool output as JSON object/array
	var outputData interface{}
	if err := json.Unmarshal(tr.Output, &outputData); err != nil {
		return
	}

	// Extract all field names from the JSON output
	realFields := extractFieldNames(outputData)
	if len(realFields) == 0 {
		return
	}

	// Common fields agents might fabricate
	checkFields := []string{"priority", "assignee", "status", "due_date", "labels", "component", "resolution", "severity", "reporter", "created", "updated"}

	realFieldSet := make(map[string]bool, len(realFields))
	for _, f := range realFields {
		realFieldSet[strings.ToLower(f)] = true
	}

	for _, field := range checkFields {
		if realFieldSet[field] {
			continue // Field exists in output, not phantom
		}
		// Check if agent mentions this field with a value
		pat := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(field) + `\s*(?:is|:|=|was)\s+["']?(\w+)`)
		if matches := pat.FindStringSubmatch(lowerResp); len(matches) >= 2 {
			report.Violations = append(report.Violations, HallucinationEntry{
				Rule:       "phantom_field",
				Severity:   "medium",
				Detail:     fmt.Sprintf("Agent claims %s=%q but field not present in tool output", field, matches[1]),
				ToolName:   tr.ToolName,
				Expected:   "Field not in output",
				AgentClaim: fmt.Sprintf("%s=%s", field, matches[1]),
				Confidence: 0.7,
			})
		}
	}
}

// url_fabrication: Agent includes a URL not present in tool output.
func (d *HallucinationDetector) checkURLFabrication(tr ToolResult, lowerResp string, report *HallucinationReport) {
	report.Checks++

	outputStr := strings.ToLower(string(tr.Output))

	// Extract URLs from agent response
	urlPat := regexp.MustCompile(`https?://[^\s"'<>\])+]+`)
	claimedURLs := urlPat.FindAllString(lowerResp, -1)
	outputURLs := urlPat.FindAllString(outputStr, -1)

	outputURLSet := make(map[string]bool, len(outputURLs))
	for _, u := range outputURLs {
		outputURLSet[u] = true
	}

	for _, claimed := range claimedURLs {
		if !outputURLSet[claimed] {
			// Check if URL domain at least appears in output (partial match OK)
			domain := extractURLDomain(claimed)
			if domain != "" && strings.Contains(outputStr, domain) {
				continue // Domain is real, URL path may be constructed (acceptable)
			}
			report.Violations = append(report.Violations, HallucinationEntry{
				Rule:       "url_fabrication",
				Severity:   "medium",
				Detail:     fmt.Sprintf("Agent included URL not found in tool output: %s", claimed),
				ToolName:   tr.ToolName,
				Expected:   "URL from tool output",
				AgentClaim: claimed,
				Confidence: 0.65,
			})
		}
	}
}

// status_mismatch: Agent claims success/failure opposite to what tool returned.
func (d *HallucinationDetector) checkStatusMismatch(tr ToolResult, lowerResp string, report *HallucinationReport) {
	report.Checks++

	// Parse tool output for error indicators
	outputStr := string(tr.Output)
	toolFailed := false

	var outputObj map[string]interface{}
	if err := json.Unmarshal(tr.Output, &outputObj); err == nil {
		if _, hasErr := outputObj["error"]; hasErr {
			toolFailed = true
		}
		if _, hasErr := outputObj["errors"]; hasErr {
			toolFailed = true
		}
		if status, ok := outputObj["status"].(float64); ok && status >= 400 {
			toolFailed = true
		}
	}

	// Also check for error strings in raw output
	if !toolFailed {
		lowerOutput := strings.ToLower(outputStr)
		if strings.Contains(lowerOutput, "\"error\"") || strings.Contains(lowerOutput, "\"errors\"") {
			toolFailed = true
		}
	}

	// Check agent's claim
	successClaims := regexp.MustCompile(`(?i)(successfully|done|completed|created|updated|i've .+ the|here (?:are|is) the)`)
	failureClaims := regexp.MustCompile(`(?i)(failed|error|couldn't|unable to|sorry.*(?:couldn't|unable|failed)|an error occurred)`)

	agentClaimsSuccess := successClaims.MatchString(lowerResp)
	agentClaimsFailure := failureClaims.MatchString(lowerResp)

	if toolFailed && agentClaimsSuccess && !agentClaimsFailure {
		report.Violations = append(report.Violations, HallucinationEntry{
			Rule:       "status_mismatch",
			Severity:   "high",
			Detail:     "Agent claimed success but tool returned an error",
			ToolName:   tr.ToolName,
			Expected:   "Error acknowledgment",
			AgentClaim: "Success",
			Confidence: 0.9,
		})
	}

	if !toolFailed && agentClaimsFailure && !agentClaimsSuccess {
		report.Violations = append(report.Violations, HallucinationEntry{
			Rule:       "status_mismatch",
			Severity:   "medium",
			Detail:     "Agent claimed failure but tool returned successfully",
			ToolName:   tr.ToolName,
			Expected:   "Success acknowledgment",
			AgentClaim: "Failure",
			Confidence: 0.7,
		})
	}
}

// summary_inflation: Agent's summary contains significantly more detail than the tool output.
// Indicates the agent is inventing specifics not in the data.
func (d *HallucinationDetector) checkSummaryInflation(tr ToolResult, responseText string, report *HallucinationReport) {
	report.Checks++

	outputLen := len(string(tr.Output))
	responseLen := len(responseText)

	if outputLen == 0 {
		return
	}

	// If response is 5x+ longer than tool output, flag it
	ratio := float64(responseLen) / float64(outputLen)
	if ratio > 5.0 && responseLen > 500 {
		report.Violations = append(report.Violations, HallucinationEntry{
			Rule:       "summary_inflation",
			Severity:   "low",
			Detail:     fmt.Sprintf("Agent response (%.0f chars) is %.1fx longer than tool output (%d chars) — may contain fabricated details", float64(responseLen), ratio, outputLen),
			ToolName:   tr.ToolName,
			Expected:   fmt.Sprintf("~%d chars of grounded content", outputLen),
			AgentClaim: fmt.Sprintf("%d chars", responseLen),
			Confidence: 0.4,
		})
	}
}

// --- Helpers ---

func extractResultCount(output json.RawMessage) int {
	// Try array length
	var arr []json.RawMessage
	if err := json.Unmarshal(output, &arr); err == nil {
		return len(arr)
	}

	// Try object with count/total/length field
	var obj map[string]interface{}
	if err := json.Unmarshal(output, &obj); err == nil {
		for _, key := range []string{"total", "count", "length", "size", "totalSize", "maxResults"} {
			if v, ok := obj[key]; ok {
				if n, ok := v.(float64); ok {
					return int(n)
				}
			}
		}
		// Try nested: results/issues/items array
		for _, key := range []string{"results", "issues", "items", "values", "data", "messages", "pages"} {
			if v, ok := obj[key]; ok {
				if items, ok := v.([]interface{}); ok {
					return len(items)
				}
			}
		}
	}

	return -1
}

var idPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[A-Z]{2,10}-\d{1,6}`),        // Jira issue key: PROJ-123
	regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-`), // UUID prefix
	regexp.MustCompile(`\b\d{5,10}\b`),                    // Numeric IDs (5-10 digits)
}

func extractIDs(text string) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, pat := range idPatterns {
		for _, match := range pat.FindAllString(text, 50) {
			if !seen[match] {
				seen[match] = true
				ids = append(ids, match)
			}
		}
	}
	return ids
}

func isStructuredID(s string) bool {
	jiraKey := regexp.MustCompile(`(?i)^[A-Z]{2,10}-\d{1,6}$`)
	uuid := regexp.MustCompile(`(?i)^[0-9a-f]{8}-`)
	return jiraKey.MatchString(s) || uuid.MatchString(s)
}

func extractFieldNames(v interface{}) []string {
	var fields []string
	switch val := v.(type) {
	case map[string]interface{}:
		for k, mv := range val {
			fields = append(fields, k)
			fields = append(fields, extractFieldNames(mv)...)
		}
	case []interface{}:
		for _, item := range val {
			fields = append(fields, extractFieldNames(item)...)
		}
	}
	return fields
}

func extractURLDomain(rawURL string) string {
	// Simple domain extraction without url.Parse for lowercase input
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return ""
	}
	rest := rawURL[idx+3:]
	end := strings.IndexAny(rest, ":/? ")
	if end > 0 {
		return rest[:end]
	}
	return rest
}

func severityForCountDiff(actual, claimed int) string {
	if actual == 0 && claimed > 0 {
		return "high" // Fabricated results
	}
	diff := math.Abs(float64(actual - claimed))
	ratio := diff / math.Max(1, float64(actual))
	if ratio > 0.5 {
		return "high"
	}
	if ratio > 0.2 {
		return "medium"
	}
	return "low"
}

func firstN(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return items[:n]
}
