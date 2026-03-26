package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCountMismatch(t *testing.T) {
	d := NewHallucinationDetector(&HallucinationConfig{
		Enabled: true,
		Rules:   []string{"count_mismatch"},
	})

	// Record tool result: 5 Jira issues
	toolOutput := json.RawMessage(`{"issues": [{"key":"PROJ-1"},{"key":"PROJ-2"},{"key":"PROJ-3"},{"key":"PROJ-4"},{"key":"PROJ-5"}], "total": 5}`)
	d.RecordToolResult("sess1", "jira_search", nil, toolOutput)

	// Agent says "I found 3 issues"
	report := d.ScanResponse("sess1", "I found 3 issues matching your query.")
	if report.Clean {
		t.Error("Expected hallucination detected, got clean")
	}
	if len(report.Violations) == 0 {
		t.Fatal("Expected violations")
	}
	if report.Violations[0].Rule != "count_mismatch" {
		t.Errorf("Expected count_mismatch, got %s", report.Violations[0].Rule)
	}
	t.Logf("Violation: %s (confidence %.2f)", report.Violations[0].Detail, report.Violations[0].Confidence)
}

func TestCorrectCount(t *testing.T) {
	d := NewHallucinationDetector(&HallucinationConfig{
		Enabled: true,
		Rules:   []string{"count_mismatch"},
	})

	toolOutput := json.RawMessage(`{"issues": [{"key":"PROJ-1"},{"key":"PROJ-2"},{"key":"PROJ-3"}], "total": 3}`)
	d.RecordToolResult("sess2", "jira_search", nil, toolOutput)

	report := d.ScanResponse("sess2", "I found 3 issues matching your query.")
	if !report.Clean {
		t.Errorf("Expected clean, got violations: %+v", report.Violations)
	}
}

func TestFabricatedID(t *testing.T) {
	d := NewHallucinationDetector(&HallucinationConfig{
		Enabled: true,
		Rules:   []string{"fabricated_id"},
	})

	toolOutput := json.RawMessage(`{"issues": [{"key":"PROJ-101"},{"key":"PROJ-102"}]}`)
	d.RecordToolResult("sess3", "jira_search", nil, toolOutput)

	// Test ID extraction directly
	respIDs := extractIDs(strings.ToLower("The critical issue is PROJ-999 which needs attention, along with PROJ-101."))
	t.Logf("Response IDs extracted: %v", respIDs)
	outIDs := extractIDs(strings.ToLower(string(toolOutput)))
	t.Logf("Output IDs extracted: %v", outIDs)
	for _, id := range respIDs {
		t.Logf("  isStructuredID(%q) = %v", id, isStructuredID(id))
	}

	// Agent references PROJ-999 which doesn't exist
	report := d.ScanResponse("sess3", "The critical issue is PROJ-999 which needs attention, along with PROJ-101.")
	t.Logf("Report: clean=%v, violations=%d, checks=%d", report.Clean, len(report.Violations), report.Checks)
	for _, v := range report.Violations {
		t.Logf("  Violation: %+v", v)
	}
	if report.Clean {
		t.Error("Expected fabricated ID detected")
	}

	found := false
	for _, v := range report.Violations {
		if v.Rule == "fabricated_id" && strings.EqualFold(v.AgentClaim, "PROJ-999") {
			found = true
			t.Logf("Caught: %s", v.Detail)
		}
	}
	if !found {
		t.Error("Expected PROJ-999 to be flagged as fabricated")
	}
}

func TestStatusMismatch(t *testing.T) {
	d := NewHallucinationDetector(&HallucinationConfig{
		Enabled: true,
		Rules:   []string{"status_mismatch"},
	})

	// Tool returned an error
	toolOutput := json.RawMessage(`{"error": "Permission denied", "status": 403}`)
	d.RecordToolResult("sess4", "jira_create", nil, toolOutput)

	// Agent claims success
	report := d.ScanResponse("sess4", "I've successfully created the issue for you.")
	if report.Clean {
		t.Error("Expected status mismatch detected")
	}
	if len(report.Violations) == 0 {
		t.Fatal("Expected violations")
	}
	if report.Violations[0].Rule != "status_mismatch" {
		t.Errorf("Expected status_mismatch, got %s", report.Violations[0].Rule)
	}
	t.Logf("Caught: %s (severity: %s)", report.Violations[0].Detail, report.Violations[0].Severity)
}

func TestDisabledReturnsNil(t *testing.T) {
	d := NewHallucinationDetector(nil)
	if d != nil {
		t.Error("Expected nil detector when config is nil")
	}

	d = NewHallucinationDetector(&HallucinationConfig{Enabled: false})
	if d != nil {
		t.Error("Expected nil detector when disabled")
	}
}

func TestAllRulesCleanResponse(t *testing.T) {
	d := NewHallucinationDetector(&HallucinationConfig{
		Enabled: true,
	})

	toolOutput := json.RawMessage(`{"issues": [{"key":"PROJ-1","summary":"Fix bug","status":"Open"}], "total": 1}`)
	d.RecordToolResult("sess5", "jira_search", nil, toolOutput)

	report := d.ScanResponse("sess5", "I found 1 issue: PROJ-1 (Fix bug, status Open).")
	if !report.Clean {
		t.Errorf("Expected clean response, got %d violations: %+v", len(report.Violations), report.Violations)
	}
}
