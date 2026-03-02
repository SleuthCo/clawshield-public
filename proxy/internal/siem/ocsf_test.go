package siem

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

// TestMapSeverity verifies severity mapping for various decision types.
func TestMapSeverity(t *testing.T) {
	cases := []struct {
		name       string
		decision   types.Decision
		expectID   int
		expectName string
	}{
		{
			"allow is Informational",
			types.Decision{Decision: "allow"},
			SeverityInformational,
			"Informational",
		},
		{
			"redacted is Medium",
			types.Decision{Decision: "redacted"},
			SeverityMedium,
			"Medium",
		},
		{
			"deny injection is Critical",
			types.Decision{
				Decision: "deny",
				Details: &types.DecisionDetail{
					ScanResults: []types.ScanResult{{Scanner: "injection"}},
				},
			},
			SeverityCritical,
			"Critical",
		},
		{
			"deny malware is Critical",
			types.Decision{
				Decision: "deny",
				Details: &types.DecisionDetail{
					ScanResults: []types.ScanResult{{Scanner: "malware"}},
				},
			},
			SeverityCritical,
			"Critical",
		},
		{
			"deny vuln is High",
			types.Decision{
				Decision: "deny",
				Details: &types.DecisionDetail{
					ScanResults: []types.ScanResult{{Scanner: "vuln"}},
				},
			},
			SeverityHigh,
			"High",
		},
		{
			"deny secrets is High",
			types.Decision{
				Decision: "deny",
				Details: &types.DecisionDetail{
					ScanResults: []types.ScanResult{{Scanner: "secrets"}},
				},
			},
			SeverityHigh,
			"High",
		},
		{
			"deny pii is Medium",
			types.Decision{
				Decision: "deny",
				Details: &types.DecisionDetail{
					ScanResults: []types.ScanResult{{Scanner: "pii"}},
				},
			},
			SeverityMedium,
			"Medium",
		},
		{
			"deny policy is High",
			types.Decision{
				Decision: "deny",
				Reason:   "tool denied by denylist",
			},
			SeverityHigh,
			"High",
		},
		{
			"deny with scanner_type injection",
			types.Decision{
				Decision:    "deny",
				ScannerType: "injection",
			},
			SeverityCritical,
			"Critical",
		},
		{
			"deny with scanner_type vuln",
			types.Decision{
				Decision:    "deny",
				ScannerType: "vuln",
			},
			SeverityHigh,
			"High",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, name := MapSeverity(&tc.decision)
			if id != tc.expectID {
				t.Errorf("expected severity ID %d, got %d", tc.expectID, id)
			}
			if name != tc.expectName {
				t.Errorf("expected severity name %q, got %q", tc.expectName, name)
			}
		})
	}
}

// TestDecisionToOCSF_RequiredFields verifies all required OCSF fields are set.
func TestDecisionToOCSF_RequiredFields(t *testing.T) {
	dec := &types.Decision{
		Timestamp: time.Now(),
		Tool:      "shell.exec",
		Decision:  "deny",
		Reason:    "tool denied by denylist",
	}

	event := DecisionToOCSF(dec)

	if event.ClassUID != ClassUID {
		t.Errorf("expected ClassUID %d, got %d", ClassUID, event.ClassUID)
	}

	if event.CategoryUID != CategoryUID {
		t.Errorf("expected CategoryUID %d, got %d", CategoryUID, event.CategoryUID)
	}

	expectedTypeUID := ClassUID*100 + ActivityCreate
	if event.TypeUID != expectedTypeUID {
		t.Errorf("expected TypeUID %d, got %d", expectedTypeUID, event.TypeUID)
	}

	if event.ActivityID != ActivityCreate {
		t.Errorf("expected ActivityID %d, got %d", ActivityCreate, event.ActivityID)
	}

	if event.StatusID != StatusBlocked {
		t.Errorf("expected StatusID %d, got %d", StatusBlocked, event.StatusID)
	}

	if event.Status != "Blocked" {
		t.Errorf("expected Status %q, got %q", "Blocked", event.Status)
	}

	if event.SeverityID < SeverityHigh {
		t.Errorf("expected SeverityID >= %d, got %d", SeverityHigh, event.SeverityID)
	}

	if event.Metadata.Version != OCSFVersion {
		t.Errorf("expected version %q, got %q", OCSFVersion, event.Metadata.Version)
	}

	if event.Metadata.Product.Name != ProductName {
		t.Errorf("expected product name %q, got %q", ProductName, event.Metadata.Product.Name)
	}

	if event.Metadata.Product.VendorName != VendorName {
		t.Errorf("expected vendor name %q, got %q", VendorName, event.Metadata.Product.VendorName)
	}

	if event.Timestamp == 0 {
		t.Errorf("expected Timestamp > 0, got %d", event.Timestamp)
	}

	if event.Metadata.LoggedTime == 0 {
		t.Errorf("expected LoggedTime > 0, got %d", event.Metadata.LoggedTime)
	}

	if event.Message == "" {
		t.Errorf("expected non-empty Message")
	}

	if !contains(event.Message, "deny") {
		t.Errorf("expected Message to contain 'deny', got %q", event.Message)
	}

	if !contains(event.Message, "shell.exec") {
		t.Errorf("expected Message to contain 'shell.exec', got %q", event.Message)
	}
}

// TestDecisionToOCSF_WithScanResults verifies scanner findings are mapped to OCSF finding_info and evidences.
func TestDecisionToOCSF_WithScanResults(t *testing.T) {
	dec := &types.Decision{
		Timestamp:   time.Now(),
		Tool:        "db.query",
		Decision:    "deny",
		Reason:      "vuln_scan: SQL injection detected",
		ScannerType: "vuln",
		AgentName:   "test-agent",
		Source:      "direct",
		Details: &types.DecisionDetail{
			PipelineStage:  "vuln_scan",
			EvalDurationMs: 1.5,
			ScanResults: []types.ScanResult{{
				Scanner:      "vuln",
				RuleID:       "sqli",
				Description:  "SQL injection detected",
				MatchExcerpt: "OR 1=1",
				Confidence:   "high",
				Blocked:      true,
			}},
			ActiveOverrides: []string{"sensitivity_override:high"},
		},
	}

	event := DecisionToOCSF(dec)

	if event.FindingInfo == nil {
		t.Errorf("expected FindingInfo to be non-nil")
	} else {
		if event.FindingInfo.UID != "sqli" {
			t.Errorf("expected FindingInfo.UID %q, got %q", "sqli", event.FindingInfo.UID)
		}
		if event.FindingInfo.Confidence != "high" {
			t.Errorf("expected FindingInfo.Confidence %q, got %q", "high", event.FindingInfo.Confidence)
		}
	}

	if len(event.Evidences) == 0 {
		t.Errorf("expected Evidences to be non-empty")
	}

	hasRuleID := false
	for _, e := range event.Evidences {
		if e.Name == "rule_id" && e.Value == "sqli" {
			hasRuleID = true
			break
		}
	}
	if !hasRuleID {
		t.Errorf("expected Evidences to contain rule_id 'sqli'")
	}

	if len(event.Resources) < 3 {
		t.Errorf("expected at least 3 Resources (tool, agent, source), got %d", len(event.Resources))
	}

	if event.Unmapped == nil {
		t.Errorf("expected Unmapped to be non-nil")
	} else {
		if event.Unmapped["pipeline_stage"] != "vuln_scan" {
			t.Errorf("expected Unmapped['pipeline_stage'] %q, got %v", "vuln_scan", event.Unmapped["pipeline_stage"])
		}

		overrides, ok := event.Unmapped["active_overrides"]
		if !ok {
			t.Errorf("expected Unmapped to contain 'active_overrides'")
		} else {
			// Check if it contains the override string
			overridesStr := toString(overrides)
			if !contains(overridesStr, "sensitivity_override:high") {
				t.Errorf("expected active_overrides to contain 'sensitivity_override:high', got %v", overrides)
			}
		}
	}
}

// TestDecisionToOCSF_AllowDecision verifies allowed decisions produce correct OCSF events.
func TestDecisionToOCSF_AllowDecision(t *testing.T) {
	dec := &types.Decision{
		Timestamp: time.Now(),
		Tool:      "tools.list",
		Decision:  "allow",
		Reason:    "default allowed",
	}

	event := DecisionToOCSF(dec)

	if event.StatusID != StatusSuccess {
		t.Errorf("expected StatusID %d, got %d", StatusSuccess, event.StatusID)
	}

	if event.Status != "Success" {
		t.Errorf("expected Status %q, got %q", "Success", event.Status)
	}

	if event.SeverityID != SeverityInformational {
		t.Errorf("expected SeverityID %d, got %d", SeverityInformational, event.SeverityID)
	}

	if event.FindingInfo != nil {
		t.Errorf("expected FindingInfo to be nil for allow decision, got %v", event.FindingInfo)
	}
}

// TestMarshalOCSF_ValidJSON verifies OCSF events serialize to valid JSON.
func TestMarshalOCSF_ValidJSON(t *testing.T) {
	dec := &types.Decision{
		Timestamp: time.Now(),
		Tool:      "test",
		Decision:  "deny",
		Reason:    "test",
		Details: &types.DecisionDetail{
			PipelineStage: "denylist",
			ScanResults:   []types.ScanResult{},
		},
	}

	event := DecisionToOCSF(dec)
	data, err := MarshalOCSF(event)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if !json.Valid(data) {
		t.Errorf("expected valid JSON, got %q", string(data))
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("expected to unmarshal JSON, got error: %v", err)
	}

	if classUID, ok := parsed["class_uid"].(float64); !ok || int(classUID) != ClassUID {
		t.Errorf("expected class_uid %d in parsed JSON", ClassUID)
	}

	if _, ok := parsed["severity_id"]; !ok {
		t.Errorf("expected severity_id in parsed JSON")
	}
}

// Helper functions for testing.

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case []string:
		if len(val) > 0 {
			return val[0]
		}
		return ""
	case []interface{}:
		if len(val) > 0 {
			if s, ok := val[0].(string); ok {
				return s
			}
		}
		return ""
	default:
		return ""
	}
}
