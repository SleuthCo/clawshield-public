package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

const (
	OCSFVersion    = "1.1.0"
	ProductName    = "ClawShield"
	VendorName     = "SleuthCo"
	ProductVersion = "1.0.0"

	// OCSF class/category for Detection Finding
	ClassUID    = 2004 // Detection Finding
	CategoryUID = 2    // Findings

	// Activity IDs
	ActivityCreate = 1 // New finding

	// Status IDs
	StatusSuccess = 1 // Allowed
	StatusBlocked = 3 // Blocked/Denied
	StatusOther   = 99

	// Severity IDs (OCSF standard)
	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6
)

// OCSFEvent represents an OCSF v1.1 Detection Finding event.
type OCSFEvent struct {
	Metadata    OCSFMetadata           `json:"metadata"`
	Timestamp   int64                  `json:"time"` // Unix milliseconds
	SeverityID  int                    `json:"severity_id"`
	Severity    string                 `json:"severity"`
	ClassUID    int                    `json:"class_uid"`
	CategoryUID int                    `json:"category_uid"`
	TypeUID     int                    `json:"type_uid"` // class_uid * 100 + activity_id
	ActivityID  int                    `json:"activity_id"`
	StatusID    int                    `json:"status_id"`
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	FindingInfo *OCSFFinding           `json:"finding_info,omitempty"`
	Evidences   []OCSFEvidence         `json:"evidences,omitempty"`
	Resources   []OCSFResource         `json:"resources,omitempty"`
	Unmapped    map[string]interface{} `json:"unmapped,omitempty"`
}

type OCSFMetadata struct {
	Version       string      `json:"version"`
	Product       OCSFProduct `json:"product"`
	LoggedTime    int64       `json:"logged_time"` // Unix milliseconds
	CorrelationID string      `json:"correlation_uid,omitempty"`
	EventCode     string      `json:"event_code,omitempty"`
}

type OCSFProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

type OCSFFinding struct {
	Title      string   `json:"title"`
	UID        string   `json:"uid"`
	Types      []string `json:"types,omitempty"`
	Desc       string   `json:"desc,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Severity   string   `json:"severity,omitempty"`
}

type OCSFEvidence struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type OCSFResource struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Details string `json:"data,omitempty"`
}

// MapSeverity maps a ClawShield Decision to an OCSF severity ID.
// The mapping considers both the decision outcome and the scanner type:
//   - allow decisions -> Informational (1)
//   - deny by injection/malware -> Critical (5)
//   - deny by vuln/secrets -> High (4)
//   - deny by pii -> Medium (3)
//   - deny by policy (denylist, allowlist, arg_filter, domain) -> High (4)
//   - redacted -> Medium (3)
//   - unknown -> Unknown (0)
func MapSeverity(dec *types.Decision) (int, string) {
	if dec.Decision == "allow" {
		return SeverityInformational, "Informational"
	}
	if dec.Decision == "redacted" {
		return SeverityMedium, "Medium"
	}
	// Deny decisions - severity depends on what triggered it
	if dec.Details != nil && len(dec.Details.ScanResults) > 0 {
		scanner := dec.Details.ScanResults[0].Scanner
		switch scanner {
		case "injection", "malware":
			return SeverityCritical, "Critical"
		case "vuln", "secrets":
			return SeverityHigh, "High"
		case "pii":
			return SeverityMedium, "Medium"
		}
	}
	// Fallback: use scanner_type field
	switch dec.ScannerType {
	case "injection", "malware":
		return SeverityCritical, "Critical"
	case "vuln", "secrets":
		return SeverityHigh, "High"
	case "pii", "redaction":
		return SeverityMedium, "Medium"
	}
	// Policy-level deny (denylist, allowlist, etc.)
	if dec.Decision == "deny" {
		return SeverityHigh, "High"
	}
	return SeverityUnknown, "Unknown"
}

// DecisionToOCSF converts a ClawShield Decision into an OCSF Detection Finding event.
func DecisionToOCSF(dec *types.Decision) *OCSFEvent {
	nowMs := time.Now().UnixMilli()
	timestampMs := dec.Timestamp.UnixMilli()

	severityID, severityStr := MapSeverity(dec)

	statusID := StatusSuccess
	statusStr := "Success"
	if dec.Decision == "deny" {
		statusID = StatusBlocked
		statusStr = "Blocked"
	} else if dec.Decision == "redacted" {
		statusID = StatusOther
		statusStr = "Redacted"
	}

	event := &OCSFEvent{
		Metadata: OCSFMetadata{
			Version: OCSFVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    ProductVersion,
			},
			LoggedTime:    nowMs,
			CorrelationID: dec.CorrelationID,
			EventCode:     "detection_finding",
		},
		Timestamp:   timestampMs,
		SeverityID:  severityID,
		Severity:    severityStr,
		ClassUID:    ClassUID,
		CategoryUID: CategoryUID,
		TypeUID:     ClassUID*100 + ActivityCreate,
		ActivityID:  ActivityCreate,
		StatusID:    statusID,
		Status:      statusStr,
		Message:     fmt.Sprintf("ClawShield %s: %s [tool=%s]", dec.Decision, dec.Reason, dec.Tool),
	}

	// Populate finding_info from DecisionDetail
	if dec.Details != nil && len(dec.Details.ScanResults) > 0 {
		sr := dec.Details.ScanResults[0]
		event.FindingInfo = &OCSFFinding{
			Title:      sr.Description,
			UID:        sr.RuleID,
			Types:      []string{sr.Scanner, sr.RuleID},
			Desc:       dec.Reason,
			Confidence: sr.Confidence,
			Severity:   severityStr,
		}

		// Add evidence from scan results
		var evidences []OCSFEvidence
		for _, result := range dec.Details.ScanResults {
			evidences = append(evidences, OCSFEvidence{Name: "rule_id", Value: result.RuleID})
			evidences = append(evidences, OCSFEvidence{Name: "scanner", Value: result.Scanner})
			evidences = append(evidences, OCSFEvidence{Name: "confidence", Value: result.Confidence})
			if result.MatchExcerpt != "" {
				evidences = append(evidences, OCSFEvidence{Name: "match_excerpt", Value: result.MatchExcerpt})
			}
			for k, v := range result.Metadata {
				evidences = append(evidences, OCSFEvidence{Name: k, Value: v})
			}
		}
		event.Evidences = evidences

		// Add pipeline stage and eval duration
		event.Unmapped = map[string]interface{}{
			"pipeline_stage":   dec.Details.PipelineStage,
			"eval_duration_ms": dec.Details.EvalDurationMs,
		}
		if len(dec.Details.ActiveOverrides) > 0 {
			event.Unmapped["active_overrides"] = strings.Join(dec.Details.ActiveOverrides, ", ")
		}
	} else {
		// Policy-only decision (no scanner)
		pipelineStage := ""
		if dec.Details != nil {
			pipelineStage = dec.Details.PipelineStage
		}
		if dec.Decision == "deny" {
			event.FindingInfo = &OCSFFinding{
				Title: dec.Reason,
				UID:   pipelineStage,
				Types: []string{"policy", pipelineStage},
				Desc:  dec.Reason,
			}
		}
	}

	// Add resource info
	if dec.Tool != "" {
		event.Resources = []OCSFResource{
			{Type: "tool", Name: dec.Tool},
		}
	}
	if dec.AgentName != "" {
		event.Resources = append(event.Resources, OCSFResource{Type: "agent", Name: dec.AgentName})
	}
	if dec.Source != "" {
		event.Resources = append(event.Resources, OCSFResource{Type: "source", Name: dec.Source})
	}

	return event
}

// MarshalOCSF serializes an OCSF event to JSON.
func MarshalOCSF(event *OCSFEvent) ([]byte, error) {
	return json.Marshal(event)
}
