package api

import (
	"log"
	"net/http"

	"github.com/SleuthCo/clawshield/hub/internal/models"
)

// RegisterDashboardRoutes registers all dashboard-related routes.
func (h *Hub) RegisterDashboardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/dashboard/overview", h.HandleDashboardOverview)
	mux.HandleFunc("GET /api/v1/dashboard/security", h.HandleSecuritySummary)
}

// HandleDashboardOverview returns fleet-wide summary statistics.
// GET /api/v1/dashboard/overview
func (h *Hub) HandleDashboardOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get all agents
	agents, err := h.Store.ListAgents("", "")
	if err != nil {
		log.Printf("error listing agents: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if agents == nil {
		agents = []models.Agent{}
	}

	// Compute overview statistics
	overview := &models.DashboardOverview{
		TotalAgents:         len(agents),
		VersionDistribution: make(map[string]int),
		PolicyCompliance: models.PolicyCompliance{
			Compliant:    0,
			NonCompliant: 0,
			Unassigned:   0,
		},
	}

	for _, agent := range agents {
		// Count by health status
		switch agent.Status {
		case "healthy":
			overview.HealthyAgents++
		case "unhealthy":
			overview.UnhealthyAgents++
		case "stale":
			overview.StaleAgents++
		}

		// Track version distribution
		if agent.ClawshieldVersion != "" {
			overview.VersionDistribution[agent.ClawshieldVersion]++
		}

		// Compute policy compliance
		if agent.PolicyGroupID == "" {
			overview.PolicyCompliance.Unassigned++
		} else {
			// Get the policy group to check current version
			group, err := h.Store.GetPolicyGroup(agent.PolicyGroupID)
			if err != nil {
				log.Printf("error getting policy group %s: %v", agent.PolicyGroupID, err)
				continue
			}

			if group == nil {
				overview.PolicyCompliance.Unassigned++
				continue
			}

			// Get the current policy version for the group
			if group.CurrentPolicyVersionID == "" {
				overview.PolicyCompliance.Unassigned++
			} else {
				policyVersion, err := h.Store.GetPolicyVersion(group.CurrentPolicyVersionID)
				if err != nil {
					log.Printf("error getting policy version: %v", err)
					overview.PolicyCompliance.NonCompliant++
					continue
				}

				if policyVersion == nil {
					overview.PolicyCompliance.NonCompliant++
				} else if agent.PolicyHash == policyVersion.PolicyHash {
					overview.PolicyCompliance.Compliant++
				} else {
					overview.PolicyCompliance.NonCompliant++
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, overview)
}

// HandleSecuritySummary returns aggregated security metrics across the fleet.
// GET /api/v1/dashboard/security
func (h *Hub) HandleSecuritySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	summary, err := h.Store.GetAggregatedMetrics()
	if err != nil {
		log.Printf("error getting aggregated metrics: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if summary == nil {
		summary = &models.SecuritySummary{
			ScannerDetections: make(map[string]int64),
		}
	}

	writeJSON(w, http.StatusOK, summary)
}
