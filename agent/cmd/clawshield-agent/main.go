package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/SleuthCo/clawshield/agent/internal/checkin"
	"github.com/SleuthCo/clawshield/agent/internal/collector"
	"github.com/SleuthCo/clawshield/shared/models"
)

func main() {
	// Define command-line flags
	hubURL := flag.String("hub-url", "", "URL of the ClawShield Management Hub (required)")
	enrollmentToken := flag.String("enrollment-token", "", "Enrollment token for first-time registration")
	proxyURL := flag.String("proxy-url", "http://localhost:18789", "URL of the local ClawShield proxy")
	auditDBPath := flag.String("audit-db-path", "/var/lib/clawshield/audit.db", "Path to the audit database file")
	checkinInterval := flag.Duration("checkin-interval", 60*time.Second, "Interval between check-ins to the Hub")
	agentIDFile := flag.String("agent-id-file", "/var/lib/clawshield/agent-id", "File to store the agent ID")

	flag.Parse()

	// Validate required flags
	if *hubURL == "" {
		log.Fatal("--hub-url is required")
	}

	// Ensure directory for agent ID file exists
	agentIDDir := filepath.Dir(*agentIDFile)
	if agentIDDir != "." && agentIDDir != "" {
		if err := os.MkdirAll(agentIDDir, 0755); err != nil {
			log.Fatalf("failed to create directory for agent ID file: %v", err)
		}
	}

	// Get or create agent ID
	agentID, err := getOrEnrollAgent(*hubURL, *enrollmentToken, *agentIDFile)
	if err != nil {
		log.Fatalf("failed to get or create agent ID: %v", err)
	}

	log.Printf("Agent ID: %s", agentID)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create collector and client
	coll := collector.NewCollector(*proxyURL, *auditDBPath)
	hubClient := checkin.NewClient(*hubURL)

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Main check-in loop
	ticker := time.NewTicker(*checkinInterval)
	defer ticker.Stop()

	log.Printf("Starting check-in loop with interval %v", *checkinInterval)

	for {
		select {
		case <-sigChan:
			log.Println("Received shutdown signal, exiting gracefully")
			return

		case <-ticker.C:
			// Collect status
			status := coll.Collect()

			// Build check-in request
			health := models.AgentHealth{
				Status:           "healthy",
				AuditDBSizeBytes: status.AuditDBSize,
				QueueDepth:       0,
			}

			req := &models.CheckinRequest{
				AgentID:           agentID,
				Hostname:          hostname,
				ClawshieldVersion: "1.0.0", // TODO: get from actual proxy
				AgentVersion:      "1.0.0", // TODO: get from actual agent version
				Health:            health,
			}

			// Add proxy status fields if available
			if status.ProxyStatus != nil {
				req.PolicyHash = status.ProxyStatus.PolicyHash
				req.PolicyVersion = status.ProxyStatus.PolicyVersion
				req.UptimeSeconds = status.ProxyStatus.Uptime
			}

			// Check in with Hub
			resp, err := hubClient.Checkin(req)
			if err != nil {
				log.Printf("check-in failed: %v", err)
				continue
			}

			log.Printf("check-in successful: actions=%d, next_checkin=%d seconds", len(resp.Actions), resp.NextCheckinSeconds)

			// Log actions
			for _, action := range resp.Actions {
				log.Printf("  action: type=%s", action.Type)
			}

			// TODO: Phase 2 - apply actions
		}
	}
}

// getOrEnrollAgent checks if an agent ID file exists, and if not, enrolls with the Hub.
func getOrEnrollAgent(hubURL, enrollmentToken, agentIDFile string) (string, error) {
	// Try to read existing agent ID
	if data, err := os.ReadFile(agentIDFile); err == nil {
		agentID := string(data)
		log.Printf("Using existing agent ID from %s", agentIDFile)
		return agentID, nil
	}

	// Need to enroll
	if enrollmentToken == "" {
		return "", fmt.Errorf("agent ID not found in %s and no --enrollment-token provided for enrollment", agentIDFile)
	}

	log.Println("Enrolling with Hub...")

	// Get hostname for enrollment
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Call Hub enrollment endpoint
	hubClient := checkin.NewClient(hubURL)
	resp, err := hubClient.Enroll(enrollmentToken, hostname, []string{})
	if err != nil {
		return "", fmt.Errorf("enrollment failed: %w", err)
	}

	// Save agent ID to file
	if err := os.WriteFile(agentIDFile, []byte(resp.AgentID), 0600); err != nil {
		return "", fmt.Errorf("failed to save agent ID to %s: %w", agentIDFile, err)
	}

	log.Printf("Successfully enrolled, agent ID: %s", resp.AgentID)
	return resp.AgentID, nil
}
