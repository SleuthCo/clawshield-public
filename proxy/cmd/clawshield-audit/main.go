// Command clawshield-audit provides a CLI for querying ClawShield audit logs.
package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/spf13/cobra"
	_ "github.com/mattn/go-sqlite3"
)

var (
	dbPath     string
	format     string
	fromTime   string
	toTime     string
	decision   string
	tool       string
	hashPrefix string
	includeCall bool
	limit      int
)

func main() {
	cmd := &cobra.Command{
		Use:   "clawshield-audit",
		Short: "Query ClawShield audit logs",
		Long:  "Search and export audit logs from SQLite database.",
	}

	cmd.PersistentFlags().StringVar(&dbPath, "db", "/var/lib/clawshield/audit.db", "path to SQLite database")
	cmd.PersistentFlags().StringVar(&format, "format", "human", "output format: human, json, csv")
	cmd.PersistentFlags().StringVar(&fromTime, "from", "", "start time (RFC3339)")
	cmd.PersistentFlags().StringVar(&toTime, "to", "", "end time (RFC3339)")
	cmd.PersistentFlags().StringVar(&decision, "decision", "", "filter by decision: allow, deny, redacted")
	cmd.PersistentFlags().StringVar(&tool, "tool", "", "filter by tool name (partial match)")
	cmd.PersistentFlags().StringVar(&hashPrefix, "hash-prefix", "", "filter by argument hash prefix")
	cmd.PersistentFlags().BoolVar(&includeCall, "with-call", false, "include full tool call request/response")
	cmd.PersistentFlags().IntVar(&limit, "limit", 100, "maximum number of results")

	cmd.RunE = run

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	r := sqlite.NewReader(db)

	var from, to time.Time
	if fromTime != "" {
		from, err = time.Parse(time.RFC3339, fromTime)
		if err != nil {
			return fmt.Errorf("parse from time: %w", err)
		}
	}
	if toTime != "" {
		to, err = time.Parse(time.RFC3339, toTime)
		if err != nil {
			return fmt.Errorf("parse to time: %w", err)
		}
	}

	opts := []sqlite.QueryOption{
		sqlite.WithTimeRange(from, to),
	}
	if decision != "" {
		opts = append(opts, sqlite.WithDecision(decision))
	}
	if tool != "" {
		opts = append(opts, sqlite.WithTool(tool))
	}
	if hashPrefix != "" {
		opts = append(opts, sqlite.WithArgumentsHashPrefix(hashPrefix))
	}
	if includeCall {
		opts = append(opts, sqlite.WithIncludeToolCall())
	}

	ctx := context.Background()
	logs, err := r.QueryDecisions(ctx, opts...)
	if err != nil {
		return fmt.Errorf("query decisions: %w", err)
	}

	// Apply limit
	if limit > 0 && len(logs) > limit {
		logs = logs[:limit]
	}

	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(logs)
	case "csv":
		w := csv.NewWriter(os.Stdout)
		defer w.Flush()

		headers := []string{"decision_id", "timestamp", "session_id", "tool", "arguments_hash", "decision", "reason", "policy_version"}
		if includeCall {
			headers = append(headers, "request_json", "response_json")
		}
		w.Write(headers)

		for _, log := range logs {
			row := []string{
				strconv.FormatInt(log.Decision.DecisionID, 10),
				log.Decision.Timestamp.Format(time.RFC3339),
				log.Decision.SessionID,
				log.Decision.Tool,
				log.Decision.ArgumentsHash,
				log.Decision.Decision,
				log.Decision.Reason,
				log.Decision.PolicyVersion,
			}
			if includeCall && log.ToolCall != nil {
				row = append(row, string(log.ToolCall.RequestJSON))
				if len(log.ToolCall.ResponseJSON) > 0 {
					row = append(row, string(log.ToolCall.ResponseJSON))
				} else {
					row = append(row, "")
				}
			}
			w.Write(row)
		}

	case "human":
		for _, log := range logs {
			fmt.Printf("=== Decision #%d ===\n", log.Decision.DecisionID)
			fmt.Printf("Time: %s\n", log.Decision.Timestamp.Format(time.RFC3339))
			fmt.Printf("Session: %s\n", log.Decision.SessionID)
			fmt.Printf("Tool: %s\n", log.Decision.Tool)
			fmt.Printf("Args Hash: %s\n", log.Decision.ArgumentsHash)
			fmt.Printf("Decision: %s\n", log.Decision.Decision)
			if log.Decision.Reason != "" {
				fmt.Printf("Reason: %s\n", log.Decision.Reason)
			}
			if log.Decision.PolicyVersion != "" {
				fmt.Printf("Policy: v%s\n", log.Decision.PolicyVersion)
			}
			if includeCall && log.ToolCall != nil {
				fmt.Printf("Request: %s\n", string(log.ToolCall.RequestJSON))
				if len(log.ToolCall.ResponseJSON) > 0 {
					fmt.Printf("Response: %s\n", string(log.ToolCall.ResponseJSON))
				}
			}
			fmt.Println()
		}

	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	return nil
}