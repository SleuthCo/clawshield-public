package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/hashlined"
	"github.com/SleuthCo/clawshield/proxy/internal/audit/sqlite"
	"github.com/SleuthCo/clawshield/proxy/internal/config"
	"github.com/SleuthCo/clawshield/proxy/internal/engine"
	"github.com/SleuthCo/clawshield/proxy/internal/siem"
	"github.com/SleuthCo/clawshield/shared/bus"
	"github.com/SleuthCo/clawshield/shared/types"
)

func main() {
	policyPath := flag.String("policy", os.Getenv("CLAWSHIELD_POLICY"), "Path to policy YAML file")
	mcpServer := flag.String("mcp-server", os.Getenv("CLAWSHIELD_MCP_SERVER"), "Path to MCP server binary (stdio mode)")
	auditDB := flag.String("audit-db", os.Getenv("CLAWSHIELD_AUDIT_DB"), "Path to audit SQLite database")

	// Gateway proxy mode flags
	gatewayURL := flag.String("gateway-url", os.Getenv("CLAWSHIELD_GATEWAY_URL"), "URL of upstream gateway (HTTP proxy mode)")
	gatewayToken := flag.String("gateway-token", os.Getenv("CLAWSHIELD_GATEWAY_TOKEN"), "Auth token for upstream gateway")
	studioToken := flag.String("studio-token", os.Getenv("CLAWSHIELD_STUDIO_TOKEN"), "HMAC signing key for Studio deep-link tickets (same as STUDIO_ACCESS_TOKEN)")
	listenAddr := flag.String("listen", os.Getenv("CLAWSHIELD_LISTEN"), "Listen address for HTTP proxy mode (default :18789)")
	standalone := flag.Bool("standalone", os.Getenv("CLAWSHIELD_STANDALONE") == "true", "Standalone mode: serve dashboard UI, skip audit auth")
	controlUIDir := flag.String("control-ui-dir", os.Getenv("CLAWSHIELD_CONTROL_UI_DIR"), "Path to Control UI assets directory (standalone mode)")

	flag.Parse()

	if *policyPath == "" {
		*policyPath = "./policy/dev_default.yaml"
	}

	// Determine mode: gateway (HTTP proxy) vs stdio (MCP proxy)
	gatewayMode := *gatewayURL != ""
	stdioMode := *mcpServer != ""

	if !gatewayMode && !stdioMode {
		log.Fatal("Either --mcp-server (stdio mode) or --gateway-url (HTTP proxy mode) is required")
	}
	if gatewayMode && stdioMode {
		log.Fatal("Cannot use both --mcp-server and --gateway-url — choose one mode")
	}

	// Resolve policy path
	var fullPolicyPath string
	if filepath.IsAbs(*policyPath) {
		fullPolicyPath = *policyPath
	} else {
		exeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatal(err)
		}
		fullPolicyPath = filepath.Join(exeDir, *policyPath)
	}

	// Load policy configuration
	cfg, err := config.Load(fullPolicyPath)
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	evaluator := engine.NewEvaluator(cfg)

	// Initialize audit writer if DB path provided
	auditWriter, auditDB2 := initAudit(*auditDB)
	if auditDB2 != nil {
		defer auditDB2.Close()
	}
	if auditWriter != nil {
		defer auditWriter.Close()
	}

	// Initialize SIEM forwarder if configured
	if cfg.SIEM != nil && cfg.SIEM.Enabled && auditWriter != nil {
		siemCfg := &siem.SIEMConfig{
			Enabled:           cfg.SIEM.Enabled,
			MinSeverity:       cfg.SIEM.MinSeverity,
			Transport:         cfg.SIEM.Transport,
			SyslogAddress:     cfg.SIEM.SyslogAddress,
			SyslogTLS:         cfg.SIEM.SyslogTLS,
			SyslogCertFile:    cfg.SIEM.SyslogCertFile,
			SyslogKeyFile:     cfg.SIEM.SyslogKeyFile,
			WebhookURL:        cfg.SIEM.WebhookURL,
			WebhookAuthHeader: cfg.SIEM.WebhookAuthHeader,
			WebhookTimeoutMs:  cfg.SIEM.WebhookTimeoutMs,
			QueueSize:         cfg.SIEM.QueueSize,
		}
		forwarder, err := siem.NewForwarderFromConfig(siemCfg)
		if err != nil {
			log.Fatalf("Failed to initialize SIEM forwarder: %v", err)
		}
		auditWriter.SetSIEMForwarder(forwarder)
		defer forwarder.Close()
		log.Printf("SIEM forwarder enabled: transport=%s min_severity=%d", cfg.SIEM.Transport, cfg.SIEM.MinSeverity)
	}

	// Generate cryptographically random session ID
	sessionID := generateSessionID()

	if gatewayMode {
		// HTTP/WebSocket reverse proxy mode
		if *listenAddr == "" {
			*listenAddr = ":18789"
		}
		log.Println("Starting in HTTP proxy mode")

		// Initialize cross-layer event bus
		eventBus := bus.New()

		// Start Unix socket listener for external event producers (eBPF, firewall)
		socketPath := bus.DefaultSocketPath
		if cfg.Adaptive != nil && cfg.Adaptive.SocketPath != "" {
			socketPath = cfg.Adaptive.SocketPath
		}
		socketListener := bus.NewSocketListener(socketPath, eventBus)
		if err := socketListener.Start(); err != nil {
			log.Printf("WARNING: failed to start event socket listener: %v (cross-layer events disabled)", err)
		}

		// Initialize adaptive controller if enabled in policy
		var adaptiveCtrl *bus.AdaptiveController
		if cfg.Adaptive != nil && cfg.Adaptive.Enabled {
			adaptiveCtrl = bus.NewAdaptiveController(eventBus, cfg.Adaptive.Rules)

			// Wire adaptive callbacks to the evaluator
			adaptiveCtrl.OnElevateSensitivity = func(level string, duration time.Duration) {
				evaluator.SetSensitivityOverride(level, time.Now().Add(duration))
				log.Printf("ADAPTIVE: injection sensitivity elevated to %s for %s", level, duration)
			}
			adaptiveCtrl.OnElevateDefaultDeny = func(duration time.Duration) {
				evaluator.SetDefaultActionOverride("deny", time.Now().Add(duration))
				log.Printf("ADAPTIVE: default action overridden to deny for %s", duration)
			}

			adaptiveCtrl.Start()
			log.Printf("Adaptive controller enabled with %d rules", len(cfg.Adaptive.Rules))
		}

		// Graceful shutdown on signal
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sigCh
			log.Println("Received shutdown signal, closing...")
			if adaptiveCtrl != nil {
				adaptiveCtrl.Stop()
			}
			socketListener.Stop()
			eventBus.Close()
			if auditWriter != nil {
				auditWriter.Close()
			}
			os.Exit(0)
		}()

		if err := runHTTPProxy(cfg, evaluator, auditWriter, auditDB2, *gatewayURL, *gatewayToken, *studioToken, *listenAddr, sessionID, *standalone, *controlUIDir, eventBus); err != nil {
			log.Fatalf("HTTP proxy error: %v", err)
		}
	} else {
		// Existing stdio MCP proxy mode
		runStdioProxy(cfg, evaluator, auditWriter, *mcpServer, sessionID)
	}
}

// runStdioProxy runs the original stdio-based MCP proxy mode.
func runStdioProxy(cfg *engine.Policy, evaluator *engine.Evaluator, auditWriter *sqlite.Writer,
	mcpServer string, sessionID string) {

	// Validate MCP server binary
	if err := validateBinary(mcpServer); err != nil {
		log.Fatalf("MCP server binary validation failed: %v", err)
	}

	timeoutMs := 100
	if cfg.EvaluationTimeoutMs > 0 {
		timeoutMs = cfg.EvaluationTimeoutMs
	}
	timeoutDuration := time.Duration(timeoutMs) * time.Millisecond

	maxBytes := cfg.MaxMessageBytes
	if maxBytes <= 0 {
		maxBytes = 1048576
	}

	// Start MCP server as child process with cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, mcpServer)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	log.Printf("MCP server started: %s (PID %d)", mcpServer, cmd.Process.Pid)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("Received shutdown signal, closing...")
		cancel()
		if auditWriter != nil {
			auditWriter.Close()
		}
	}()

	// Intercept stdin: Agent -> MCP Server
	go func() {
		defer stdinPipe.Close()

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, int(maxBytes)), int(maxBytes))

		for scanner.Scan() {
			line := scanner.Bytes()
			if int64(len(line)) > maxBytes {
				log.Printf("BLOCKED: message exceeds max size (%d > %d bytes)", len(line), maxBytes)
				continue
			}

			var msg json.RawMessage
			if err := json.Unmarshal(line, &msg); err != nil {
				log.Printf("Error decoding JSON from stdin: %v", err)
				continue
			}

			s := []byte(msg)

			evalCtx, evalCancel := context.WithTimeout(ctx, timeoutDuration)
			decision, reason := evaluator.EvaluateWithContext(evalCtx, string(s))
			evalCancel()

			var rpc struct {
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			_ = json.Unmarshal(s, &rpc)
			method := rpc.Method
			if method == "" {
				method = "<unknown>"
			}

			// Audit log - hash params ONCE here; writer stores directly
			if auditWriter != nil {
				paramsStr := string(rpc.Params)
				argsHash := paramsStr
				if h, err := hashlined.HashArguments(paramsStr); err == nil {
					argsHash = h
				}
				// Determine scanner type from reason prefix
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
					SessionID:     sessionID,
					Tool:          method,
					ArgumentsHash: argsHash,
					Decision:      decision,
					Reason:        reason,
					PolicyVersion: "1.0",
					ScannerType:   scanType,
				}
				if err := auditWriter.Write(&auditDec); err != nil {
					log.Printf("Audit write error: %v", err)
				}
			}

			if decision == engine.Deny {
				log.Printf("BLOCKED: method=%s reason=%s", method, reason)
				continue
			}

			log.Printf("ALLOWED: method=%s", method)
			if _, err := stdinPipe.Write(line); err != nil {
				log.Printf("Error writing to MCP server: %v", err)
				return
			}
			if _, err := stdinPipe.Write([]byte{'\n'}); err != nil {
				log.Printf("Error writing newline to MCP server: %v", err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading from stdin: %v", err)
		}
	}()

	// Intercept stdout: MCP Server -> Agent (now with response scanning + auditing)
	go func() {
		defer stdoutPipe.Close()
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, int(maxBytes)), int(maxBytes))
		for scanner.Scan() {
			line := scanner.Bytes()

			var rpc struct {
				ID     interface{} `json:"id"`
				Method string      `json:"method"`
			}
			_ = json.Unmarshal(line, &rpc)
			respMethod := rpc.Method
			if respMethod == "" {
				respMethod = "<response>"
			}

			// Response scanning: prompt injection + malware detection
			respDecision := "allow"
			respReason := "mcp server response"
			scannerType := ""
			if evaluator.InjectionDetector() != nil || evaluator.MalwareScanner() != nil || evaluator.SecretsScanner() != nil || evaluator.PIIScanner() != nil {
				evalCtx, evalCancel := context.WithTimeout(ctx, timeoutDuration)
				respResult := evaluator.EvaluateResponse(evalCtx, respMethod, string(line))
				evalCancel()
				respDecision = respResult.Decision
				respReason = respResult.Reason
				if respResult.Decision == engine.Deny {
					if len(respResult.Reason) > 0 {
						if respResult.Reason[0] == 'p' { // prompt_injection*
							scannerType = "injection"
						} else if respResult.Reason[0] == 'm' { // malware_scan*
							scannerType = "malware"
						} else if respResult.Reason[0] == 's' { // secrets_scan*
							scannerType = "secrets"
						}
					}
				} else if respResult.WasRedacted {
					line = []byte(respResult.RedactedBody)
					scannerType = "redaction"
					log.Printf("REDACTED RESPONSE: method=%s reason=%s", respMethod, respResult.Reason)
				}
			}

			// Audit log
			if auditWriter != nil {
				auditDec := types.Decision{
					Timestamp:     time.Now(),
					SessionID:     sessionID,
					Tool:          respMethod,
					ArgumentsHash: fmt.Sprintf("response_size=%d", len(line)),
					Decision:      respDecision,
					Reason:        respReason,
					PolicyVersion: "1.0",
					ScannerType:   scannerType,
				}
				if err := auditWriter.Write(&auditDec); err != nil {
					log.Printf("SECURITY WARNING: audit write failed for stdio response: %v", err)
				}
			}

			if respDecision == engine.Deny {
				log.Printf("BLOCKED RESPONSE: method=%s reason=%s", respMethod, respReason)
				continue
			}

			if _, err := os.Stdout.Write(line); err != nil {
				log.Printf("Error writing to stdout: %v", err)
				return
			}
			if _, err := os.Stdout.Write([]byte{'\n'}); err != nil {
				log.Printf("Error writing to stdout: %v", err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading from MCP server: %v", err)
		}
	}()

	if err := cmd.Wait(); err != nil {
		log.Printf("MCP server exited with error: %v", err)
	}
	fmt.Println("ClawShield Proxy shutting down.")
}

// initAudit creates the audit SQLite writer if a DB path is provided.
func initAudit(auditDBPath string) (*sqlite.Writer, *sql.DB) {
	if auditDBPath == "" {
		return nil, nil
	}

	db, err := sql.Open("sqlite3", auditDBPath+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		log.Fatalf("Failed to open audit database: %v", err)
	}

	schemaSQL := `
	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		end_time TIMESTAMP,
		agent_version TEXT,
		node_id TEXT,
		context JSON
	);
	CREATE TABLE IF NOT EXISTS decisions (
		decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		session_id TEXT REFERENCES sessions(session_id),
		tool TEXT NOT NULL,
		arguments_hash TEXT NOT NULL,
		decision TEXT CHECK(decision IN ('allow', 'deny', 'redacted')) NOT NULL,
		reason TEXT,
		policy_version TEXT,
		scanner_type TEXT,
		correlation_id TEXT,
		classification TEXT,
		source TEXT,
		response_blocked INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS integrity_checkpoints (
		checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		db_hash TEXT NOT NULL,
		reason TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
	CREATE INDEX IF NOT EXISTS idx_decisions_tool ON decisions(tool);
	`
	if _, err := db.Exec(schemaSQL); err != nil {
		log.Fatalf("Failed to initialize audit schema: %v", err)
	}

	// Add security_events table for cross-layer event audit trail
	securityEventsSchema := `
	CREATE TABLE IF NOT EXISTS security_events (
		event_id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		event_type TEXT NOT NULL,
		severity TEXT NOT NULL,
		source TEXT NOT NULL,
		session_id TEXT,
		pid INTEGER,
		tool TEXT,
		reason TEXT,
		details JSON,
		reaction TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_security_events_source ON security_events(source);
	`
	if _, err := db.Exec(securityEventsSchema); err != nil {
		log.Printf("Security events schema warning: %v", err)
	}

	// Migrate: add columns if they don't exist (ALTER TABLE ADD COLUMN is safe in SQLite)
	migrations := []string{
		"ALTER TABLE decisions ADD COLUMN correlation_id TEXT",
		"ALTER TABLE decisions ADD COLUMN classification TEXT",
		"ALTER TABLE decisions ADD COLUMN source TEXT",
		"ALTER TABLE decisions ADD COLUMN response_blocked INTEGER DEFAULT 0",
		"ALTER TABLE decisions ADD COLUMN agent_name TEXT",
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			// "duplicate column name" means already migrated — ignore
			if !strings.Contains(err.Error(), "duplicate column") {
				log.Printf("Migration warning: %v", err)
			}
		}
	}
	// Now safe to create index on correlation_id
	db.Exec("CREATE INDEX IF NOT EXISTS idx_decisions_correlation ON decisions(correlation_id)")

	writer, err := sqlite.NewWriterWithPath(db, auditDBPath)
	if err != nil {
		log.Fatalf("Failed to create audit writer: %v", err)
	}
	log.Println("Audit logging enabled:", auditDBPath)

	return writer, db
}

// validateBinary checks the MCP server binary exists, is a regular file,
// and has appropriate permissions.
func validateBinary(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("MCP server path must be absolute, got: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}
	// Check not world-writable
	if info.Mode()&0002 != 0 {
		return fmt.Errorf("binary is world-writable (insecure): %s", path)
	}
	return nil
}

// generateSessionID creates a cryptographically random session ID.
// SECURITY: Refuses to start with a predictable session ID if crypto/rand fails.
func generateSessionID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		log.Fatalf("FATAL: crypto/rand failed — refusing to generate insecure session ID: %v", err)
	}
	return fmt.Sprintf("session-%x", buf)
}
