-- ClawShield Audit Log Schema
-- SQLite-based event storage for security decisions

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    agent_version TEXT,
    node_id TEXT,
    context JSON
);

CREATE TABLE IF NOT EXISTS policy_changes (
    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_id TEXT REFERENCES sessions(session_id),
    old_policy_hash TEXT,
    new_policy_hash TEXT,
    changed_by TEXT,
    reason TEXT
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
    response_blocked INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS tool_calls (
    call_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER UNIQUE REFERENCES decisions(decision_id),
    request_json BLOB NOT NULL,  -- Full MCP request
    response_json BLOB,          -- Full MCP response (nullable if failed)
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for high-throughput querying
CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
CREATE INDEX IF NOT EXISTS idx_decisions_tool ON decisions(tool);
CREATE INDEX IF NOT EXISTS idx_decisions_decision ON decisions(decision);
CREATE INDEX IF NOT EXISTS idx_decisions_arguments_hash ON decisions(arguments_hash);
CREATE INDEX IF NOT EXISTS idx_decisions_correlation ON decisions(correlation_id);
CREATE INDEX IF NOT EXISTS idx_policy_changes_timestamp ON policy_changes(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);

-- Integrity checksum table (detect tampering)
CREATE TABLE IF NOT EXISTS integrity_checkpoints (
    checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    db_hash TEXT NOT NULL,  -- SHA-256 of entire DB state at time of checkpoint
    reason TEXT             -- e.g., "policy update", "daily rotation"
);

-- Cross-layer security events (defense-in-depth audit trail)
CREATE TABLE IF NOT EXISTS security_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,    -- e.g., "privesc", "injection_blocked", "port_scan"
    severity TEXT NOT NULL,      -- critical, high, medium, low, info
    source TEXT NOT NULL,        -- proxy, ebpf, firewall, adaptive
    session_id TEXT,
    pid INTEGER,
    tool TEXT,
    reason TEXT,
    details JSON,
    reaction TEXT                -- adaptive action taken, if any
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_source ON security_events(source);
