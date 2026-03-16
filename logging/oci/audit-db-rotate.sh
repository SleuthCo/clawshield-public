#!/bin/bash
# ClawShield Audit DB rotation — exports old records, vacuums
# Run via cron: 0 3 * * * /opt/clawshield/logging/oci/audit-db-rotate.sh
set -euo pipefail

LOG_DIR="/var/log/clawshield"
EXPORT_DIR="${LOG_DIR}/audit-exports"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d)

mkdir -p "$EXPORT_DIR"

# Find audit.db — check known locations
find_audit_db() {
    # Standalone compose project
    local standalone="/var/lib/docker/volumes/standalone_audit-data/_data/audit.db"
    [ -f "$standalone" ] && echo "$standalone" && return

    # Deploy compose project
    local deploy="/var/lib/docker/volumes/deploy_clawshield-audit/_data/audit.db"
    [ -f "$deploy" ] && echo "$deploy" && return

    # Search Docker volumes
    local found
    found=$(find /var/lib/docker/volumes -name "audit.db" -path "*/clawshield*" 2>/dev/null | head -1)
    [ -n "$found" ] && echo "$found" && return

    # Direct bind mount
    [ -f "/var/lib/clawshield/audit.db" ] && echo "/var/lib/clawshield/audit.db" && return

    echo ""
}

AUDIT_DB=$(find_audit_db)
if [ -z "$AUDIT_DB" ]; then
    echo "[$(date -Iseconds)] ERROR: audit.db not found" | tee -a "$LOG_DIR/audit-rotate.log"
    exit 1
fi

echo "[$(date -Iseconds)] Rotating audit DB: $AUDIT_DB" | tee -a "$LOG_DIR/audit-rotate.log"

# Count records to export
EXPORT_COUNT=$(sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM decisions WHERE timestamp < datetime('now', '-${RETENTION_DAYS} days');")

if [ "$EXPORT_COUNT" -eq 0 ]; then
    echo "[$(date -Iseconds)] No records older than ${RETENTION_DAYS} days to export" | tee -a "$LOG_DIR/audit-rotate.log"
    exit 0
fi

# Export to JSONL
EXPORT_FILE="${EXPORT_DIR}/audit-export-${DATE}.jsonl"
sqlite3 "$AUDIT_DB" <<SQL > "$EXPORT_FILE"
.mode json
SELECT decision_id, datetime(timestamp) as timestamp, session_id, tool,
       arguments_hash, decision, reason, policy_version, scanner_type,
       correlation_id, classification, source, response_blocked,
       trace_id, span_id, parent_span_id
FROM decisions
WHERE timestamp < datetime('now', '-${RETENTION_DAYS} days')
ORDER BY decision_id;
SQL

# Verify export
EXPORTED_LINES=$(wc -l < "$EXPORT_FILE")
echo "[$(date -Iseconds)] Exported $EXPORT_COUNT records ($EXPORTED_LINES lines) to $EXPORT_FILE" | tee -a "$LOG_DIR/audit-rotate.log"

# Delete exported records
sqlite3 "$AUDIT_DB" "DELETE FROM decisions WHERE timestamp < datetime('now', '-${RETENTION_DAYS} days');"

# Vacuum to reclaim space
sqlite3 "$AUDIT_DB" "VACUUM;"

REMAINING=$(sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM decisions;")
echo "[$(date -Iseconds)] Remaining records: $REMAINING" | tee -a "$LOG_DIR/audit-rotate.log"

# Compress old exports (older than 1 day)
find "$EXPORT_DIR" -name "audit-export-*.jsonl" -mtime +1 ! -name "*.gz" -exec gzip {} \;

echo "[$(date -Iseconds)] Audit DB rotation complete" | tee -a "$LOG_DIR/audit-rotate.log"
