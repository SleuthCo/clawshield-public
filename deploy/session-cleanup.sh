#!/bin/bash
# M2: Session Isolation — hourly cleanup of ephemeral session JSONL files.
#
# OpenClaw persists conversations as JSONL files in agent session directories.
# Professional data from bridge requests should not persist on the OCI VM.
# This script deletes session files older than 1 hour.
#
# Install as a cron job:
#   echo "0 * * * * /opt/clawshield/session-cleanup.sh" | crontab -
#
# Or run via Docker entrypoint (add to Dockerfile CMD):
#   (crontab -l 2>/dev/null; echo "0 * * * * /opt/clawshield/session-cleanup.sh") | crontab -

set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
MAX_AGE_MINUTES="${SESSION_MAX_AGE_MINUTES:-60}"

# Count files before cleanup for logging
before=$(find "$OPENCLAW_HOME"/agents/*/sessions/ -name "*.jsonl" -mmin +"$MAX_AGE_MINUTES" 2>/dev/null | wc -l)

if [ "$before" -gt 0 ]; then
    find "$OPENCLAW_HOME"/agents/*/sessions/ -name "*.jsonl" -mmin +"$MAX_AGE_MINUTES" -delete 2>/dev/null
    echo "[session-cleanup] Deleted $before session files older than ${MAX_AGE_MINUTES}m"
else
    echo "[session-cleanup] No stale session files found"
fi
