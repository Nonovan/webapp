#!/bin/bash
# Rotate and compress log files for Cloud Infrastructure Platform
# Usage: ./scripts/rotate_logs.sh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="/var/log/cloud-platform"
ARCHIVE_DIR="${LOG_DIR}/archive"
RETENTION_DAYS=30

# Ensure directories exist
mkdir -p "$LOG_DIR"
mkdir -p "$ARCHIVE_DIR"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

log "Starting log rotation process"

# Find and compress logs older than 7 days but not already compressed
find "$LOG_DIR" -name "*.log.*" -type f -mtime +7 | grep -v '\.gz$' | while read logfile; do
    log "Compressing $logfile"
    gzip -9 "$logfile"
done

# Move compressed logs older than 14 days to archive
find "$LOG_DIR" -name "*.log.*.gz" -type f -mtime +14 | while read logfile; do
    filename=$(basename "$logfile")
    log "Archiving $filename"
    mv "$logfile" "$ARCHIVE_DIR/$filename"
done

# Delete archives older than retention period
log "Removing logs older than $RETENTION_DAYS days"
find "$ARCHIVE_DIR" -type f -mtime +$RETENTION_DAYS -delete

# Rotate current logs if they are too large (>100MB)
for logfile in $(find "$LOG_DIR" -maxdepth 1 -name "*.log" -size +100M); do
    filename=$(basename "$logfile")
    datestamp=$(date +%Y%m%d-%H%M%S)
    log "Rotating large log file: $filename"
    mv "$logfile" "${logfile}.${datestamp}"
    
    # Signal the application to create a new log file
    if [[ "$filename" == "app.log" ]] && command -v systemctl &>/dev/null; then
        systemctl kill -s SIGUSR1 cloud-platform.service
    fi
done

# Ensure proper permissions on log files
log "Setting proper permissions on log files"
find "$LOG_DIR" -type f -exec chmod 640 {} \;
find "$LOG_DIR" -type d -exec chmod 750 {} \;

# Update log summary statistics
LOG_STATS_FILE="${LOG_DIR}/log_stats.txt"
log "Updating log statistics"
echo "Log statistics as of $(date)" > "$LOG_STATS_FILE"
echo "---------------------------" >> "$LOG_STATS_FILE"
echo "Current logs:" >> "$LOG_STATS_FILE"
du -sh "$LOG_DIR"/*.log 2>/dev/null | sort -hr >> "$LOG_STATS_FILE"
echo -e "\nArchived logs:" >> "$LOG_STATS_FILE"
du -sh "$ARCHIVE_DIR" 2>/dev/null >> "$LOG_STATS_FILE"
echo -e "\nTotal log count:" >> "$LOG_STATS_FILE"
find "$LOG_DIR" "$ARCHIVE_DIR" -type f | wc -l >> "$LOG_STATS_FILE"

log "Log rotation complete"