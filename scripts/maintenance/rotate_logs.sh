#!/bin/bash
# Rotate and archive application logs
# Usage: ./rotate_logs.sh [days_to_keep]

set -e

# Default to keep 30 days of logs if not specified
DAYS_TO_KEEP=${1:-30}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="/var/log/cloud-platform"
ARCHIVE_DIR="${LOG_DIR}/archive"
DATE_SUFFIX=$(date +"%Y%m%d")

# Ensure directories exist
mkdir -p "$LOG_DIR"
mkdir -p "$ARCHIVE_DIR"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${LOG_DIR}/rotation.log"
}

log "Starting log rotation process"
log "Keeping logs for $DAYS_TO_KEEP days"

# List of log files to rotate
LOG_FILES=(
    "app.log"
    "error.log"
    "access.log"
    "auth.log"
    "security.log"
    "api.log"
    "debug.log"
)

# Rotate each log file
for log_file in "${LOG_FILES[@]}"; do
    if [ -f "${LOG_DIR}/${log_file}" ]; then
        log "Rotating ${log_file}"
        
        # Compress the log file
        gzip -c "${LOG_DIR}/${log_file}" > "${ARCHIVE_DIR}/${log_file}.${DATE_SUFFIX}.gz"
        
        # Check if compression was successful
        if [ $? -eq 0 ]; then
            # Clear the original log file
            cat /dev/null > "${LOG_DIR}/${log_file}"
            log "Successfully rotated ${log_file}"
        else
            log "ERROR: Failed to compress ${log_file}"
        fi
    else
        log "NOTICE: ${log_file} does not exist, skipping"
    fi
done

# Clean up old log archives
log "Cleaning up log archives older than ${DAYS_TO_KEEP} days"
find "$ARCHIVE_DIR" -name "*.gz" -type f -mtime +${DAYS_TO_KEEP} -delete

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