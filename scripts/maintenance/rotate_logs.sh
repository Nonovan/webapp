#!/bin/bash
# Rotate and compress old log files
LOG_DIR="logs"
ARCHIVE_DIR="logs/archive"
RETENTION_DAYS=30

mkdir -p "$ARCHIVE_DIR"

# Find and compress logs older than 7 days
find "$LOG_DIR" -name "*.log.*" -type f -mtime +7 | while read logfile; do
    if [[ ! "$logfile" =~ \.gz$ ]]; then
        echo "Compressing $logfile"
        gzip "$logfile"
    fi
done

# Move compressed logs to archive
find "$LOG_DIR" -name "*.log.*.gz" -type f -mtime +14 | while read logfile; do
    filename=$(basename "$logfile")
    echo "Archiving $filename"
    mv "$logfile" "$ARCHIVE_DIR/$filename"
done

# Delete archives older than retention period
find "$ARCHIVE_DIR" -type f -mtime +$RETENTION_DAYS -delete

echo "Log rotation complete"