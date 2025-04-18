#!/bin/bash
# Archive audit logs to secure storage

APP_ROOT="/opt/cloud-platform"
LOG_DIR="/var/log/cloud-platform"
ARCHIVE_DIR="/secure/archives/audit"
RETENTION_DAYS=365
DATE=$(date +%Y%m%d)

# Ensure directories exist
mkdir -p "$ARCHIVE_DIR"

cd "$APP_ROOT" || exit 1

# Export audit logs from database
echo "Exporting audit logs from database..."
FLASK_APP=app.py flask audit-logs export --days=7 --output="$LOG_DIR/audit_export_$DATE.json"

# Compress the export
echo "Compressing audit logs..."
gzip -9 "$LOG_DIR/audit_export_$DATE.json"

# Move to archive with timestamp
echo "Moving to secure archive..."
mv "$LOG_DIR/audit_export_$DATE.json.gz" "$ARCHIVE_DIR/audit_$DATE.json.gz"

# Set appropriate permissions
chmod 600 "$ARCHIVE_DIR/audit_$DATE.json.gz"

# Remove old archives based on retention policy
find "$ARCHIVE_DIR" -name "audit_*.json.gz" -type f -mtime +$RETENTION_DAYS -delete

echo "Audit log archival complete"
