#!/bin/bash
# Database backup script
BACKUP_DIR="/var/backups/cloud-platform"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "Creating database backup..."
flask db backup --dir="$BACKUP_DIR" --compress

# Rotate old backups (keep last 7 days)
find "$BACKUP_DIR" -name "backup_*.sql.gz" -type f -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR/backup_$TIMESTAMP.sql.gz"