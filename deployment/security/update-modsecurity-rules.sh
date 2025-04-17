#!/bin/bash
# Update ModSecurity Core Rule Set (CRS) for Cloud Infrastructure Platform

# Configuration
CRS_REPO="<https://github.com/coreruleset/coreruleset.git>"
CRS_DIR="/etc/nginx/modsecurity-crs"
BACKUP_DIR="/var/backups/modsecurity-crs"
LOG_FILE="/var/log/cloud-platform/modsec-update.log"

# Ensure log directory exists
mkdir -p $(dirname "$LOG_FILE")
mkdir -p "$BACKUP_DIR"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Check if git is installed
if ! command -v git &> /dev/null; then
    log "ERROR: Git is not installed. Please install it first."
    exit 1
fi

log "Starting ModSecurity CRS update process"

# Create backup of current rules
if [ -d "$CRS_DIR" ]; then
    backup_file="$BACKUP_DIR/crs-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    log "Creating backup of current CRS rules to $backup_file"
    tar -czf "$backup_file" -C "$(dirname $CRS_DIR)" "$(basename $CRS_DIR)" || {
        log "ERROR: Failed to create backup. Aborting update."
        exit 1
    }
else
    log "No existing CRS installation found at $CRS_DIR. Will perform fresh install."
    mkdir -p "$CRS_DIR"
fi

# Clone or update the CRS repository
if [ -d "$CRS_DIR/.git" ]; then
    log "Updating existing CRS repository..."
    cd "$CRS_DIR" || {
        log "ERROR: Could not change to $CRS_DIR directory"
        exit 1
    }
    git fetch --all || {
        log "ERROR: Git fetch failed"
        exit 1
    }

    # Get current version before update
    current_version=$(git describe --tags)
    log "Current CRS version: $current_version"

    # Pull latest changes
    git pull || {
        log "ERROR: Git pull failed"
        exit 1
    }

    # Get new version after update
    new_version=$(git describe --tags)
    log "Updated CRS version: $new_version"
else
    log "Performing fresh CRS installation..."
    rm -rf "$CRS_DIR"
    git clone "$CRS_REPO" "$CRS_DIR" || {
        log "ERROR: Git clone failed"
        exit 1
    }

    cd "$CRS_DIR" || {
        log "ERROR: Could not change to $CRS_DIR directory"
        exit 1
    }

    # Get version
    new_version=$(git describe --tags)
    log "Installed CRS version: $new_version"
fi

# Setup correct configuration
log "Setting up CRS configuration..."
if [ -f "$CRS_DIR/crs-setup.conf.example" ]; then
    cp -f "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"
fi

# Copy custom rules
log "Copying Cloud Platform custom rules..."
if [ -f "/opt/cloud-platform/deployment/security/waf-rules.conf" ]; then
    cp -f "/opt/cloud-platform/deployment/security/waf-rules.conf" "$CRS_DIR/rules/cloud-platform-rules.conf"
fi

# Update file ownership and permissions
log "Setting correct permissions..."
find "$CRS_DIR" -type f -exec chmod 644 {} \\;
find "$CRS_DIR" -type d -exec chmod 755 {} \\;

# Test NGINX configuration
log "Testing NGINX configuration..."
nginx -t

if [ $? -eq 0 ]; then
    log "NGINX configuration test passed"

    # Reload NGINX to apply changes
    log "Reloading NGINX to apply new rules..."
    systemctl reload nginx || {
        log "ERROR: Failed to reload NGINX"
        exit 1
    }

    log "ModSecurity CRS update completed successfully"
else
    log "ERROR: NGINX configuration test failed. Restoring backup..."

    # Restore from backup
    if [ -f "$backup_file" ]; then
        rm -rf "$CRS_DIR"
        mkdir -p "$(dirname $CRS_DIR)"
        tar -xzf "$backup_file" -C "$(dirname $CRS_DIR)" || {
            log "ERROR: Failed to restore backup. Manual intervention required!"
            exit 1
        }
        log "Backup restored. NGINX not reloaded."
    else
        log "ERROR: Backup file not found. Manual intervention required!"
        exit 1
    fi
fi

# Cleanup old backups (keep last 5)
log "Cleaning up old backups..."
ls -tp "$BACKUP_DIR"/*.tar.gz | grep -v '/$' | tail -n +6 | xargs -I {} rm -- {}

log "ModSecurity CRS update process completed"
