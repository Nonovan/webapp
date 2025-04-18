#!/bin/bash
# Update ModSecurity Core Rule Set (CRS) for Cloud Infrastructure Platform

# Configuration
CRS_REPO="https://github.com/coreruleset/coreruleset.git"
CRS_DIR="/etc/nginx/modsecurity-crs"
WAF_RULES_DIR="/etc/nginx/modsecurity.d/waf-rules"
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

# Backup WAF rules directory if it exists
if [ -d "$WAF_RULES_DIR" ]; then
    waf_backup_file="$BACKUP_DIR/waf-rules-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    log "Creating backup of custom WAF rules to $waf_backup_file"
    tar -czf "$waf_backup_file" -C "$(dirname $WAF_RULES_DIR)" "$(basename $WAF_RULES_DIR)" || {
        log "WARNING: Failed to create WAF rules backup. Will proceed with update."
    }
else
    log "No existing WAF rules directory found at $WAF_RULES_DIR. Will create it."
    mkdir -p "$WAF_RULES_DIR"
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

# Copy custom WAF rules from source directory
log "Setting up custom WAF rules directory..."
SOURCE_WAF_DIR="/opt/cloud-platform/deployment/security/waf-rules"

if [ -d "$SOURCE_WAF_DIR" ]; then
    log "Copying custom WAF rules from $SOURCE_WAF_DIR to $WAF_RULES_DIR..."
    
    # Create WAF rules directory if it doesn't exist
    mkdir -p "$WAF_RULES_DIR"
    
    # Copy all rule files from the source directory
    cp -f "$SOURCE_WAF_DIR"/*.conf "$WAF_RULES_DIR/" 2>/dev/null || {
        log "WARNING: No rule files found in $SOURCE_WAF_DIR"
    }
    
    log "Custom WAF rules copied successfully"
else
    log "Custom WAF rules source directory not found at $SOURCE_WAF_DIR"
    
    # Check for single file for backward compatibility
    if [ -f "/opt/cloud-platform/deployment/security/waf-rules.conf" ]; then
        log "WARNING: Found legacy waf-rules.conf file. Consider migrating to the directory structure."
        cp -f "/opt/cloud-platform/deployment/security/waf-rules.conf" "$CRS_DIR/rules/cloud-platform-rules.conf"
    fi
fi

# Update file ownership and permissions
log "Setting correct permissions..."
find "$CRS_DIR" -type f -exec chmod 644 {} \;
find "$CRS_DIR" -type d -exec chmod 755 {} \;
find "$WAF_RULES_DIR" -type f -exec chmod 644 {} \;
find "$WAF_RULES_DIR" -type d -exec chmod 755 {} \;

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

    # Restore CRS from backup
    if [ -f "$backup_file" ]; then
        rm -rf "$CRS_DIR"
        mkdir -p "$(dirname $CRS_DIR)"
        tar -xzf "$backup_file" -C "$(dirname $CRS_DIR)" || {
            log "ERROR: Failed to restore CRS backup. Manual intervention required!"
            exit 1
        }
        log "CRS backup restored."
    else
        log "ERROR: CRS backup file not found. Manual intervention required!"
    fi
    
    # Restore WAF rules from backup
    if [ -f "$waf_backup_file" ]; then
        rm -rf "$WAF_RULES_DIR"
        mkdir -p "$(dirname $WAF_RULES_DIR)"
        tar -xzf "$waf_backup_file" -C "$(dirname $WAF_RULES_DIR)" || {
            log "ERROR: Failed to restore WAF rules backup. Manual intervention required!"
            exit 1
        }
        log "WAF rules backup restored. NGINX not reloaded."
    else
        log "ERROR: WAF rules backup file not found. Manual intervention may be required!"
    fi
    
    exit 1
fi

# Cleanup old backups (keep last 5)
log "Cleaning up old backups..."
ls -tp "$BACKUP_DIR"/crs-backup-*.tar.gz 2>/dev/null | grep -v '/$' | tail -n +6 | xargs -I {} rm -- {} 2>/dev/null
ls -tp "$BACKUP_DIR"/waf-rules-backup-*.tar.gz 2>/dev/null | grep -v '/$' | tail -n +6 | xargs -I {} rm -- {} 2>/dev/null

log "ModSecurity CRS and custom WAF rules update process completed"