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
    log "Created CRS setup configuration from example"
elif [ ! -f "$CRS_DIR/crs-setup.conf" ]; then
    log "ERROR: CRS setup configuration example not found"
    exit 1
fi

# Copy custom WAF rules from source directory
log "Setting up custom WAF rules directory..."
SOURCE_WAF_DIR="/opt/cloud-platform/deployment/security/waf-rules"

# Ensure WAF rules directory exists
mkdir -p "$WAF_RULES_DIR" || {
    log "ERROR: Failed to create WAF rules directory"
    exit 1
}

# Handle custom WAF rules
if [ -d "$SOURCE_WAF_DIR" ] && [ "$(ls -A "$SOURCE_WAF_DIR" 2>/dev/null)" ]; then
    log "Copying custom WAF rules from $SOURCE_WAF_DIR to $WAF_RULES_DIR..."
    
    # Copy all rule files and preserve attributes
    find "$SOURCE_WAF_DIR" -name "*.conf" -type f -exec cp -f {} "$WAF_RULES_DIR/" \; || {
        log "WARNING: Failed to copy some rule files from $SOURCE_WAF_DIR"
    }
    
    # Verify successful copy
    RULE_COUNT=$(find "$WAF_RULES_DIR" -name "*.conf" -type f | wc -l)
    if [ "$RULE_COUNT" -gt 0 ]; then
        log "Successfully copied $RULE_COUNT custom WAF rule files"
    else
        log "WARNING: No custom rule files found or copied"
    fi
else
    log "Custom WAF rules source directory not found or empty at $SOURCE_WAF_DIR"
        
        # Check for single file for backward compatibility
        if [ -f "/opt/cloud-platform/deployment/security/waf-rules.conf" ]; then
            log "Found legacy waf-rules.conf file. Copying to rules directory..."
            cp -f "/opt/cloud-platform/deployment/security/waf-rules.conf" "$CRS_DIR/rules/cloud-platform-rules.conf" || {
                log "ERROR: Failed to copy legacy WAF rules file"
            }
            log "Legacy WAF rules file copied. Consider migrating to the directory structure."
        else
            log "WARNING: No custom WAF rules found. Using default CRS rules only."
        fi
    fi
    
    # Update file ownership and permissions
    log "Setting correct permissions..."
    find "$CRS_DIR" -type f -exec chmod 644 {} \; || log "WARNING: Failed to set permissions on some CRS files"
    find "$CRS_DIR" -type d -exec chmod 755 {} \; || log "WARNING: Failed to set permissions on some CRS directories"
    find "$WAF_RULES_DIR" -type f -exec chmod 644 {} \; || log "WARNING: Failed to set permissions on some WAF rule files" 
    find "$WAF_RULES_DIR" -type d -exec chmod 755 {} \; || log "WARNING: Failed to set permissions on some WAF rule directories"
    
    # Check file ownership if running as root
    if [ "$(id -u)" -eq 0 ]; then
        find "$CRS_DIR" -exec chown root:root {} \; 2>/dev/null || log "WARNING: Failed to set ownership on some CRS files"
        find "$WAF_RULES_DIR" -exec chown root:root {} \; 2>/dev/null || log "WARNING: Failed to set ownership on some WAF files"
    fi
    
    # Test NGINX configuration
    log "Testing NGINX configuration..."
    if nginx -t &>/tmp/nginx-test.log; then
        log "NGINX configuration test passed"
    
        # Reload NGINX to apply changes
        log "Reloading NGINX to apply new rules..."
        if systemctl reload nginx; then
            log "NGINX reloaded successfully"
            log "ModSecurity CRS update completed successfully"
            # Cleanup temporary files
            rm -f /tmp/nginx-test.log
        else
            log "ERROR: Failed to reload NGINX"
            cat /tmp/nginx-test.log
            # Keep the log file for troubleshooting
            log "Test output saved to /tmp/nginx-test.log"
            exit 1
        fi
    else
        log "ERROR: NGINX configuration test failed. Restoring backup..."
        # Save the test output for troubleshooting
        log "Test output:"
        cat /tmp/nginx-test.log
        
        # Restore CRS from backup
        if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
            log "Restoring from backup: $backup_file"
            # Create temporary directory for restoration
            tmp_restore_dir=$(mktemp -d)
            if tar -xzf "$backup_file" -C "$tmp_restore_dir"; then
                # Remove failed configuration
                if [ -d "$CRS_DIR" ]; then
                    rm -rf "$CRS_DIR"
                fi
                
                # Restore from backup
                if [ -d "$tmp_restore_dir" ]; then
                    mv "$tmp_restore_dir"/* "$(dirname "$CRS_DIR")/" 2>/dev/null || log "WARNING: Error moving restored files"
                    log "Backup restoration completed"
                    
                    # Verify NGINX config after restoration
                    if nginx -t &>/dev/null; then
                        log "NGINX configuration valid after restore"
                    else
                        log "ERROR: NGINX configuration still invalid after restore"
                    fi
                fi
            else
                log "ERROR: Failed to extract backup file"
            fi
            
            # Clean up temporary directory regardless of success
            if [ -d "$tmp_restore_dir" ]; then
                rm -rf "$tmp_restore_dir"
            fi
        else
            log "ERROR: Backup file not found or not specified. Cannot restore."
        fi
        
        # Exit with failure status
        exit 1
    fi
    
    # Final cleanup - only executed on success path
    log "Cleaning up temporary files..."
    rm -f /tmp/nginx-test.log