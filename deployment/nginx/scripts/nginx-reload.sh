#!/bin/bash
# NGINX Configuration Reload Script for Cloud Infrastructure Platform
# Usage: ./nginx-reload.sh [--graceful] [--force] [--dry-run]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
NGINX_ROOT="/etc/nginx"
NGINX_CONF="${NGINX_ROOT}/nginx.conf"
LOG_FILE="/var/log/cloud-platform/nginx-reload.log"
BACKUP_DIR="/var/backups/nginx-configs"
TIMEOUT=30
GRACEFUL=true
FORCE=false
DRY_RUN=false
SKIP_TEST=false
RELOAD_ONLY=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] $1"
    
    # Ensure log directory exists
    if [ ! -d "$(dirname "$LOG_FILE")" ] && [ "$DRY_RUN" == "false" ]; then
        mkdir -p "$(dirname "$LOG_FILE")"
    fi
    
    # Log to file if not in dry run mode
    if [ "$DRY_RUN" == "false" ]; then
        echo "[$timestamp] $1" >> "$LOG_FILE"
    fi
}

# Function to display usage
usage() {
    echo "NGINX Configuration Reload Script for Cloud Infrastructure Platform"
    echo
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --graceful           Reload gracefully, keeping connections (default)"
    echo "  --restart            Restart NGINX instead of reloading (closes connections)"
    echo "  --force              Force reload even if config test fails (dangerous)"
    echo "  --skip-test          Skip configuration test and reload directly"
    echo "  --timeout N          Wait N seconds for NGINX to reload (default: 30)"
    echo "  --reload-only        Only reload, don't check for changed files"
    echo "  --dry-run            Show what would be done without doing it"
    echo "  --help, -h           Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --graceful)
            GRACEFUL=true
            shift
            ;;
        --restart)
            GRACEFUL=false
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --skip-test)
            SKIP_TEST=true
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --reload-only)
            RELOAD_ONLY=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Function to check if NGINX is installed
check_nginx_installed() {
    if ! command -v nginx &> /dev/null; then
        log "${RED}ERROR: NGINX is not installed${NC}"
        exit 1
    fi
}

# Function to check if NGINX is running
check_nginx_running() {
    if ! systemctl is-active --quiet nginx; then
        log "${YELLOW}WARNING: NGINX is not currently running${NC}"
        return 1
    fi
    
    return 0
}

# Function to create backup of configuration
backup_config() {
    if [ "$DRY_RUN" == "true" ]; then
        log "[DRY RUN] Would back up NGINX configuration"
        return 0
    fi
    
    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR"
    
    local timestamp=$(date "+%Y%m%d%H%M%S")
    local backup_file="${BACKUP_DIR}/nginx-config-${timestamp}.tar.gz"
    
    log "Creating backup of NGINX configuration..."
    if tar -czf "$backup_file" -C "$NGINX_ROOT" .; then
        log "${GREEN}✓ Configuration backup created at $backup_file${NC}"
        return 0
    else
        log "${RED}Failed to create configuration backup${NC}"
        return 1
    fi
}

# Function to check if configuration has changed
check_config_changes() {
    local last_reload_time
    local config_modification_time
    
    # Get the last reload time from systemd
    last_reload_time=$(systemctl show nginx | grep ExecMainStartTimestamp= | cut -d= -f2)
    if [ -z "$last_reload_time" ]; then
        # If we can't get the timestamp, assume we need to reload
        log "${YELLOW}Could not determine last reload time, proceeding with reload${NC}"
        return 0
    fi
    
    # Convert to Unix timestamp
    last_reload_unix=$(date -d "$last_reload_time" +%s 2>/dev/null)
    if [ $? -ne 0 ]; then
        log "${YELLOW}Error parsing last reload time, proceeding with reload${NC}"
        return 0
    fi
    
    # Check if any configuration file has been modified since last reload
    any_changes=false
    while IFS= read -r file; do
        mod_time=$(stat -c %Y "$file")
        if [ "$mod_time" -gt "$last_reload_unix" ]; then
            log "Configuration file changed since last reload: $file"
            any_changes=true
        fi
    done < <(find "$NGINX_ROOT" -type f -name "*.conf" 2>/dev/null)
    
    if [ "$any_changes" = true ]; then
        return 0  # Changes detected
    else
        log "${GREEN}✓ No configuration changes detected since last reload${NC}"
        return 1  # No changes
    fi
}

# Function to test NGINX configuration
test_config() {
    log "Testing NGINX configuration..."
    
    if [ "$DRY_RUN" == "true" ]; then
        log "[DRY RUN] Would test NGINX configuration"
        return 0
    fi
    
    if nginx -t; then
        log "${GREEN}✓ Configuration test passed${NC}"
        return 0
    else
        log "${RED}✗ Configuration test failed${NC}"
        return 1
    fi
}

# Function to reload NGINX (graceful)
reload_nginx() {
    if check_nginx_running; then
        log "Reloading NGINX configuration..."
        
        if [ "$DRY_RUN" == "true" ]; then
            log "[DRY RUN] Would reload NGINX configuration"
            return 0
        fi
        
        if systemctl reload nginx; then
            log "${GREEN}✓ NGINX reloaded successfully${NC}"
            return 0
        else
            log "${RED}✗ Failed to reload NGINX${NC}"
            return 1
        fi
    else
        log "Starting NGINX since it's not running..."
        
        if [ "$DRY_RUN" == "true" ]; then
            log "[DRY RUN] Would start NGINX"
            return 0
        fi
        
        if systemctl start nginx; then
            log "${GREEN}✓ NGINX started successfully${NC}"
            return 0
        else
            log "${RED}✗ Failed to start NGINX${NC}"
            return 1
        fi
    fi
}

# Function to restart NGINX
restart_nginx() {
    log "Restarting NGINX..."
    
    if [ "$DRY_RUN" == "true" ]; then
        log "[DRY RUN] Would restart NGINX"
        return 0
    fi
    
    if systemctl restart nginx; then
        log "${GREEN}✓ NGINX restarted successfully${NC}"
        return 0
    else
        log "${RED}✗ Failed to restart NGINX${NC}"
        return 1
    fi
}

# Function to verify NGINX is responding
verify_nginx_responding() {
    log "Verifying NGINX is responding..."
    
    if [ "$DRY_RUN" == "true" ]; then
        log "[DRY RUN] Would verify NGINX is responding"
        return 0
    fi
    
    # Try to connect to NGINX using curl for $TIMEOUT seconds
    local end_time=$(($(date +%s) + TIMEOUT))
    local success=false
    
    while [ $(date +%s) -lt $end_time ]; do
        if curl -s --max-time 2 http://localhost/ > /dev/null; then
            success=true
            break
        fi
        sleep 1
    done
    
    if [ "$success" == "true" ]; then
        log "${GREEN}✓ NGINX is responding${NC}"
        return 0
    else
        log "${RED}✗ NGINX is not responding after $TIMEOUT seconds${NC}"
        return 1
    fi
}

# Function to check for potential SSL certificate issues
check_ssl_certs() {
    log "Checking SSL certificates..."
    
    if [ "$DRY_RUN" == "true" ]; then
        log "[DRY RUN] Would check SSL certificates"
        return 0
    fi
    
    local ssl_paths=$(grep -r "ssl_certificate" --include="*.conf" $NGINX_ROOT | awk '{print $2}' | tr -d ';' | sort | uniq)
    
    if [ -z "$ssl_paths" ]; then
        log "${YELLOW}No SSL certificates found in configuration${NC}"
        return 0
    fi
    
    local has_errors=false
    
    for cert_path in $ssl_paths; do
        if [ ! -f "$cert_path" ]; then
            log "${RED}✗ Certificate file not found: $cert_path${NC}"
            has_errors=true
            continue
        fi
        
        # Check expiry date
        local expiry_date=$(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2)
        if [ $? -ne 0 ]; then
            log "${RED}✗ Error reading certificate: $cert_path${NC}"
            has_errors=true
            continue
        fi
        
        local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
        local current_epoch=$(date +%s)
        local days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        if [ "$days_left" -lt 30 ]; then
            log "${YELLOW}⚠ Certificate $cert_path will expire in $days_left days${NC}"
            if [ "$days_left" -lt 7 ]; then
                has_errors=true
            fi
        else
            log "${GREEN}✓ Certificate $cert_path valid for $days_left days${NC}"
        fi
    done
    
    if [ "$has_errors" == "true" ]; then
        log "${YELLOW}There are SSL certificate issues that should be addressed${NC}"
        return 1
    fi
    
    return 0
}

# Function to check NGINX status details
check_nginx_status() {
    log "Checking NGINX status..."
    
    if [ "$DRY_RUN" == "true" ]; then
        log "[DRY RUN] Would check NGINX status"
        return
    fi
    
    # Get current connections
    local connections=$(ss -ant | grep -c ESTAB)
    log "Current established connections: $connections"
    
    # Check if NGINX is running with the expected user
    local nginx_user=$(ps -eo user,comm | grep nginx | grep -v grep | head -1 | awk '{print $1}')
    log "NGINX running as user: $nginx_user"
    
    # Show NGINX version
    local nginx_version=$(nginx -v 2>&1)
    log "NGINX version: $nginx_version"
    
    # Check for pending restart
    if systemctl is-system-running > /dev/null 2>&1; then
        if systemctl is-active --quiet nginx; then
            if systemctl show -p NeedDaemonReload nginx | grep -q "NeedDaemonReload=yes"; then
                log "${YELLOW}⚠ NGINX needs daemon reload${NC}"
            fi
        fi
    fi
}

# Main execution flow
log "${BLUE}Starting NGINX configuration reload...${NC}"

# Check if NGINX is installed
check_nginx_installed

# Create backup of current configuration
backup_config

# Check if we need to reload (if not in reload-only mode)
if [ "$RELOAD_ONLY" == "false" ]; then
    if ! check_config_changes; then
        log "${GREEN}No changes detected since last reload, exiting${NC}"
        exit 0
    fi
fi

# Check for SSL certificate issues
check_ssl_certs

# Test configuration
if [ "$SKIP_TEST" == "false" ]; then
    if ! test_config && [ "$FORCE" == "false" ]; then
        log "${RED}Configuration test failed. Not reloading NGINX.${NC}"
        log "Use --force to reload anyway (dangerous)."
        exit 1
    fi
else
    log "${YELLOW}Skipping configuration test (--skip-test)${NC}"
fi

# Reload or restart NGINX
if [ "$GRACEFUL" == "true" ]; then
    reload_nginx
else
    restart_nginx
fi

# Verify NGINX is responding
if ! verify_nginx_responding; then
    log "${RED}WARNING: NGINX may not be fully operational after reload.${NC}"
    log "Check the error logs for more details: /var/log/nginx/error.log"
    exit 1
fi

# Show NGINX status
check_nginx_status

log "${GREEN}NGINX reload/restart completed successfully!${NC}"
exit 0