#!/bin/bash
# Security setup and hardening script for Cloud Infrastructure Platform
# Usage: ./security_setup.sh [environment]

set -euo pipefail

# Default to production if no environment specified
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/cloud-platform/security_setup.log"
BACKUP_DIR="/var/backups/cloud-platform/security"

# Ensure log and backup directories exist
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$BACKUP_DIR"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

error() {
    log "ERROR: $1"
    exit 1
}

# Function to back up a file before modifying it
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_name="$(basename "$file").$(date +%Y%m%d%H%M%S).bak"
        cp "$file" "${BACKUP_DIR}/${backup_name}"
        log "Backed up $file to ${BACKUP_DIR}/${backup_name}"
    fi
}

log "Starting security setup for ${ENVIRONMENT} environment"

# Check for root permissions
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root"
fi

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [ -f "$ENV_FILE" ]; then
    log "Loading ${ENVIRONMENT} environment variables"
    source "$ENV_FILE"
else
    error "Environment file $ENV_FILE not found"
fi

# Apply NGINX security configuration
if [ -d "/etc/nginx" ]; then
    log "Applying NGINX security configuration"
    
    # Backup existing configuration files
    if [ -f "/etc/nginx/nginx.conf" ]; then
        backup_file "/etc/nginx/nginx.conf"
    fi
    
    # Create security configuration directory if it doesn't exist
    mkdir -p /etc/nginx/conf.d/
    
    # Copy security configuration files
    cp "${PROJECT_ROOT}/deployment/security/nginx-hardening.conf" /etc/nginx/conf.d/
    cp "${PROJECT_ROOT}/deployment/security/security-headers.conf" /etc/nginx/conf.d/
    cp "${PROJECT_ROOT}/deployment/security/ssl-params.conf" /etc/nginx/conf.d/
    
    # Set proper permissions
    chmod 644 /etc/nginx/conf.d/nginx-hardening.conf
    chmod 644 /etc/nginx/conf.d/security-headers.conf
    chmod 644 /etc/nginx/conf.d/ssl-params.conf
    
    # Reload NGINX to apply changes
    if nginx -t; then
        systemctl reload nginx
        log "NGINX configuration applied successfully"
    else
        error "NGINX configuration test failed. Changes not applied."
    fi
else
    log "NGINX not installed, skipping NGINX security configuration"
fi

# Setup ModSecurity WAF if installed
if [ -d "/etc/nginx/modsecurity" ]; then
    log "Setting up ModSecurity WAF"
    
    # Run the update script
    "${PROJECT_ROOT}/deployment/security/update-modsecurity-rules.sh"
    
    # Create WAF rules directory if it doesn't exist
    mkdir -p "/etc/nginx/modsecurity.d/waf-rules"
    
    # Copy custom WAF rules
    cp "${PROJECT_ROOT}/deployment/security/waf-rules/"*.conf /etc/nginx/modsecurity.d/waf-rules/
    
    # Set proper permissions
    chmod 644 /etc/nginx/modsecurity.d/waf-rules/*.conf
    
    log "ModSecurity WAF setup complete"
else
    log "ModSecurity not installed, skipping WAF setup"
fi

# Setup file integrity monitoring with AIDE
if command -v aide &>/dev/null; then
    log "Setting up AIDE file integrity monitoring"
    
    # Backup existing configuration
    if [ -f "/etc/aide/aide.conf" ]; then
        backup_file "/etc/aide/aide.conf"
    fi
    
    # Copy AIDE configuration
    cp "${PROJECT_ROOT}/deployment/security/aide.conf" /etc/aide/
    chmod 644 /etc/aide/aide.conf
    
    # Initialize AIDE database
    log "Initializing AIDE database (this may take a while)..."
    aide --init
    
    # Move the newly created database into place
    if [ -f "/var/lib/aide/aide.db.new" ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log "AIDE database initialized"
    else
        log "WARNING: AIDE database initialization may have failed"
    fi
else
    log "AIDE not installed, skipping file integrity monitoring setup"
fi

# Setup firewall rules
log "Setting up firewall rules"
if [ -x "${PROJECT_ROOT}/deployment/security/iptables-rules.sh" ]; then
    "${PROJECT_ROOT}/deployment/security/iptables-rules.sh"
    log "Firewall rules applied"
else
    log "WARNING: Firewall rules script not found or not executable"
fi

# Setup Fail2ban
if [ -d "/etc/fail2ban" ]; then
    log "Setting up Fail2ban"
    
    # Backup existing configuration
    if [ -f "/etc/fail2ban/jail.local" ]; then
        backup_file "/etc/fail2ban/jail.local"
    fi
    
    # Copy Fail2ban configuration
    cp "${PROJECT_ROOT}/deployment/security/fail2ban.local" /etc/fail2ban/jail.local
    chmod 644 /etc/fail2ban/jail.local
    
    # Copy custom filters
    mkdir -p /etc/fail2ban/filter.d
    if [ -d "${PROJECT_ROOT}/deployment/security/fail2ban-filters" ]; then
        cp "${PROJECT_ROOT}/deployment/security/fail2ban-filters/"*.conf /etc/fail2ban/filter.d/
        chmod 644 /etc/fail2ban/filter.d/*.conf
    fi
    
    # Restart Fail2ban to apply changes
    systemctl restart fail2ban
    
    log "Fail2ban setup complete"
else
    log "Fail2ban not installed, skipping Fail2ban setup"
fi

# Setup SSH hardening
if [ -f "/etc/ssh/sshd_config" ]; then
    log "Setting up SSH hardening"
    
    # Backup original sshd_config
    backup_file "/etc/ssh/sshd_config"
    
    # Create config.d directory if it doesn't exist
    mkdir -p /etc/ssh/sshd_config.d/
    
    # Apply SSH hardening configuration
    cp "${PROJECT_ROOT}/deployment/security/ssh-hardening.conf" /etc/ssh/sshd_config.d/hardening.conf
    chmod 644 /etc/ssh/sshd_config.d/hardening.conf
    
    # Ensure config.d directory is included in main config
    if ! grep -q "Include /etc/ssh/sshd_config.d/\*.conf" "/etc/ssh/sshd_config"; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH service to apply changes
    systemctl restart sshd
    
    log "SSH hardening setup complete"
else
    log "SSH configuration not found, skipping SSH hardening"
fi

# Setup security update cron jobs
log "Setting up security update cron jobs"
cp "${PROJECT_ROOT}/deployment/security/security-update-cron" /etc/cron.d/cloud-platform-security
chmod 644 /etc/cron.d/cloud-platform-security

# Apply AppArmor profiles if AppArmor is enabled
if command -v apparmor_status &>/dev/null && apparmor_status --enabled; then
    log "Setting up AppArmor profiles"
    
    # Copy AppArmor profiles
    if [ -f "${PROJECT_ROOT}/deployment/security/apparmor-profile-nginx" ]; then
        cp "${PROJECT_ROOT}/deployment/security/apparmor-profile-nginx" /etc/apparmor.d/usr.sbin.nginx
        chmod 644 /etc/apparmor.d/usr.sbin.nginx
        
        # Reload profile
        apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
        log "AppArmor profile for nginx loaded"
    fi
    
    # Add more profiles as needed
else
    log "AppArmor not enabled, skipping AppArmor profiles setup"
fi

# Apply special hardening for production
if [ "$ENVIRONMENT" == "production" ]; then
    log "Applying production-specific security hardening"
    
    # Ensure sensitive files have proper permissions
    log "Setting secure permissions for sensitive files"
    find /etc/ssl/private -type f -name "*.key" -exec chmod 600 {} \;
    find /etc/ssl/private -type f -name "*.key" -exec chown root:root {} \;
    
    # Set secure umask for all users
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
        log "Set secure umask for all users"
    fi
    
    # Disable core dumps
    if ! grep -q "* hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
        log "Disabled core dumps"
    fi
    
    # Set more restrictive file permissions
    if [ -d "${PROJECT_ROOT}/instance" ]; then
        chown -R root:www-data "${PROJECT_ROOT}/instance"
        chmod -R 750 "${PROJECT_ROOT}/instance"
        log "Set secure permissions for instance directory"
    fi
    
    # Additional hardening steps can be added here
fi

# Run initial security audit
log "Running initial security audit"
if [ -x "${PROJECT_ROOT}/deployment/security/security-audit.sh" ]; then
    "${PROJECT_ROOT}/deployment/security/security-audit.sh"
    log "Security audit complete"
else
    log "WARNING: Security audit script not found or not executable"
fi

log "Security setup for ${ENVIRONMENT} environment completed successfully"
exit 0