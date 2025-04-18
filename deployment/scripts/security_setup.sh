#!/bin/bash
# Security setup and hardening script for Cloud Infrastructure Platform
# Usage: ./security_setup.sh [environment]

set -e

# Default to production if no environment specified
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/cloud-platform/security_setup.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log "Starting security setup for ${ENVIRONMENT} environment"

# Check for root permissions
if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: This script must be run as root"
    exit 1
fi

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    log "Loading ${ENVIRONMENT} environment variables"
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
else
    log "ERROR: Environment file ${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env not found"
    exit 1
fi

# Apply NGINX security configuration
if [ -d "/etc/nginx" ]; then
    log "Applying NGINX security configuration"
    
    # Copy security configuration files
    cp "${PROJECT_ROOT}/deployment/security/nginx-hardening.conf" /etc/nginx/conf.d/
    cp "${PROJECT_ROOT}/deployment/security/security-headers.conf" /etc/nginx/conf.d/
    cp "${PROJECT_ROOT}/deployment/security/ssl-params.conf" /etc/nginx/conf.d/
    
    # Reload NGINX to apply changes
    if nginx -t; then
        systemctl reload nginx
        log "NGINX configuration applied successfully"
    else
        log "ERROR: NGINX configuration test failed"
        exit 1
    fi
else
    log "NGINX not installed, skipping NGINX security configuration"
fi

# Setup ModSecurity WAF
if [ -d "/etc/nginx/modsecurity" ]; then
    log "Setting up ModSecurity WAF"
    
    # Run the update script
    "${PROJECT_ROOT}/deployment/security/update-modsecurity-rules.sh"
    
    # Create WAF rules directory if it doesn't exist
    mkdir -p "/etc/nginx/modsecurity.d/waf-rules"
    
    # Copy custom WAF rules
    cp "${PROJECT_ROOT}/deployment/security/waf-rules/"*.conf /etc/nginx/modsecurity.d/waf-rules/
    
    log "ModSecurity WAF setup complete"
else
    log "ModSecurity not installed, skipping WAF setup"
fi

# Setup file integrity monitoring with AIDE
if command -v aide &>/dev/null; then
    log "Setting up AIDE file integrity monitoring"
    
    # Copy AIDE configuration
    cp "${PROJECT_ROOT}/deployment/security/aide.conf" /etc/aide/
    
    # Initialize AIDE database
    aide --init
    
    # Move the newly created database into place
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    log "AIDE setup complete"
else
    log "AIDE not installed, skipping file integrity monitoring setup"
fi

# Setup firewall rules
log "Setting up firewall rules"
"${PROJECT_ROOT}/deployment/security/iptables-rules.sh"

# Setup Fail2ban
if [ -d "/etc/fail2ban" ]; then
    log "Setting up Fail2ban"
    
    # Copy Fail2ban configuration
    cp "${PROJECT_ROOT}/deployment/security/fail2ban.local" /etc/fail2ban/jail.local
    
    # Copy custom filters
    mkdir -p /etc/fail2ban/filter.d
    cp "${PROJECT_ROOT}/deployment/security/fail2ban-filters/"*.conf /etc/fail2ban/filter.d/
    
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
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)
    
    # Apply SSH hardening configuration
    cp "${PROJECT_ROOT}/deployment/security/ssh-hardening.conf" /etc/ssh/sshd_config.d/hardening.conf
    
    # Restart SSH service to apply changes
    systemctl restart sshd
    
    log "SSH hardening setup complete"
else
    log "SSH configuration not found, skipping SSH hardening"
fi

# Setup security update cron jobs
log "Setting up security update cron jobs"
cp "${PROJECT_ROOT}/deployment/security/security-update-cron" /etc/cron.d/cloud-platform-security

# Apply special hardening for production
if [ "$ENVIRONMENT" == "production" ]; then
    log "Applying production-specific security hardening"
    
    # Ensure sensitive files have proper permissions
    chmod 640 /etc/cloud-platform/config.ini 2>/dev/null || log "WARNING: Could not set permissions on config.ini"
    chmod 600 /opt/cloud-platform/.env 2>/dev/null || log "WARNING: Could not set permissions on .env"
    
    # Set proper ownership
    chown root:www-data /etc/cloud-platform/config.ini 2>/dev/null || log "WARNING: Could not set ownership on config.ini"
    chown www-data:www-data /opt/cloud-platform/.env 2>/dev/null || log "WARNING: Could not set ownership on .env"
    
    # Apply additional sysctl hardening
    cat > /etc/sysctl.d/99-security-hardening.conf <<EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Don't act as a router
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0

# Protect against tcp time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15

# Decrease the time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security-hardening.conf
fi

log "Security setup completed successfully"