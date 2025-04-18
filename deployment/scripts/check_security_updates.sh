#!/bin/bash
# Check for security updates on the system
# Usage: ./check_security_updates.sh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/cloud-platform/security.log"
EMAIL_RECIPIENT="security@example.com"
UPDATE_COUNT=0
CRITICAL_UPDATES=0

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log "Starting security updates check"

# For Debian/Ubuntu systems
if command -v apt-get &>/dev/null; then
    log "Detected Debian/Ubuntu system"
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    log "Updating package lists"
    apt-get update -qq
    
    # Count security updates
    log "Checking for security updates"
    UPDATE_COUNT=$(apt-get --just-print upgrade | grep -c "^Inst.*security")
    
    if [ $UPDATE_COUNT -gt 0 ]; then
        log "Found $UPDATE_COUNT security updates available:"
        apt-get --just-print upgrade | grep "^Inst.*security" >> "$LOG_FILE"
        
        # List critical packages that need updates
        log "Checking for critical packages requiring updates"
        CRITICAL_UPDATES=$(apt-get --just-print upgrade | grep "^Inst.*security" | grep -E 'openssl|openssh|linux-|nginx|postgresql|apache2' | wc -l)
        if [ $CRITICAL_UPDATES -gt 0 ]; then
            log "WARNING: $CRITICAL_UPDATES critical packages require security updates:"
            apt-get --just-print upgrade | grep "^Inst.*security" | grep -E 'openssl|openssh|linux-|nginx|postgresql|apache2' >> "$LOG_FILE"
        fi
    else
        log "No security updates available"
    fi

# For RHEL/CentOS systems
elif command -v yum &>/dev/null; then
    log "Detected RHEL/CentOS system"
    
    # Update package lists
    log "Updating package lists"
    yum check-update -q
    
    # Count security updates
    log "Checking for security updates"
    UPDATE_COUNT=$(yum check-update --security | grep -c "^[a-zA-Z0-9]")
    
    if [ $UPDATE_COUNT -gt 0 ]; then
        log "Found $UPDATE_COUNT security updates available:"
        yum check-update --security | grep "^[a-zA-Z0-9]" >> "$LOG_FILE"
        
        # List critical packages that need updates
        log "Checking for critical packages requiring updates"
        CRITICAL_UPDATES=$(yum check-update --security | grep -E 'openssl|openssh|kernel|nginx|postgresql|httpd' | wc -l)
        if [ $CRITICAL_UPDATES -gt 0 ]; then
            log "WARNING: $CRITICAL_UPDATES critical packages require security updates:"
            yum check-update --security | grep -E 'openssl|openssh|kernel|nginx|postgresql|httpd' >> "$LOG_FILE"
        fi
    else
        log "No security updates available"
    fi
else
    log "ERROR: Could not detect package manager (apt-get or yum)"
    exit 1
fi

# Send email if updates are available
if [ $UPDATE_COUNT -gt 0 ]; then
    log "Sending notification email about security updates"
    
    # Check if critical updates are available
    if [ ${CRITICAL_UPDATES:-0} -gt 0 ]; then
        SUBJECT="CRITICAL: $UPDATE_COUNT security updates available on $(hostname)"
    else
        SUBJECT="$UPDATE_COUNT security updates available on $(hostname)"
    fi
    
    if command -v mail &>/dev/null; then
        mail -s "$SUBJECT" "$EMAIL_RECIPIENT" <<EOF
There are $UPDATE_COUNT security updates available on $(hostname).
Please review the security log at $LOG_FILE for details.

Server: $(hostname)
Date: $(date)
Environment: $([ -f "${PROJECT_ROOT}/config/current_environment" ] && cat "${PROJECT_ROOT}/config/current_environment" || echo "unknown")

$([ ${CRITICAL_UPDATES:-0} -gt 0 ] && echo "IMPORTANT: $CRITICAL_UPDATES critical security updates require immediate attention!" || echo "")

Summary of available updates:
$(apt-get --just-print upgrade | grep "^Inst.*security" | head -10)
$([ $UPDATE_COUNT -gt 10 ] && echo "... and $((UPDATE_COUNT - 10)) more" || echo "")
EOF
    else
        log "WARNING: 'mail' command not found. Cannot send notification email."
    fi
fi

log "Security updates check complete"

# Return the number of updates as exit code
exit $UPDATE_COUNT