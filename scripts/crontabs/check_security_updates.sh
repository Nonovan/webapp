#!/bin/bash
# Check for security updates on the system

LOG_FILE="/var/log/cloud-platform/security.log"
EMAIL="admin@example.com"
UPDATE_COUNT=0

echo "[$(date)] Checking for security updates..." >> "$LOG_FILE"

# For Debian/Ubuntu systems
if command -v apt-get &> /dev/null; then
    apt-get update -qq
    UPDATE_COUNT=$(apt-get --just-print upgrade | grep -c "^Inst.*security")
    
    if [ $UPDATE_COUNT -gt 0 ]; then
        echo "[$(date)] $UPDATE_COUNT security updates available:" >> "$LOG_FILE"
        apt-get --just-print upgrade | grep "^Inst.*security" >> "$LOG_FILE"
    fi

# For RHEL/CentOS systems
elif command -v yum &> /dev/null; then
    UPDATE_COUNT=$(yum check-update --security | grep -c "^[a-zA-Z0-9]")
    
    if [ $UPDATE_COUNT -gt 0 ]; then
        echo "[$(date)] $UPDATE_COUNT security updates available:" >> "$LOG_FILE"
        yum check-update --security | grep "^[a-zA-Z0-9]" >> "$LOG_FILE"
    fi
fi

# Send email if updates are available
if [ $UPDATE_COUNT -gt 0 ]; then
    mail -s "Security updates available on $(hostname)" "$EMAIL" <<EOF
There are $UPDATE_COUNT security updates available on $(hostname).
Please review the security log at $LOG_FILE for details.

Server: $(hostname)
Date: $(date)
EOF
fi

echo "[$(date)] Security update check complete." >> "$LOG_FILE"
