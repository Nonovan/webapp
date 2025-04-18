#!/bin/bash
# Check SSL certificate expiration and send alerts
# Usage: ./scripts/check_certificate_expiration.sh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="/etc/ssl/cloud-platform"
EMAIL_RECIPIENT="admin@example.com"
WARNING_DAYS=30
CRITICAL_DAYS=7
LOG_FILE="/var/log/cloud-platform/certificate_check.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

check_cert() {
    local cert="$1"
    local name=$(basename "$cert")
    
    log "Checking certificate: $name"
    
    # Extract expiration date
    local expiry_date=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
    
    # Convert to timestamp
    local expiry_timestamp=$(date -d "$expiry_date" +%s)
    local current_timestamp=$(date +%s)
    
    # Calculate days until expiry
    local seconds_diff=$((expiry_timestamp - current_timestamp))
    local days_diff=$((seconds_diff / 86400))
    
    log "$name expires in $days_diff days on $expiry_date"
    
    # Check against thresholds and alert if necessary
    if [ $days_diff -le $CRITICAL_DAYS ]; then
        log "CRITICAL: Certificate $name expires in $days_diff days"
        send_alert "CRITICAL: SSL Certificate Expiring in $days_diff days" \
                 "Certificate $name will expire on $expiry_date.\n\nPlease renew it immediately to avoid service disruption."
        return 2
    elif [ $days_diff -le $WARNING_DAYS ]; then
        log "WARNING: Certificate $name expires in $days_diff days"
        send_alert "WARNING: SSL Certificate Expiring in $days_diff days" \
                 "Certificate $name will expire on $expiry_date.\n\nPlease plan to renew it soon."
        return 1
    else
        log "OK: Certificate $name will expire in $days_diff days"
        return 0
    fi
}

send_alert() {
    local subject="$1"
    local message="$2"
    
    if command -v mail &>/dev/null; then
        echo -e "$message" | mail -s "$subject" "$EMAIL_RECIPIENT"
        log "Alert email sent to $EMAIL_RECIPIENT"
    else
        log "WARNING: 'mail' command not found. Cannot send alert email."
        log "Alert subject: $subject"
        log "Alert message: $message"
    fi
}

log "Starting certificate expiration check"

# Check if certificates directory exists
if [ ! -d "$CERTS_DIR" ]; then
    log "Certificates directory $CERTS_DIR not found. Checking common locations."
    CERTS_DIR="/etc/ssl/certs"
fi

# Check if jq is installed for domain name extraction from config
if command -v jq &>/dev/null; then
    DOMAINS_JSON="${PROJECT_ROOT}/config/domains.json"
    if [ -f "$DOMAINS_JSON" ]; then
        log "Extracting domains from configuration"
        DOMAINS=$(jq -r '.domains[]' "$DOMAINS_JSON")
        
        for domain in $DOMAINS; do
            log "Checking external certificate for $domain"
            expiry=$(echo | openssl s_client -servername "$domain" -connect "$domain":443 2>/dev/null | openssl x509 -enddate -noout | cut -d= -f2)
            
            if [ -n "$expiry" ]; then
                # Process the expiration date as before
                expiry_timestamp=$(date -d "$expiry" +%s)
                current_timestamp=$(date +%s)
                seconds_diff=$((expiry_timestamp - current_timestamp))
                days_diff=$((seconds_diff / 86400))
                
                log "$domain expires in $days_diff days on $expiry"
                
                if [ $days_diff -le $CRITICAL_DAYS ]; then
                    log "CRITICAL: Certificate for $domain expires in $days_diff days"
                    send_alert "CRITICAL: SSL Certificate for $domain Expiring in $days_diff days" \
                             "Certificate for $domain will expire on $expiry.\n\nPlease renew it immediately."
                elif [ $days_diff -le $WARNING_DAYS ]; then
                    log "WARNING: Certificate for $domain expires in $days_diff days"
                    send_alert "WARNING: SSL Certificate for $domain Expiring in $days_diff days" \
                             "Certificate for $domain will expire on $expiry.\n\nPlease plan to renew it soon."
                fi
            else
                log "WARNING: Could not check certificate for $domain"
            fi
        done
    fi
fi

# Check all certificates in the directory
CERT_COUNT=0
find "$CERTS_DIR" -name "*.crt" -o -name "*.pem" | while read cert; do
    if [ -f "$cert" ]; then
        check_cert "$cert"
        CERT_COUNT=$((CERT_COUNT + 1))
    fi
done

if [ $CERT_COUNT -eq 0 ]; then
    log "WARNING: No certificates found to check"
fi

log "Certificate expiration check completed"