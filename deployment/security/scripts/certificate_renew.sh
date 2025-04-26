#!/bin/bash
# SSL certificate renewal script for Cloud Infrastructure Platform
# Uses Certbot for Let's Encrypt certificate renewal

set -euo pipefail

# Configuration
DOMAIN="cloud-platform.example.com"
EMAIL="admin@example.com"
WEBROOT="/var/www/html"
NGINX_CONF="/etc/nginx/sites-available/cloud-platform"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
LOG_FILE="/var/log/cloud-platform/cert-renewal.log"
BACKUP_DIR="/var/backups/cloud-platform/certs"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-$EMAIL}"
RENEWAL_THRESHOLD=30  # Send alerts when less than this many days remain

# Ensure log and backup directories exist
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$BACKUP_DIR"
chmod 750 "$BACKUP_DIR"

# Function to log messages
log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Function to send notifications
send_notification() {
    local subject="$1"
    local message="$2"
    local priority="$3"  # info, warning, error
    
    # Send email notification
    if command -v mail &>/dev/null; then
        echo "$message" | mail -s "$subject" "$NOTIFICATION_EMAIL"
        log "Email notification sent to $NOTIFICATION_EMAIL"
    fi
    
    # Send Slack notification if webhook URL is configured
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        local color
        case $priority in
            error) color="#FF0000" ;;  # Red
            warning) color="#FFA500" ;; # Orange
            *) color="#36A64F" ;;  # Green
        esac
        
        curl -s -X POST -H 'Content-type: application/json' \
        --data "{\"attachments\": [{\"color\": \"$color\", \"title\": \"$subject\", \"text\": \"$message\"}]}" \
        "$SLACK_WEBHOOK_URL" &>/dev/null || log "WARNING: Failed to send Slack notification"
    fi
}

# Check if Certbot is installed
if ! command -v certbot &>/dev/null; then
    log "ERROR: Certbot is not installed. Please install it first."
    send_notification "Certificate Renewal Failed: $DOMAIN" "Certbot is not installed on $(hostname)" "error"
    exit 1
fi

log "Starting certificate renewal process for $DOMAIN"

# Backup existing certificates
if [ -d "$CERT_DIR" ]; then
    BACKUP_FILE="$BACKUP_DIR/$DOMAIN-$(date +%Y%m%d%H%M%S).tar.gz"
    log "Backing up current certificates to $BACKUP_FILE"
    tar -czf "$BACKUP_FILE" -C "$(dirname "$CERT_DIR")" "$(basename "$CERT_DIR")" || {
        log "WARNING: Failed to create certificate backup"
    }
fi

# Test NGINX configuration before proceeding
log "Testing NGINX configuration..."
if ! nginx -t &>/dev/null; then
    log "ERROR: NGINX configuration test failed. Aborting certificate renewal."
    send_notification "Certificate Renewal Failed: $DOMAIN" "NGINX configuration test failed on $(hostname)" "error"
    exit 1
fi

# Renew certificate with Certbot
log "Attempting to renew certificate with Certbot..."
if certbot renew --webroot -w "$WEBROOT" --cert-name "$DOMAIN" --quiet; then
    log "Certificate renewal process completed"
else
    log "ERROR: Certificate renewal failed"
    send_notification "Certificate Renewal Failed: $DOMAIN" "Certbot renewal command failed on $(hostname). Check logs at $LOG_FILE" "error"
    exit 1
fi

# Verify certificate existence and validity
if [ -f "$CERT_DIR/fullchain.pem" ]; then
    EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_DIR/fullchain.pem" | cut -d= -f2)
    CURRENT_DATE=$(date +%s)
    EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" +%s)
    DAYS_LEFT=$(( (EXPIRY_TIMESTAMP - CURRENT_DATE) / 86400 ))
    
    log "Certificate valid until: $EXPIRY_DATE ($DAYS_LEFT days left)"
    
    # Verify certificate matches domain
    CERT_DOMAIN=$(openssl x509 -in "$CERT_DIR/fullchain.pem" -text -noout | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/DNS://g; s/, /\n/g' | grep "^$DOMAIN$" || echo "")
    
    if [ -z "$CERT_DOMAIN" ]; then
        log "WARNING: Domain $DOMAIN not found in the certificate's Subject Alternative Name field"
        send_notification "Certificate Domain Mismatch: $DOMAIN" "The renewed certificate may not match the intended domain on $(hostname)" "warning"
    fi
    
    # Alert if certificate will expire soon
    if [ "$DAYS_LEFT" -lt "$RENEWAL_THRESHOLD" ]; then
        log "WARNING: Certificate will expire in $DAYS_LEFT days"
        send_notification "Certificate Expiring Soon: $DOMAIN" "Certificate will expire in $DAYS_LEFT days on $(hostname)" "warning"
    fi
else
    log "ERROR: Certificate files not found after renewal"
    send_notification "Certificate Not Found: $DOMAIN" "Certificate files not found after renewal on $(hostname)" "error"
    exit 1
fi

# Reload NGINX to apply new certificate
log "Reloading NGINX to apply new certificate..."
if systemctl reload nginx; then
    log "NGINX reloaded successfully"
else
    log "ERROR: Failed to reload NGINX"
    send_notification "NGINX Reload Failed: $DOMAIN" "Failed to reload NGINX after certificate renewal on $(hostname)" "error"
    exit 1
fi

# Verify HTTPS connection with the new certificate
log "Verifying HTTPS connection..."
if command -v curl &>/dev/null; then
    HTTPS_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" || echo "000")
    if [ "$HTTPS_CHECK" = "200" ] || [ "$HTTPS_CHECK" = "301" ] || [ "$HTTPS_CHECK" = "302" ]; then
        log "HTTPS verification successful (HTTP status: $HTTPS_CHECK)"
    else
        log "WARNING: HTTPS verification returned unexpected status: $HTTPS_CHECK"
        send_notification "HTTPS Verification Issue: $DOMAIN" "HTTPS verification returned status code $HTTPS_CHECK on $(hostname)" "warning"
    fi
else
    log "WARNING: curl not found, skipping HTTPS verification"
fi

# Clean up old backups (keep last 5)
find "$BACKUP_DIR" -name "$DOMAIN-*.tar.gz" -type f -mtime +30 -delete 2>/dev/null || true

log "Certificate renewal process completed successfully"
send_notification "Certificate Renewed Successfully: $DOMAIN" "Certificate renewed with $DAYS_LEFT days validity on $(hostname)" "info"

exit 0