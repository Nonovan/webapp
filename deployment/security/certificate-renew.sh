#!/bin/bash
# SSL certificate renewal script for Cloud Infrastructure Platform
# Uses Certbot for Let's Encrypt certificate renewal

# Configuration
DOMAIN="cloud-platform.example.com"
EMAIL="admin@example.com"
WEBROOT="/var/www/html"
NGINX_CONF="/etc/nginx/sites-available/cloud-platform"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
LOG_FILE="/var/log/cloud-platform/cert-renewal.log"

# Ensure log directory exists
mkdir -p $(dirname "$LOG_FILE")

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Check if Certbot is installed
if ! command -v certbot &> /dev/null; then
    log "ERROR: Certbot is not installed. Please install it first."
    exit 1
fi

log "Starting certificate renewal process for $DOMAIN"

# Test NGINX configuration before proceeding
log "Testing NGINX configuration..."
nginx -t
if [ $? -ne 0 ]; then
    log "ERROR: NGINX configuration test failed. Aborting certificate renewal."
    exit 1
fi

# Renew certificate
log "Attempting to renew certificate with Certbot..."
certbot renew --webroot -w $WEBROOT --cert-name $DOMAIN --quiet

# Check the result
if [ $? -eq 0 ]; then
    log "Certificate renewal successful"

    # Verify certificate validity
    if [ -f "$CERT_DIR/fullchain.pem" ]; then
        EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_DIR/fullchain.pem" | cut -d= -f2)
        DAYS_LEFT=$(( ( $(date -d "$EXPIRY_DATE" +%s) - $(date +%s) ) / 86400 ))
        log "Certificate valid until: $EXPIRY_DATE ($DAYS_LEFT days left)"
    else
        log "WARNING: Certificate files not found at expected location"
    fi

    # Reload NGINX to apply the new certificate
    log "Reloading NGINX to apply new certificate..."
    systemctl reload nginx
    if [ $? -eq 0 ]; then
        log "NGINX reloaded successfully"
    else
        log "ERROR: Failed to reload NGINX"
    fi
else
    log "ERROR: Certificate renewal failed"
fi

# Check certificate security rating using SSLLabs (optional)
if command -v curl &> /dev/null; then
    log "Requesting SSL Labs assessment..."
    curl -s "<https://api.ssllabs.com/api/v3/analyze?host=$DOMAIN>" > /dev/null
    log "SSL Labs assessment requested. Results will be available at: <https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN>"
fi

log "Certificate renewal process completed"
