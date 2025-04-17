#!/bin/bash
# Check SSL certificate expiration dates

CERTS_DIR="/opt/cloud-platform/instance/ssl"
EXPIRY_THRESHOLD=30  # Days before expiry to start warning
LOG_FILE="/var/log/cloud-platform/security.log"

check_cert() {
    cert_file=$1
    name=$(basename "$cert_file")
    
    # Get expiration date
    expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
    
    # Convert to seconds since epoch
    expiry_epoch=$(date -d "$expiry_date" +%s)
    current_epoch=$(date +%s)
    
    # Calculate days until expiry
    seconds_diff=$((expiry_epoch - current_epoch))
    days_diff=$((seconds_diff / 86400))
    
    if [ $days_diff -le $EXPIRY_THRESHOLD ]; then
        echo "[$(date)] WARNING: Certificate $name will expire in $days_diff days on $expiry_date" | tee -a "$LOG_FILE"
        
        # Send email alert if very close to expiry
        if [ $days_diff -le 7 ]; then
            mail -s "CRITICAL: SSL Certificate Expiring in $days_diff days" admin@example.com <<EOF
Certificate $name will expire on $expiry_date.
Please renew it immediately to avoid service disruption.
EOF
        fi
        return 1
    else
        echo "[$(date)] INFO: Certificate $name will expire in $days_diff days on $expiry_date" >> "$LOG_FILE"
        return 0
    fi
}

# Check all certificates
find "$CERTS_DIR" -name "*.crt" -o -name "*.pem" | while read cert; do
    check_cert "$cert"
done
