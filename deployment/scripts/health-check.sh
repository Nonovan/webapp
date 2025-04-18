#!/bin/bash
# Health Check Script for Cloud Infrastructure Platform
# Performs various health checks and generates a report
# Usage: ./health-check.sh [environment]

set -e

# Default settings
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
OUTPUT_FORMAT=${OUTPUT_FORMAT:-text}  # text or json
EMAIL_RECIPIENT=${EMAIL_RECIPIENT:-""}

# Create temporary report file
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="/tmp/health-check-${TIMESTAMP}.txt"
OVERALL_STATUS="HEALTHY"

# Ensure log directory exists
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/health-check.log"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Function to check a component and update overall status
check_component() {
    local name="$1"
    local check_command="$2"
    
    echo "Checking $name..." | tee -a "$REPORT_FILE"
    
    if eval "$check_command"; then
        echo "✅ $name: OK" | tee -a "$REPORT_FILE"
        return 0
    else
        echo "❌ $name: FAILED" | tee -a "$REPORT_FILE"
        OVERALL_STATUS="UNHEALTHY"
        return 1
    fi
}

log "Starting health check for ${ENVIRONMENT} environment"

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
fi

# Set default URL if not defined in environment file
APP_URL=${APP_URL:-"http://localhost:5000"}
log "Checking application at $APP_URL"

# Initialize report file
echo "HEALTH CHECK REPORT - ${ENVIRONMENT}" > "$REPORT_FILE"
echo "----------------------------------------" >> "$REPORT_FILE"
echo "Timestamp: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Initialize JSON output if needed
if [ "$OUTPUT_FORMAT" = "json" ]; then
    JSON_OUTPUT="{\"timestamp\":\"$(date -Iseconds)\",\"environment\":\"${ENVIRONMENT}\",\"checks\":{"
fi

# 1. API health check
api_status=$(check_component "API Health" "curl -s -f -o /dev/null ${APP_URL}/api/health")

# 2. Database connectivity
db_status=$(check_component "Database" "curl -s -f ${APP_URL}/api/health | grep -q '\"database\":\\s*\"ok\"'")

# 3. Disk space
disk_status=$(check_component "Disk Space" "df -h / | awk 'NR==2 {print \$5}' | sed 's/%//' | awk '{if(\$1<90)exit 0; else exit 1}'")

# 4. Memory usage
memory_status=$(check_component "Memory Usage" "free -m | awk '/^Mem:/ {if(\$3/\$2*100<90)exit 0; else exit 1}'")

# 5. CPU load
load_status=$(check_component "CPU Load" "uptime | awk '{print \$(NF-2)}' | sed 's/,//' | awk '{if(\$1<$(nproc)*2)exit 0; else exit 1}'")

# 6. Essential services
services=("nginx" "postgresql" "redis-server" "cloud-platform")
services_status=0

echo "Checking services..." | tee -a "$REPORT_FILE"
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "✅ $service: Running" >> "$REPORT_FILE"
    else
        echo "❌ $service: Not running" >> "$REPORT_FILE"
        services_status=1
        OVERALL_STATUS="UNHEALTHY"
    fi
done

# 7. Check log for critical errors
log_status=$(check_component "Application Logs" "grep -i 'critical\\|exception' /var/log/cloud-platform/app.log --max-count=5 | wc -l | awk '{if(\$1 == 0) exit 0; else exit 1}'")

# 8. SSL certificate validity (if applicable)
ssl_status="not_applicable"
if [ "$ENVIRONMENT" = "production" ] || [ "$ENVIRONMENT" = "staging" ]; then
    SSL_CERT="/etc/ssl/certs/cloud-platform.crt"
    if [ -f "$SSL_CERT" ]; then
        ssl_status=$(check_component "SSL Certificate" "openssl x509 -checkend 2592000 -noout -in $SSL_CERT")
    fi
fi

# 9. Security updates check
security_updates_status="not_checked"
if [ "$ENVIRONMENT" = "production" ] || [ "$ENVIRONMENT" = "staging" ]; then
    if [ -f "${SCRIPT_DIR}/check_security_updates.sh" ]; then
        updates_count=$("${SCRIPT_DIR}/check_security_updates.sh" --quiet || echo "ERROR")
        if [ "$updates_count" = "ERROR" ]; then
            security_updates_status=$(check_component "Security Updates" "false")
        elif [ "$updates_count" -gt 10 ]; then
            security_updates_status=$(check_component "Security Updates" "false")
            echo "  - $updates_count security updates available" >> "$REPORT_FILE"
        elif [ "$updates_count" -gt 0 ]; then
            echo "⚠️ Security Updates: $updates_count available" >> "$REPORT_FILE"
            echo "  - Consider updating soon" >> "$REPORT_FILE"
        else
            security_updates_status=$(check_component "Security Updates" "true")
        fi
    fi
fi

# 10. File integrity check
integrity_status="not_checked"
if [ "$ENVIRONMENT" = "production" ] && command -v aide &>/dev/null; then
    integrity_status=$(check_component "File Integrity" "aide --check | grep -q 'No differences found'")
fi

# Summary
echo "" >> "$REPORT_FILE"
echo "SUMMARY" >> "$REPORT_FILE"
echo "----------------------------------------" >> "$REPORT_FILE"
echo "Overall Status: $OVERALL_STATUS" >> "$REPORT_FILE"
echo "Timestamp: $TIMESTAMP" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Generate JSON output if requested
if [ "$OUTPUT_FORMAT" = "json" ]; then
    JSON_OUTPUT="${JSON_OUTPUT}\"api\":\"$api_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"database\":\"$db_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"disk\":\"$disk_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"memory\":\"$memory_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"load\":\"$load_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"services\":\"$services_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"logs\":\"$log_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"ssl\":\"$ssl_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"security_updates\":\"$security_updates_status\""
    JSON_OUTPUT="${JSON_OUTPUT},\"integrity\":\"$integrity_status\""
    JSON_OUTPUT="${JSON_OUTPUT}},\"overall_status\":\"$OVERALL_STATUS\"}"
    
    echo "$JSON_OUTPUT"
    
    if [ -n "$EMAIL_RECIPIENT" ]; then
        echo "$JSON_OUTPUT" | mail -s "[$ENVIRONMENT] Health Check Report: $OVERALL_STATUS" "$EMAIL_RECIPIENT"
    fi
else
    cat "$REPORT_FILE"
    
    if [ -n "$EMAIL_RECIPIENT" ]; then
        cat "$REPORT_FILE" | mail -s "[$ENVIRONMENT] Health Check Report: $OVERALL_STATUS" "$EMAIL_RECIPIENT"
    fi
fi

# Save report to log directory
cp "$REPORT_FILE" "$LOG_DIR/health-check-${TIMESTAMP}.txt"
log "Health check completed. Status: $OVERALL_STATUS"

# Clean up temp file
rm "$REPORT_FILE"

# Exit with appropriate status code
if [ "$OVERALL_STATUS" = "HEALTHY" ]; then
    exit 0
else
    exit 1
fi