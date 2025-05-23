#!/bin/bash
# Health Check Script for Cloud Infrastructure Platform
# Performs comprehensive health checks and generates a detailed report
# Usage: ./health-check.sh [environment] [--region primary|secondary] [--format text|json] [--notify [email]] [--dr-mode]

set -e

# Default settings
ENVIRONMENT=${1:-production}
REGION="primary"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
OUTPUT_FORMAT="text"  # text or json
EMAIL_RECIPIENT=""
NOTIFY=false
DR_MODE=false
KEEP_REPORTS=false

# Create temporary report file
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="/tmp/health-check-${ENVIRONMENT}-${TIMESTAMP}.txt"
JSON_REPORT_FILE="/tmp/health-check-${ENVIRONMENT}-${TIMESTAMP}.json"
OVERALL_STATUS="HEALTHY"
COMPONENTS_STATUS=()

# Parse arguments - shift the first argument if it's the environment name
shift_count=0
if [[ ! -z "$1" && "$1" != --* ]]; then
    shift_count=1  # Skip the environment parameter in the while loop
fi

while [[ $# -gt $shift_count ]]; do
    key="${1}"
    case $key in
        --region)
            REGION="${2}"
            if [[ "$REGION" != "primary" && "$REGION" != "secondary" ]]; then
                echo "Error: Region must be 'primary' or 'secondary'"
                exit 1
            fi
            shift 2
            ;;
        --format)
            OUTPUT_FORMAT="${2}"
            if [[ "$OUTPUT_FORMAT" != "text" && "$OUTPUT_FORMAT" != "json" ]]; then
                echo "Error: Format must be 'text' or 'json'"
                exit 1
            fi
            shift 2
            ;;
        --notify)
            NOTIFY=true
            if [[ ! -z "${2}" && "${2}" != --* ]]; then
                EMAIL_RECIPIENT="${2}"
                shift
            fi
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        --keep-reports)
            KEEP_REPORTS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [environment] [options]"
            echo "Options:"
            echo "  --region primary|secondary   Set region to test"
            echo "  --format text|json           Output format"
            echo "  --notify [email]             Send notification with results"
            echo "  --dr-mode                    Log to DR events system"
            echo "  --keep-reports               Keep report files after execution"
            echo "  --help, -h                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

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
    local is_critical="${3:-true}"
    local start_time=$(date +%s.%N)
    
    log "Checking $name..."
    
    if eval "$check_command"; then
        local status="HEALTHY"
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc)
        
        echo "✅ $name: OK (${duration}s)" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"$name\",\"status\":\"$status\",\"time\":\"$duration\",\"critical\":$is_critical}")
        return 0
    else
        local status="UNHEALTHY"
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc)
        
        echo "❌ $name: FAILED (${duration}s)" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"$name\",\"status\":\"$status\",\"time\":\"$duration\",\"critical\":$is_critical}")
        
        if [[ "$is_critical" = true ]]; then
            OVERALL_STATUS="UNHEALTHY"
        fi
        
        return 1
    fi
}

log "Starting health check for ${ENVIRONMENT} environment in ${REGION} region"
echo "HEALTH CHECK REPORT: ${ENVIRONMENT} (${REGION} region)" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "----------------------------------------" >> "$REPORT_FILE"

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Determine endpoints based on region
if [[ "$REGION" = "primary" ]]; then
    API_ENDPOINT="${PRIMARY_API_ENDPOINT:-https://api.cloud-platform.example.com}"
    WEB_ENDPOINT="${PRIMARY_WEB_ENDPOINT:-https://cloud-platform.example.com}"
    DB_HOST="${PRIMARY_DB_HOST:-primary-db.internal}"
    REDIS_HOST="${PRIMARY_REDIS_HOST:-primary-redis.internal}"
else
    API_ENDPOINT="${SECONDARY_API_ENDPOINT:-https://api-dr.cloud-platform.example.com}"
    WEB_ENDPOINT="${SECONDARY_WEB_ENDPOINT:-https://dr.cloud-platform.example.com}"
    DB_HOST="${SECONDARY_DB_HOST:-secondary-db.internal}"
    REDIS_HOST="${SECONDARY_REDIS_HOST:-secondary-redis.internal}"
fi

# Component checks
echo "Core Components:" >> "$REPORT_FILE"
echo "----------------" >> "$REPORT_FILE"

# 1. API Health
check_component "API Health" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/health | grep -q 200"

# 2. Web UI
check_component "Web UI" "curl -s -o /dev/null -w '%{http_code}' ${WEB_ENDPOINT} | grep -q 200"

# 3. Database connectivity
if command -v psql &> /dev/null && [[ "$DB_HOST" != "primary-db.internal" && "$DB_HOST" != "secondary-db.internal" ]]; then
    check_component "Database" "PGPASSWORD=\"${DB_PASSWORD}\" psql -h ${DB_HOST} -U ${DB_USER} -d ${DB_NAME} -c 'SELECT 1' -q -t | grep -q 1"
elif [[ -x "${PROJECT_ROOT}/scripts/database/database-manager.sh" ]]; then
    check_component "Database" "${PROJECT_ROOT}/scripts/database/database-manager.sh verify-db --env ${ENVIRONMENT} --host ${DB_HOST} --quick-check"
elif [[ -x "${PROJECT_ROOT}/scripts/database/db_verify.sh" ]]; then
    check_component "Database" "${PROJECT_ROOT}/scripts/database/db_verify.sh --host ${DB_HOST} --environment ${ENVIRONMENT} --quick-check"
else 
    echo "⚠️ Database check skipped: No database client or verification script available" | tee -a "$REPORT_FILE"
    COMPONENTS_STATUS+=("{\"component\":\"Database\",\"status\":\"SKIPPED\",\"time\":\"0\",\"critical\":true}")
fi

# 4. Redis connectivity
if command -v redis-cli &> /dev/null && [[ "$REDIS_HOST" != "primary-redis.internal" && "$REDIS_HOST" != "secondary-redis.internal" ]]; then
    check_component "Redis" "redis-cli -h ${REDIS_HOST} ping | grep -q PONG"
else
    echo "⚠️ Redis check skipped: No Redis client available" | tee -a "$REPORT_FILE"
    COMPONENTS_STATUS+=("{\"component\":\"Redis\",\"status\":\"SKIPPED\",\"time\":\"0\",\"critical\":false}")
fi

echo "" >> "$REPORT_FILE"
echo "DR-Specific Components:" >> "$REPORT_FILE"
echo "----------------------" >> "$REPORT_FILE"

# 5. Database replication (DR-specific)
if [[ "$REGION" = "secondary" ]]; then
    if [[ -x "${PROJECT_ROOT}/scripts/database/database-manager.sh" ]]; then
        check_component "DB Replication" "${PROJECT_ROOT}/scripts/database/database-manager.sh check-replication --env ${ENVIRONMENT}" "true"
    elif [[ -x "${PROJECT_ROOT}/scripts/database/check_replication.sh" ]]; then
        check_component "DB Replication" "${PROJECT_ROOT}/scripts/database/check_replication.sh --environment ${ENVIRONMENT}" "true"
    else
        echo "⚠️ DB Replication check skipped: No replication check script available" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"DB Replication\",\"status\":\"SKIPPED\",\"time\":\"0\",\"critical\":true}")
    fi
elif [[ "$REGION" = "primary" ]]; then
    echo "ℹ️ DB Replication check not applicable for primary region" | tee -a "$REPORT_FILE"
    COMPONENTS_STATUS+=("{\"component\":\"DB Replication\",\"status\":\"NOT_APPLICABLE\",\"time\":\"0\",\"critical\":false}")
fi

# 6. Check file integrity
if [[ -x "${PROJECT_ROOT}/scripts/security/verify_files.py" ]]; then
    check_component "File Integrity" "python3 ${PROJECT_ROOT}/scripts/security/verify_files.py --environment ${ENVIRONMENT} --region ${REGION}" "true"
else
    echo "⚠️ WARNING: File integrity verification script not found, skipping integrity test" | tee -a "$REPORT_FILE"
    COMPONENTS_STATUS+=("{\"component\":\"File Integrity\",\"status\":\"SKIPPED\",\"time\":\"0\",\"critical\":true}")
fi

# 7. Region DNS resolution
check_component "DNS Resolution" "nslookup ${WEB_ENDPOINT} &> /dev/null" "true"

echo "" >> "$REPORT_FILE"
echo "Security Components:" >> "$REPORT_FILE"
echo "-------------------" >> "$REPORT_FILE"

# 8. SSL Certificate 
if command -v openssl &> /dev/null; then
    check_component "SSL Certificate" "echo | openssl s_client -connect ${WEB_ENDPOINT#https://}:443 -servername ${WEB_ENDPOINT#https://} 2>/dev/null | openssl x509 -noout -checkend 0" "true"
else
    echo "⚠️ SSL Certificate check skipped: OpenSSL not available" | tee -a "$REPORT_FILE"
    COMPONENTS_STATUS+=("{\"component\":\"SSL Certificate\",\"status\":\"SKIPPED\",\"time\":\"0\",\"critical\":true}")
fi

# 9. WAF Status
check_component "WAF Status" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/health/waf | grep -q 200" "false"

# 10. Security Headers
check_component "Security Headers" "curl -s -I ${WEB_ENDPOINT} | grep -q 'Strict-Transport-Security'" "false"

echo "" >> "$REPORT_FILE"
echo "Application Components:" >> "$REPORT_FILE"
echo "----------------------" >> "$REPORT_FILE"

# 11. Authentication Service
check_component "Authentication" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/auth/status | grep -q 200" "true"

# 12. Cloud Integration Service
check_component "Cloud Integration" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/cloud/status | grep -q 200" "true"

# 13. ICS Service (if enabled)
if [[ "${ICS_ENABLED:-false}" = "true" ]]; then
    check_component "ICS Integration" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/ics/status | grep -q 200" "true"
else
    echo "ℹ️ ICS Integration check skipped: Feature not enabled" | tee -a "$REPORT_FILE"
    COMPONENTS_STATUS+=("{\"component\":\"ICS Integration\",\"status\":\"NOT_ENABLED\",\"time\":\"0\",\"critical\":false}")
fi

# 14. Webhook Service
check_component "Webhook Service" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/webhooks/status | grep -q 200" "false"

# 15. System health indicators
echo "" >> "$REPORT_FILE"
echo "System Health:" >> "$REPORT_FILE"
echo "--------------" >> "$REPORT_FILE"

# Disk usage
if command -v df &> /dev/null; then
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    if [[ "$DISK_USAGE" -gt 90 ]]; then
        echo "❌ Disk Usage: CRITICAL - ${DISK_USAGE}% used" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"Disk Usage\",\"status\":\"CRITICAL\",\"value\":\"${DISK_USAGE}%\",\"critical\":true}")
        OVERALL_STATUS="UNHEALTHY"
    elif [[ "$DISK_USAGE" -gt 80 ]]; then
        echo "⚠️ Disk Usage: WARNING - ${DISK_USAGE}% used" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"Disk Usage\",\"status\":\"WARNING\",\"value\":\"${DISK_USAGE}%\",\"critical\":false}")
    else
        echo "✅ Disk Usage: OK - ${DISK_USAGE}% used" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"Disk Usage\",\"status\":\"HEALTHY\",\"value\":\"${DISK_USAGE}%\",\"critical\":false}")
    fi
fi

# Memory usage
if command -v free &> /dev/null; then
    MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2*100}')
    if [[ "$MEMORY_USAGE" -gt 90 ]]; then
        echo "❌ Memory Usage: CRITICAL - ${MEMORY_USAGE}% used" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"Memory Usage\",\"status\":\"CRITICAL\",\"value\":\"${MEMORY_USAGE}%\",\"critical\":true}")
        OVERALL_STATUS="UNHEALTHY"
    elif [[ "$MEMORY_USAGE" -gt 80 ]]; then
        echo "⚠️ Memory Usage: WARNING - ${MEMORY_USAGE}% used" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"Memory Usage\",\"status\":\"WARNING\",\"value\":\"${MEMORY_USAGE}%\",\"critical\":false}")
    else
        echo "✅ Memory Usage: OK - ${MEMORY_USAGE}% used" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"Memory Usage\",\"status\":\"HEALTHY\",\"value\":\"${MEMORY_USAGE}%\",\"critical\":false}")
    fi
fi

# CPU load
if [[ -f "/proc/loadavg" ]]; then
    CPU_LOAD=$(cat /proc/loadavg | awk '{print $1}')
    CORES=$(nproc 2>/dev/null || echo 1)
    CPU_LOAD_PCT=$(echo "$CPU_LOAD $CORES" | awk '{printf "%.0f", $1/$2*100}')
    
    if [[ "$CPU_LOAD_PCT" -gt 90 ]]; then
        echo "❌ CPU Load: CRITICAL - ${CPU_LOAD} (${CPU_LOAD_PCT}%)" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"CPU Load\",\"status\":\"CRITICAL\",\"value\":\"${CPU_LOAD_PCT}%\",\"critical\":true}")
        OVERALL_STATUS="UNHEALTHY"
    elif [[ "$CPU_LOAD_PCT" -gt 80 ]]; then
        echo "⚠️ CPU Load: WARNING - ${CPU_LOAD} (${CPU_LOAD_PCT}%)" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"CPU Load\",\"status\":\"WARNING\",\"value\":\"${CPU_LOAD_PCT}%\",\"critical\":false}")
    else
        echo "✅ CPU Load: OK - ${CPU_LOAD} (${CPU_LOAD_PCT}%)" | tee -a "$REPORT_FILE"
        COMPONENTS_STATUS+=("{\"component\":\"CPU Load\",\"status\":\"HEALTHY\",\"value\":\"${CPU_LOAD_PCT}%\",\"critical\":false}")
    fi
fi

# Final status and summary
echo "" >> "$REPORT_FILE"
echo "----------------------------------------" >> "$REPORT_FILE"
echo "OVERALL STATUS: ${OVERALL_STATUS}" >> "$REPORT_FILE"
echo "Time: $(date)" >> "$REPORT_FILE"

log "Health check completed with status: ${OVERALL_STATUS}"

# Create JSON output if needed
if [[ "$OUTPUT_FORMAT" = "json" ]]; then
    echo "{" > "$JSON_REPORT_FILE"
    echo "  \"environment\": \"${ENVIRONMENT}\"," >> "$JSON_REPORT_FILE"
    echo "  \"region\": \"${REGION}\"," >> "$JSON_REPORT_FILE"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$JSON_REPORT_FILE"
    echo "  \"overall_status\": \"${OVERALL_STATUS}\"," >> "$JSON_REPORT_FILE"
    echo "  \"components\": [" >> "$JSON_REPORT_FILE"
    
    # Join component statuses with commas
    local IFS=","
    echo "    ${COMPONENTS_STATUS[*]}" >> "$JSON_REPORT_FILE"
    
    echo "  ]" >> "$JSON_REPORT_FILE"
    echo "}" >> "$JSON_REPORT_FILE"
    
    # Validate JSON if jq is available
    if command -v jq &>/dev/null; then
        if ! jq '.' "$JSON_REPORT_FILE" > /dev/null 2>&1; then
            log "WARNING: Generated JSON may be invalid"
        fi
    fi
    
    cat "$JSON_REPORT_FILE"
else
    cat "$REPORT_FILE"
fi

# Send notification if requested
if [[ "$NOTIFY" = true && ! -z "$EMAIL_RECIPIENT" ]]; then
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority $([ "$OVERALL_STATUS" = "HEALTHY" ] && echo "low" || echo "high") \
            --subject "Health Check Report: ${ENVIRONMENT} (${REGION}) - ${OVERALL_STATUS}" \
            --message "$(cat $REPORT_FILE)" \
            --recipient "$EMAIL_RECIPIENT"
        log "Notification sent to $EMAIL_RECIPIENT"
    else
        log "WARNING: Could not send notification, send-notification.sh not found or not executable"
    fi
fi

# If in DR mode, log the status to DR events log
if [[ "$DR_MODE" = true ]]; then
    mkdir -p "/var/log/cloud-platform"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),HEALTH_CHECK,${ENVIRONMENT},${REGION},${OVERALL_STATUS}" >> "/var/log/cloud-platform/dr-events.log"
    log "Health check result logged to DR events log"
fi

# Cleanup temporary files unless we want to keep them
if [[ "${KEEP_REPORTS}" != "true" ]]; then
    rm -f "$REPORT_FILE" "$JSON_REPORT_FILE"
fi

# Exit with status code based on health
if [[ "$OVERALL_STATUS" = "HEALTHY" ]]; then
    exit 0
else
    exit 1
fi