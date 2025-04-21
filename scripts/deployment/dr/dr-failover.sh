#!/bin/bash
# Cloud Infrastructure Platform - Disaster Recovery Failover Script
# Usage: ./dr-failover.sh --activate-region [primary|secondary] [--force]
#
# This script activates the specified region during disaster recovery,
# ensuring database replication, service activation, and proper readiness checks.

set -euo pipefail

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/cloud-platform/dr-failover.log"
ENV_FILE="${PROJECT_ROOT}/deployment/environments/production.env"
CONFIG_DIR="${PROJECT_ROOT}/deployment/infrastructure"
FORCE=false
TARGET_REGION=""

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Load environment variables
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
fi

PRIMARY_REGION="${PRIMARY_REGION:-us-west-2}"
SECONDARY_REGION="${SECONDARY_REGION:-us-east-1}"

# Functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    # Also log to stdout if not in quiet mode
    if [[ "${QUIET:-false}" != "true" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
    fi
}

check_region_status() {
    local region=$1
    log "Checking status of region: $region"
    
    # Check load balancer health
    if [[ "$region" == "$PRIMARY_REGION" ]]; then
        ENDPOINT="${PRIMARY_REGION_ENDPOINT:-primary-lb.cloud-platform.example.com}"
    else
        ENDPOINT="${SECONDARY_REGION_ENDPOINT:-secondary-lb.cloud-platform.example.com}"
    fi
    
    # Check HTTP endpoint health
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "https://${ENDPOINT}/health" || echo "000")
    
    if [[ "$STATUS_CODE" == "200" ]]; then
        log "Region $region is healthy (HTTP 200)"
        echo "active"
    else
        log "Region $region appears to be unhealthy (HTTP $STATUS_CODE)"
        echo "inactive"
    fi
}

verify_database_status() {
    local region=$1
    log "Verifying database status in $region region"
    
    # Adjust connection parameters based on region
    local db_host
    if [[ "$region" == "$PRIMARY_REGION" ]]; then
        db_host="${PRIMARY_DB_HOST:-primary-db.internal}"
    else
        db_host="${SECONDARY_DB_HOST:-secondary-db.internal}"
    fi
    
    # Check database connectivity and replication status
    ${PROJECT_ROOT}/scripts/database/db_verify.sh --host "$db_host" --environment production || {
        log "ERROR: Database verification failed in $region region"
        return 1
    }
    
    log "Database verification successful in $region region"
    return 0
}

activate_region() {
    local region=$1
    log "Activating $region region for failover..."
    
    # Step 1: Ensure database availability
    log "Step 1: Ensuring database availability"
    verify_database_status "$region" || {
        if [[ "$FORCE" != "true" ]]; then
            log "ERROR: Cannot proceed with failover due to database issues"
            log "Use --force to override this check"
            return 1
        else
            log "WARNING: Proceeding with failover despite database issues (--force specified)"
        fi
    }
    
    # Step 2: Scale up services in target region
    log "Step 2: Scaling up services in $region region"
    if [[ "$region" == "$PRIMARY_REGION" ]]; then
        CLUSTER_NAME="${PRIMARY_CLUSTER:-primary-cluster}"
    else
        CLUSTER_NAME="${SECONDARY_CLUSTER:-secondary-cluster}"
    }
    
    if command -v aws &> /dev/null; then
        aws autoscaling update-auto-scaling-group \
            --auto-scaling-group-name "$CLUSTER_NAME" \
            --min-size 3 \
            --desired-capacity 3 \
            --region "$region" || {
            log "WARNING: Failed to scale up services in $region region"
        }
    fi
    
    # Step 3: Wait for services to be ready
    log "Step 3: Waiting for services to be ready in $region region"
    for i in {1..12}; do
        status=$(check_region_status "$region")
        if [[ "$status" == "active" ]]; then
            log "Services are ready in $region region"
            break
        else
            log "Waiting for services to be ready (attempt $i/12)"
            sleep 10
        fi
        
        if [[ $i -eq 12 ]]; then
            log "WARNING: Services did not become ready in time"
            if [[ "$FORCE" != "true" ]]; then
                log "ERROR: Cannot proceed with failover. Use --force to override."
                return 1
            fi
        fi
    done
    
    # Step 4: Update DNS to point to the activated region
    log "Step 4: Updating DNS configuration"
    ${PROJECT_ROOT}/scripts/deployment/update-dns.sh --point-to "$region" || {
        log "ERROR: Failed to update DNS configuration"
        return 1
    }
    
    # Step 5: Update monitoring and alerting for new active region
    log "Step 5: Updating monitoring configuration"
    if [ -x "${PROJECT_ROOT}/scripts/monitoring/update-monitoring.sh" ]; then
        ${PROJECT_ROOT}/scripts/monitoring/update-monitoring.sh --primary-region "$region" || {
            log "WARNING: Failed to update monitoring configuration"
        }
    else
        log "WARNING: Monitoring update script not found, skipping this step"
    fi
    
    # Step 6: Verify file integrity in the region
    log "Step 6: Verifying file integrity in $region region"
    if [ -x "${PROJECT_ROOT}/scripts/security/verify_files.py" ]; then
        python3 "${PROJECT_ROOT}/scripts/security/verify_files.py" --environment production --region "$region" || {
            log "WARNING: File integrity verification failed"
        }
    else
        log "WARNING: File integrity verification script not found, skipping this verification"
    fi
    
    # Step 7: Verify the failover with health check
    log "Step 7: Verifying failover completion with health checks"
    if [ -x "${PROJECT_ROOT}/scripts/monitoring/health-check.sh" ]; then
        ${PROJECT_ROOT}/scripts/monitoring/health-check.sh production --region "$region" --dr-mode || {
            log "WARNING: Health checks failed after failover"
        }
    else
        log "WARNING: Health check script not found, skipping health verification"
    fi
    
    # For additional validation
    if [ "${COMPREHENSIVE_CHECK:-false}" = "true" ]; then
        log "Running comprehensive smoke tests"
        if [ -x "${PROJECT_ROOT}/scripts/testing/smoke-test.sh" ]; then
            ${PROJECT_ROOT}/scripts/testing/smoke-test.sh production --region "$region" --dr-mode || {
                log "WARNING: Smoke tests failed after failover"
            }
        else
            log "WARNING: Smoke test script not found, skipping comprehensive testing"
        fi
    fi
    
    log "Region $region has been successfully activated as the primary region"
    return 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --activate-region)
            TARGET_REGION="$2"
            shift
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        *)
            log "ERROR: Unknown option: $key"
            echo "Usage: $0 --activate-region [primary|secondary] [--force] [--quiet]"
            exit 1
            ;;
    esac
done

# Validate arguments
if [[ -z "$TARGET_REGION" ]]; then
    log "ERROR: Target region not specified"
    echo "Usage: $0 --activate-region [primary|secondary] [--force] [--quiet]"
    exit 1
fi

if [[ "$TARGET_REGION" != "primary" && "$TARGET_REGION" != "secondary" ]]; then
    log "ERROR: Invalid region specified: $TARGET_REGION. Use 'primary' or 'secondary'."
    echo "Usage: $0 --activate-region [primary|secondary] [--force] [--quiet]"
    exit 1
fi

# Convert region name to actual region ID
if [[ "$TARGET_REGION" == "primary" ]]; then
    REGION_ID="$PRIMARY_REGION"
else
    REGION_ID="$SECONDARY_REGION"
fi

# Execute failover
log "Starting failover process to $TARGET_REGION region ($REGION_ID)..."

# Check if the target region is already active
if [[ "$FORCE" != "true" ]]; then
    current_status=$(check_region_status "$REGION_ID")
    if [[ "$current_status" == "active" ]]; then
        log "Target region $TARGET_REGION ($REGION_ID) is already active. No failover needed."
        exit 0
    fi
fi

# If we're activating secondary region, verify primary is down unless forced
if [[ "$TARGET_REGION" == "secondary" && "$FORCE" != "true" ]]; then
    primary_status=$(check_region_status "$PRIMARY_REGION")
    if [[ "$primary_status" == "active" ]]; then
        log "WARNING: Primary region appears to be active. Use --force to override."
        log "This might result in split-brain scenario if primary is actually functional."
        exit 1
    fi
fi

# Perform the actual failover
if activate_region "$REGION_ID"; then
    log "Failover to $TARGET_REGION region ($REGION_ID) completed successfully"
    
    # Send notifications about the failover
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority high \
            --subject "DR Failover Completed: $TARGET_REGION region activated" \
            --message "Disaster recovery failover to $TARGET_REGION region ($REGION_ID) has been completed successfully at $(date)."
    fi
    
    # Ensure DR events log directory exists
    mkdir -p "/var/log/cloud-platform"
    
    # Log the failover event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_FAILOVER,$TARGET_REGION,$REGION_ID,SUCCESS" >> /var/log/cloud-platform/dr-events.log    

    exit 0
else
    log "ERROR: Failover to $TARGET_REGION region ($REGION_ID) failed"
    
    # Send failure notification
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority critical \
            --subject "DR Failover FAILED: $TARGET_REGION region activation failed" \
            --message "Disaster recovery failover to $TARGET_REGION region ($REGION_ID) has FAILED at $(date). Immediate attention required!"
    fi
    
    # Log the failover failure event for audit purposes
    echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_FAILOVER,$TARGET_REGION,$REGION_ID,FAILURE" >> /var/log/cloud-platform/audit.log
    
    exit 1
fi