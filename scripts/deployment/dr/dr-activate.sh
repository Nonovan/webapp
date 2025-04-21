#!/bin/bash
# DR Activation Script for Cloud Infrastructure Platform
# Usage: ./dr-activate.sh [--force] [--skip-verification]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INFRA_ROOT="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$(dirname "$INFRA_ROOT")")"
FORCE=false
SKIP_VERIFICATION=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --force)
            FORCE=true
            shift
            ;;
        --skip-verification)
            SKIP_VERIFICATION=true
            shift
            ;;
        *)
            echo "Unknown option: $key"
            echo "Usage: $0 [--force] [--skip-verification]"
            exit 1
            ;;
    esac
done

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting DR infrastructure activation process"

# Ensure directories exist
mkdir -p "/var/log/cloud-platform"

# First, run the Terraform apply with DR recovery config
log "Deploying DR recovery infrastructure"
"$SCRIPT_DIR/apply.sh" dr-recover ${FORCE:+--auto-approve}

if [[ $? -ne 0 ]]; then
    log "ERROR: Failed to deploy DR infrastructure"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_INFRASTRUCTURE_ACTIVATION,FAILURE" >> "/var/log/cloud-platform/dr-events.log"
    exit 1
fi

# Verify infrastructure was successfully deployed
if [[ "$SKIP_VERIFICATION" != "true" ]]; then
    log "Verifying infrastructure deployment"
    
    # Extract outputs
    DB_ENDPOINT=$(terraform -chdir="$INFRA_ROOT" output -raw primary_db_endpoint)
    LB_DNS=$(terraform -chdir="$INFRA_ROOT" output -raw secondary_lb_dns_name)
    
    # Check if the load balancer is responding
    log "Checking load balancer health"
    LB_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${LB_DNS}/health" || echo "000")
    if [[ "$LB_STATUS" != "200" ]]; then
        log "WARNING: Load balancer health check failed with status $LB_STATUS"
        if [[ "$FORCE" != "true" ]]; then
            log "Use --force to activate despite verification failure"
            echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_INFRASTRUCTURE_ACTIVATION,VERIFICATION_FAILED" >> "/var/log/cloud-platform/dr-events.log"
            exit 1
        fi
    else
        log "Load balancer health check succeeded"
    fi
    
    # Check database connectivity if db_verify.sh exists
    if [[ -x "${PROJECT_ROOT}/scripts/database/db_verify.sh" ]]; then
        log "Checking database connectivity"
        DB_HOST=$(echo "$DB_ENDPOINT" | cut -d':' -f1)
        "${PROJECT_ROOT}/scripts/database/db_verify.sh" --host "$DB_HOST" --environment production --quick-check
        if [[ $? -ne 0 ]]; then
            log "WARNING: Database verification failed"
            if [[ "$FORCE" != "true" ]]; then
                log "Use --force to activate despite verification failure"
                echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_INFRASTRUCTURE_ACTIVATION,DB_VERIFICATION_FAILED" >> "/var/log/cloud-platform/dr-events.log"
                exit 1
            fi
        else
            log "Database verification succeeded"
        fi
    else
        log "WARNING: Database verification script not found, skipping"
    fi
fi

# Update Route53 DNS to point to the DR infrastructure
log "Updating DNS configuration"
if [[ -x "${PROJECT_ROOT}/scripts/deployment/update-dns.sh" ]]; then
    "${PROJECT_ROOT}/scripts/deployment/update-dns.sh" --point-to secondary ${FORCE:+--force}
    if [[ $? -ne 0 ]]; then
        log "WARNING: DNS update failed"
        if [[ "$FORCE" != "true" ]]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_INFRASTRUCTURE_ACTIVATION,DNS_UPDATE_FAILED" >> "/var/log/cloud-platform/dr-events.log"
        fi
    else
        log "DNS updated successfully"
    fi
else
    log "WARNING: DNS update script not found, skipping"
fi

# Call the dr-failover.sh script if it exists
if [[ -x "${PROJECT_ROOT}/scripts/deployment/dr-failover.sh" ]]; then
    log "Running DR failover script"
    "${PROJECT_ROOT}/scripts/deployment/dr-failover.sh" --activate-region secondary ${FORCE:+--force}
else
    log "WARNING: DR failover script not found, skipping application failover"
fi

log "DR infrastructure activation completed"
echo "$(date '+%Y-%m-%d %H:%M:%S'),DR_INFRASTRUCTURE_ACTIVATION,SUCCESS" >> "/var/log/cloud-platform/dr-events.log"