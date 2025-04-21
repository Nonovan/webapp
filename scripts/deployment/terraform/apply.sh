#!/bin/bash
# Apply Terraform plan for Cloud Infrastructure Platform
# Usage: ./apply.sh [environment] [plan_file]
#        ./apply.sh [environment] --auto-approve

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INFRA_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT=${1:-production}
PLAN_FILE=$2
AUTO_APPROVE=false
VALID_ENVS=("development" "staging" "production" "dr-recover")

# Validate environment
valid_env=false
for env in "${VALID_ENVS[@]}"; do
    if [[ "$ENVIRONMENT" == "$env" ]]; then
        valid_env=true
        break
    fi
done

if [[ "$valid_env" == "false" ]]; then
    echo "Error: Invalid environment '$ENVIRONMENT'"
    echo "Valid environments: ${VALID_ENVS[*]}"
    exit 1
fi

if [[ "$PLAN_FILE" == "--auto-approve" ]]; then
    AUTO_APPROVE=true
    PLAN_FILE=""
fi

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Applying Terraform for $ENVIRONMENT environment"

# Ensure we're in the infrastructure directory
cd "$INFRA_ROOT"

# Initialize and select workspace
"$SCRIPT_DIR/init.sh" "$ENVIRONMENT"

# If plan file is specified, apply it
if [[ -n "$PLAN_FILE" ]]; then
    if [[ ! -f "$PLAN_FILE" ]]; then
        log "Error: Plan file not found: $PLAN_FILE"
        exit 1
    fi
    
    log "Applying plan: $PLAN_FILE"
    terraform apply "$PLAN_FILE"
    
# Otherwise, apply with or without auto-approve
else
    TFVARS_FILE="environments/${ENVIRONMENT}.tfvars"
    if [[ ! -f "$TFVARS_FILE" ]]; then
        log "Error: Terraform variables file not found: $TFVARS_FILE"
        exit 1
    fi
    
    if [[ "$AUTO_APPROVE" == true ]]; then
        log "Applying with auto-approve"
        terraform apply -var-file="$TFVARS_FILE" -auto-approve
    else
        log "Applying with interactive approval"
        terraform apply -var-file="$TFVARS_FILE"
    fi
fi

# Create output directory if it doesn't exist
mkdir -p "outputs"

# Save outputs to a file
terraform output -json > "outputs/${ENVIRONMENT}-output-$(date +%Y%m%d%H%M%S).json"

log "Terraform apply completed for $ENVIRONMENT environment"
log "Outputs saved to outputs/${ENVIRONMENT}-output-*.json"

# For DR recovery, generate a report
if [[ "$ENVIRONMENT" == "dr-recover" ]]; then
    log "Generating DR recovery report"
    
    # Create DR events log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"
    
    # Log the infrastructure deployment event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),INFRASTRUCTURE_DEPLOYMENT,${ENVIRONMENT},SUCCESS" >> "/var/log/cloud-platform/dr-events.log"
    
    # Display important outputs for DR recovery
    log "=========== DR RECOVERY INFO ==========="
    terraform output secondary_lb_dns_name
    terraform output primary_db_endpoint
    log "========================================"
fi