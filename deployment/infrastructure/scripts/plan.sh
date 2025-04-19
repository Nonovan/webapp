#!/bin/bash
# Generate Terraform plan for Cloud Infrastructure Platform
# Usage: ./plan.sh [environment]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INFRA_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT=${1:-production}
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

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Generating Terraform plan for $ENVIRONMENT environment"

# Ensure we're in the infrastructure directory
cd "$INFRA_ROOT"

# Initialize and select workspace
"$SCRIPT_DIR/init.sh" "$ENVIRONMENT"

# Check if tfvars file exists
TFVARS_FILE="environments/${ENVIRONMENT}.tfvars"
if [[ ! -f "$TFVARS_FILE" ]]; then
    log "Error: Terraform variables file not found: $TFVARS_FILE"
    exit 1
fi

# Ensure output directory exists
mkdir -p "plans"

# Generate terraform plan
PLAN_FILE="plans/${ENVIRONMENT}-$(date +%Y%m%d%H%M%S).tfplan"
log "Generating plan: $PLAN_FILE"

terraform plan -var-file="$TFVARS_FILE" -out="$PLAN_FILE"

log "Plan generated: $PLAN_FILE"
log "To apply this plan, run: ./scripts/apply.sh $ENVIRONMENT $PLAN_FILE"