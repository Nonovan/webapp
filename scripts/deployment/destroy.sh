#!/bin/bash
# Destroy Terraform resources for Cloud Infrastructure Platform
# Usage: ./destroy.sh [environment]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INFRA_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT=${1:-development}
VALID_ENVS=("development" "staging" "dr-recover")

# Validate environment - prevent accidental production destroy
valid_env=false
for env in "${VALID_ENVS[@]}"; do
    if [[ "$ENVIRONMENT" == "$env" ]]; then
        valid_env=true
        break
    fi
done

if [[ "$valid_env" == "false" ]]; then
    echo "Error: Cannot destroy environment '$ENVIRONMENT'"
    echo "This script can only destroy: ${VALID_ENVS[*]}"
    echo "To destroy production, use manual terraform destroy"
    exit 1
fi

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "WARNING: This will destroy all resources in the $ENVIRONMENT environment"
read -p "Are you sure you want to continue? (yes/no) " confirmation
if [[ "$confirmation" != "yes" ]]; then
    log "Aborting destroy operation"
    exit 0
fi

if [[ "$ENVIRONMENT" == "dr-recover" ]]; then
    log "WARNING: You are destroying DR recovery infrastructure!"
    read -p "Type 'dr-recover' to confirm: " dr_confirm
    if [[ "$dr_confirm" != "dr-recover" ]]; then
        log "Aborting destroy operation"
        exit 0
    fi
fi

log "Proceeding with destroy for $ENVIRONMENT environment"

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

# Backup the current state before destroying
mkdir -p "backups"
BACKUP_FILE="backups/${ENVIRONMENT}-state-backup-$(date +%Y%m%d%H%M%S).json"
log "Backing up current state to $BACKUP_FILE"
terraform state pull > "$BACKUP_FILE"

# Destroy resources
log "Destroying resources for $ENVIRONMENT"
terraform destroy -var-file="$TFVARS_FILE"

log "Resource destruction completed for $ENVIRONMENT environment"
log "State backup saved to $BACKUP_FILE"