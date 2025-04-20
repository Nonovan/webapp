#!/bin/bash
# Output current Terraform state in JSON format
# Usage: ./output-state.sh [environment]

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

log "Outputting Terraform state for $ENVIRONMENT environment"

# Ensure we're in the infrastructure directory
cd "$INFRA_ROOT"

# Initialize and select workspace
"$SCRIPT_DIR/init.sh" "$ENVIRONMENT"

# Ensure output directory exists
mkdir -p "outputs"

# Output state
STATE_FILE="outputs/${ENVIRONMENT}-state-$(date +%Y%m%d%H%M%S).json"
terraform state pull > "$STATE_FILE"

# Output specific values
OUTPUT_FILE="outputs/${ENVIRONMENT}-values-$(date +%Y%m%d%H%M%S).json"
terraform output -json > "$OUTPUT_FILE"

log "State saved to: $STATE_FILE"
log "Output values saved to: $OUTPUT_FILE"