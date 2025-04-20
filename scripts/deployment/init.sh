#!/bin/bash
# Initialize Terraform workspace for Cloud Infrastructure Platform
# Usage: ./init.sh [environment]

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

log "Initializing Terraform for $ENVIRONMENT environment"

# Ensure we're in the infrastructure directory
cd "$INFRA_ROOT"

# Check if tfstate bucket exists and create if needed
BUCKET_NAME="cloud-platform-terraform-state"
REGION="us-west-2"

if ! aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    log "Creating Terraform state bucket: $BUCKET_NAME"
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" \
        --create-bucket-configuration LocationConstraint="$REGION"
    
    aws s3api put-bucket-versioning \
        --bucket "$BUCKET_NAME" \
        --versioning-configuration Status=Enabled
    
    aws s3api put-bucket-encryption \
        --bucket "$BUCKET_NAME" \
        --server-side-encryption-configuration '{
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        }'
fi

# Check if DynamoDB table exists and create if needed
TABLE_NAME="terraform-state-lock"

if ! aws dynamodb describe-table --table-name "$TABLE_NAME" --region "$REGION" 2>/dev/null; then
    log "Creating DynamoDB table for state locking: $TABLE_NAME"
    aws dynamodb create-table \
        --table-name "$TABLE_NAME" \
        --attribute-definitions AttributeName=LockID,AttributeType=S \
        --key-schema AttributeName=LockID,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --region "$REGION"
fi

# Initialize Terraform
log "Running terraform init"
terraform init

# Select workspace (create if doesn't exist)
if ! terraform workspace select "$ENVIRONMENT" 2>/dev/null; then
    log "Creating new workspace: $ENVIRONMENT"
    terraform workspace new "$ENVIRONMENT"
else
    log "Selected workspace: $ENVIRONMENT"
fi

log "Terraform initialization complete for $ENVIRONMENT environment"