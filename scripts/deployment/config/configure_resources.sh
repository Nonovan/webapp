#!/bin/bash
# Resource Configuration Script for Cloud Infrastructure Platform
# This script configures compute, memory, storage, and network resources
# Usage: ./configure_resources.sh [--environment <env>] [--region <region>] [--auto-scale]
#
# Copyright (c) 2023-2024 Cloud Infrastructure Platform

# Strict error handling
set -o errexit
set -o pipefail
set -o nounset

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
REGION=""
AUTO_SCALE=false
DRY_RUN=false
FORCE=false
PROFILE=""
LOG_FILE="/var/log/cloud-platform/resource_config.log"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Load common functions
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh"
else
    echo "Error: common_functions.sh not found"
    exit 1
fi

# Default resource allocations by environment
declare -A CPU_LIMITS=(
    [development]=2
    [staging]=4
    [production]=8
    [dr-recovery]=8
)

declare -A MEMORY_LIMITS=(
    [development]="4Gi"
    [staging]="8Gi"
    [production]="16Gi"
    [dr-recovery]="16Gi"
)

declare -A DISK_SIZES=(
    [development]=50
    [staging]=100
    [production]=250
    [dr-recovery]=250
)

declare -A INSTANCE_TYPES=(
    [development]="t3.medium"
    [staging]="m5.large"
    [production]="m5.xlarge"
    [dr-recovery]="m5.xlarge"
)

# Default region settings by cloud provider
declare -A DEFAULT_REGIONS=(
    [aws]="us-west-2"
    [azure]="eastus"
    [gcp]="us-central1"
)

# Function to display usage
usage() {
    cat <<EOF
Resource Configuration Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Options:
  --environment, -e ENV     Specify environment (default: production)
                            Valid values: development, staging, production, dr-recovery
  --region, -r REGION       Specify cloud region
  --profile, -p PROFILE     AWS/Azure/GCP profile to use
  --cpu CPU                 Override CPU allocation (cores)
  --memory MEM              Override memory allocation (e.g. 8Gi)
  --disk DISK               Override disk size (GB)
  --instance-type TYPE      Override instance type
  --auto-scale              Enable auto-scaling configuration
  --min-instances NUM       Minimum instances for auto-scaling (default: 2)
  --max-instances NUM       Maximum instances for auto-scaling (default: 10)
  --dry-run                 Show what would be configured without making changes
  --force                   Force configuration even if current settings exist
  --log-file FILE           Specify custom log file location
  --help, -h                Show this help message

Examples:
  $(basename "$0") --environment staging --region us-west-2 --auto-scale
  $(basename "$0") --environment production --cpu 16 --memory 32Gi
EOF
    exit 0
}

# Parse command-line arguments
MIN_INSTANCES=2
MAX_INSTANCES=10
CPU_OVERRIDE=""
MEMORY_OVERRIDE=""
DISK_OVERRIDE=""
INSTANCE_TYPE_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --region|-r)
            REGION="$2"
            shift 2
            ;;
        --profile|-p)
            PROFILE="$2"
            shift 2
            ;;
        --cpu)
            CPU_OVERRIDE="$2"
            shift 2
            ;;
        --memory)
            MEMORY_OVERRIDE="$2"
            shift 2
            ;;
        --disk)
            DISK_OVERRIDE="$2"
            shift 2
            ;;
        --instance-type)
            INSTANCE_TYPE_OVERRIDE="$2"
            shift 2
            ;;
        --auto-scale)
            AUTO_SCALE=true
            shift
            ;;
        --min-instances)
            MIN_INSTANCES="$2"
            shift 2
            ;;
        --max-instances)
            MAX_INSTANCES="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            log "Unknown option: $1" "ERROR"
            usage
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
    log "Invalid environment: $ENVIRONMENT" "ERROR"
    log "Valid environments: development, staging, production, dr-recovery" "ERROR"
    exit 1
fi

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE" "INFO" "$LOG_FILE"
else
    log "Environment file not found: $ENV_FILE" "WARNING" "$LOG_FILE"
fi

# Determine cloud provider from environment variables
determine_cloud_provider() {
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" || -n "${AWS_PROFILE:-}" ]]; then
        echo "aws"
    elif [[ -n "${AZURE_SUBSCRIPTION_ID:-}" ]]; then
        echo "azure"
    elif [[ -n "${GCP_PROJECT_ID:-}" ]]; then
        echo "gcp"
    else
        # Try to detect from command availability and authentication
        if command_exists aws && check_aws_auth &>/dev/null; then
            echo "aws"
        elif command_exists az && check_azure_auth &>/dev/null; then
            echo "azure"
        elif command_exists gcloud && check_gcp_auth &>/dev/null; then
            echo "gcp"
        else
            echo "kubernetes" # Default to kubernetes if no cloud provider detected
        fi
    fi
}

# Resolve the region to use
resolve_region() {
    local provider=$1
    
    # If region is explicitly provided, use it
    if [[ -n "$REGION" ]]; then
        echo "$REGION"
        return
    fi
    
    # Check environment-specific region variables
    local env_region_var="${ENVIRONMENT}_REGION"
    if [[ -n "${!env_region_var:-}" ]]; then
        echo "${!env_region_var}"
        return
    fi
    
    # Otherwise try to get from provider-specific environment variables
    local region
    case $provider in
        aws)
            region="${AWS_DEFAULT_REGION:-${DEFAULT_REGIONS[aws]}}"
            ;;
        azure)
            region="${AZURE_REGION:-${DEFAULT_REGIONS[azure]}}"
            ;;
        gcp)
            region="${GCP_REGION:-${DEFAULT_REGIONS[gcp]}}"
            ;;
        *)
            region="${DEFAULT_REGIONS[aws]}"  # Default fallback
            ;;
    esac
    
    echo "$region"
}

# Validate CPU allocation
validate_cpu() {
    local cpu=$1
    if ! [[ "$cpu" =~ ^[0-9]+$ ]]; then
        log "Invalid CPU value: $cpu (must be a positive integer)" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    # Check if value is within reasonable limits
    if (( cpu < 1 || cpu > 128 )); then
        log "Warning: CPU value $cpu seems unusual (expected between 1-128)" "WARNING" "$LOG_FILE"
    fi
}

# Validate memory allocation
validate_memory() {
    local memory=$1
    if ! [[ "$memory" =~ ^[0-9]+[MGT]i$ ]]; then
        log "Invalid memory format: $memory (should be like 8Gi, 512Mi, etc.)" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    # Extract the numeric part and check if within reasonable limits
    local mem_value
    mem_value=$(echo "$memory" | sed 's/[^0-9]//g')
    local mem_unit
    mem_unit=$(echo "$memory" | sed 's/[0-9]//g')
    
    case "$mem_unit" in
        "Mi")
            if (( mem_value < 256 || mem_value > 262144 )); then # 256Mi to 256Gi in Mi
                log "Warning: Memory value $memory seems unusual" "WARNING" "$LOG_FILE"
            fi
            ;;
        "Gi")
            if (( mem_value < 1 || mem_value > 512 )); then # 1Gi to 512Gi
                log "Warning: Memory value $memory seems unusual" "WARNING" "$LOG_FILE"
            fi
            ;;
        "Ti")
            if (( mem_value > 4 )); then # Up to 4Ti
                log "Warning: Memory value $memory seems unusually high" "WARNING" "$LOG_FILE"
            fi
            ;;
    esac
}

# Validate disk size
validate_disk() {
    local disk=$1
    if ! [[ "$disk" =~ ^[0-9]+$ ]]; then
        log "Invalid disk size: $disk (must be a positive integer in GB)" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    # Check if value is within reasonable limits
    if (( disk < 10 || disk > 16384 )); then # 10GB to 16TB
        log "Warning: Disk size $disk GB seems unusual (expected between 10-16384)" "WARNING" "$LOG_FILE"
    fi
}

# Configure AWS resources
configure_aws_resources() {
    local cpu=$1
    local memory=$2
    local disk=$3
    local instance_type=$4
    
    log "Configuring AWS resources for $ENVIRONMENT environment in $REGION region" "INFO" "$LOG_FILE"
    
    # Set AWS profile if provided
    local aws_args=""
    if [[ -n "$PROFILE" ]]; then
        aws_args="--profile $PROFILE"
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY RUN] Would configure AWS resources with:" "INFO" "$LOG_FILE"
        log "  - Instance Type: $instance_type" "INFO" "$LOG_FILE"
        log "  - EBS Volume Size: ${disk}GB" "INFO" "$LOG_FILE"
        log "  - Auto-scaling: $AUTO_SCALE" "INFO" "$LOG_FILE"
        
        if [[ "$AUTO_SCALE" == true ]]; then
            log "  - Min Instances: $MIN_INSTANCES" "INFO" "$LOG_FILE"
            log "  - Max Instances: $MAX_INSTANCES" "INFO" "$LOG_FILE"
        fi
        return 0
    fi
    
    # Check AWS CLI availability
    if ! check_aws_auth; then
        log "AWS CLI not installed or not authenticated" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    local app_name="${ENVIRONMENT}-cloud-platform"
    
    # Create launch template
    log "Creating launch template for $app_name" "INFO" "$LOG_FILE"
    
    # Create JSON file for block device mappings
    local temp_file=$(mktemp)
    cat > "$temp_file" <<EOF
{
  "DeviceName": "/dev/xvda",
  "Ebs": {
    "VolumeSize": ${disk},
    "VolumeType": "gp3",
    "DeleteOnTermination": true,
    "Encrypted": true
  }
}
EOF
    
    # Check if launch template already exists
    if aws $aws_args ec2 describe-launch-templates --filters "Name=launch-template-name,Values=${app_name}" --region "$REGION" &> /dev/null; then
        if [[ "$FORCE" == true ]]; then
            log "Launch template ${app_name} already exists, updating due to --force flag" "WARNING" "$LOG_FILE"
            
            # Get latest version
            local latest_version
            latest_version=$(aws $aws_args ec2 describe-launch-templates --filters "Name=launch-template-name,Values=${app_name}" --region "$REGION" --query "LaunchTemplates[0].LatestVersionNumber" --output text)
            
            # Create new version
            aws $aws_args ec2 create-launch-template-version \
                --launch-template-name "${app_name}" \
                --version-description "Updated by configure_resources.sh on $(date)" \
                --launch-template-data "{\"InstanceType\":\"${instance_type}\",\"BlockDeviceMappings\":[$(cat $temp_file)]}" \
                --region "$REGION" || {
                    log "Failed to update launch template ${app_name}" "ERROR" "$LOG_FILE"
                    rm -f "$temp_file"
                    return 1
                }
                
            log "Updated launch template ${app_name} to version $((latest_version+1))" "INFO" "$LOG_FILE"
        else
            log "Launch template ${app_name} already exists, use --force to update" "WARNING" "$LOG_FILE"
        fi
    else
        # Create new launch template
        aws $aws_args ec2 create-launch-template \
            --launch-template-name "${app_name}" \
            --version-description "Created by configure_resources.sh on $(date)" \
            --launch-template-data "{\"InstanceType\":\"${instance_type}\",\"BlockDeviceMappings\":[$(cat $temp_file)]}" \
            --region "$REGION" || {
                log "Failed to create launch template ${app_name}" "ERROR" "$LOG_FILE"
                rm -f "$temp_file"
                return 1
            }
            
        log "Created launch template ${app_name}" "INFO" "$LOG_FILE"
    fi
    
    # Clean up temporary file
    rm -f "$temp_file"
    
    # Configure auto-scaling if enabled
    if [[ "$AUTO_SCALE" == true ]]; then
        log "Configuring auto-scaling for $app_name" "INFO" "$LOG_FILE"
        
        # Check if auto-scaling group already exists
        if aws $aws_args autoscaling describe-auto-scaling-groups --auto-scaling-group-names "${app_name}-asg" --region "$REGION" &> /dev/null; then
            if [[ "$FORCE" == true ]]; then
                log "Auto-scaling group ${app_name}-asg already exists, updating due to --force flag" "WARNING" "$LOG_FILE"
                
                # Update auto-scaling group
                aws $aws_args autoscaling update-auto-scaling-group \
                    --auto-scaling-group-name "${app_name}-asg" \
                    --min-size "$MIN_INSTANCES" \
                    --max-size "$MAX_INSTANCES" \
                    --launch-template "LaunchTemplateName=${app_name},Version=\$Latest" \
                    --region "$REGION" || {
                        log "Failed to update auto-scaling group ${app_name}-asg" "ERROR" "$LOG_FILE"
                        return 1
                    }
                    
                log "Updated auto-scaling group ${app_name}-asg" "INFO" "$LOG_FILE"
            else
                log "Auto-scaling group ${app_name}-asg already exists, use --force to update" "WARNING" "$LOG_FILE"
            fi
        else
            # Get subnet IDs for the region
            local subnets
            subnets=$(aws $aws_args ec2 describe-subnets --region "$REGION" --filters "Name=default-for-az,Values=true" --query "Subnets[].SubnetId" --output text | tr '\t' ',') || {
                log "Failed to retrieve subnet information" "ERROR" "$LOG_FILE"
                return 1
            }
            
            if [[ -z "$subnets" ]]; then
                log "No subnets found in region $REGION" "ERROR" "$LOG_FILE"
                return 1
            fi
            
            # Create auto-scaling group
            aws $aws_args autoscaling create-auto-scaling-group \
                --auto-scaling-group-name "${app_name}-asg" \
                --min-size "$MIN_INSTANCES" \
                --max-size "$MAX_INSTANCES" \
                --desired-capacity "$MIN_INSTANCES" \
                --launch-template "LaunchTemplateName=${app_name},Version=\$Latest" \
                --vpc-zone-identifier "$subnets" \
                --region "$REGION" \
                --tags "Key=Environment,Value=${ENVIRONMENT}" "Key=Name,Value=${app_name}" || {
                    log "Failed to create auto-scaling group ${app_name}-asg" "ERROR" "$LOG_FILE"
                    return 1
                }
                
            log "Created auto-scaling group ${app_name}-asg" "INFO" "$LOG_FILE"
            
            # Create CPU-based scaling policy
            local policy_config=$(mktemp)
            cat > "$policy_config" <<EOF
{
  "TargetValue": 70.0,
  "PredefinedMetricSpecification": {
    "PredefinedMetricType": "ASGAverageCPUUtilization"
  }
}
EOF
            
            aws $aws_args autoscaling put-scaling-policy \
                --auto-scaling-group-name "${app_name}-asg" \
                --policy-name "${app_name}-cpu-policy" \
                --policy-type TargetTrackingScaling \
                --target-tracking-configuration "file://$policy_config" \
                --region "$REGION" || {
                    log "Failed to create scaling policy for ${app_name}-asg" "ERROR" "$LOG_FILE"
                    rm -f "$policy_config"
                    return 1
                }
                
            log "Created CPU-based scaling policy for ${app_name}-asg" "INFO" "$LOG_FILE"
            
            # Clean up
            rm -f "$policy_config"
        fi
    else
        # Check if ASG exists and disable auto-scaling if it was previously enabled
        if aws $aws_args autoscaling describe-auto-scaling-groups --auto-scaling-group-names "${app_name}-asg" --region "$REGION" &> /dev/null; then
            if [[ "$FORCE" == true ]]; then
                # Update to fixed instance count (disabling auto-scaling)
                aws $aws_args autoscaling update-auto-scaling-group \
                    --auto-scaling-group-name "${app_name}-asg" \
                    --min-size "$MIN_INSTANCES" \
                    --max-size "$MIN_INSTANCES" \
                    --desired-capacity "$MIN_INSTANCES" \
                    --region "$REGION" || {
                        log "Failed to update auto-scaling group to fixed instance count" "ERROR" "$LOG_FILE"
                        return 1
                    }
                
                # Delete scaling policies if they exist
                local policies
                policies=$(aws $aws_args autoscaling describe-policies --auto-scaling-group-name "${app_name}-asg" --region "$REGION" --query "ScalingPolicies[].PolicyName" --output text) || {
                    log "Failed to retrieve scaling policies" "WARNING" "$LOG_FILE"
                }
                
                for policy in $policies; do
                    aws $aws_args autoscaling delete-policy --auto-scaling-group-name "${app_name}-asg" --policy-name "$policy" --region "$REGION" || {
                        log "Failed to delete scaling policy $policy" "WARNING" "$LOG_FILE"
                    }
                done
                
                log "Disabled auto-scaling for ${app_name}-asg" "INFO" "$LOG_FILE"
            fi
        fi
    fi
    
    log "AWS resource configuration completed" "INFO" "$LOG_FILE"
    return 0
}

# Configure Azure resources
configure_azure_resources() {
    local cpu=$1
    local memory=$2
    local disk=$3
    local instance_type=$4
    
    log "Configuring Azure resources for $ENVIRONMENT environment in $REGION region" "INFO" "$LOG_FILE"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY RUN] Would configure Azure resources with:" "INFO" "$LOG_FILE"
        log "  - VM Size: $instance_type" "INFO" "$LOG_FILE"
        log "  - Disk Size: ${disk}GB" "INFO" "$LOG_FILE"
        log "  - Auto-scaling: $AUTO_SCALE" "INFO" "$LOG_FILE"
        
        if [[ "$AUTO_SCALE" == true ]]; then
            log "  - Min Instances: $MIN_INSTANCES" "INFO" "$LOG_FILE"
            log "  - Max Instances: $MAX_INSTANCES" "INFO" "$LOG_FILE"
        fi
        return 0
    fi
    
    # Check Azure CLI availability
    if ! check_azure_auth; then
        log "Azure CLI not installed or not authenticated" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    # Set Azure CLI profile/subscription if specified
    if [[ -n "$PROFILE" ]]; then
        az account set --subscription "$PROFILE" || {
            log "Failed to set Azure subscription $PROFILE" "ERROR" "$LOG_FILE"
            return 1
        }
    fi
    
    # Resource group name
    local resource_group="${ENVIRONMENT}-cloud-platform"
    local app_name="${ENVIRONMENT}-cloud-platform"
    
    # Check if resource group exists
    if ! az group show --name "$resource_group" --output none 2>/dev/null; then
        log "Creating resource group $resource_group in $REGION" "INFO" "$LOG_FILE"
        az group create --name "$resource_group" --location "$REGION" || {
            log "Failed to create resource group $resource_group" "ERROR" "$LOG_FILE"
            return 1
        }
    fi
    
    # Check if VMSS exists
    if az vmss show --resource-group "$resource_group" --name "${app_name}-vmss" --output none 2>/dev/null; then
        if [[ "$FORCE" == true ]]; then
            log "VM Scale Set ${app_name}-vmss already exists, updating due to --force flag" "WARNING" "$LOG_FILE"
            
            # Update VM Scale Set
            az vmss update \
                --resource-group "$resource_group" \
                --name "${app_name}-vmss" \
                --set "sku.name=${instance_type}" \
                --set "sku.capacity=${MIN_INSTANCES}" || {
                    log "Failed to update VM Scale Set ${app_name}-vmss" "ERROR" "$LOG_FILE"
                    return 1
                }
                
            log "Updated VM Scale Set ${app_name}-vmss" "INFO" "$LOG_FILE"
        else
            log "VM Scale Set ${app_name}-vmss already exists, use --force to update" "WARNING" "$LOG_FILE"
        fi
    else
        # Create VM Scale Set
        local random_password=$(generate_random_string 16 "alnum!@#$%^&")
        
        az vmss create \
            --resource-group "$resource_group" \
            --name "${app_name}-vmss" \
            --location "$REGION" \
            --vm-sku "$instance_type" \
            --instance-count "$MIN_INSTANCES" \
            --storage-sku "Premium_LRS" \
            --os-disk-size-gb "$disk" \
            --upgrade-policy-mode "Automatic" \
            --admin-username "cpadmin" \
            --admin-password "$random_password" \
            --tags "Environment=${ENVIRONMENT}" \
            --generate-ssh-keys || {
                log "Failed to create VM Scale Set ${app_name}-vmss" "ERROR" "$LOG_FILE"
                return 1
            }
            
        log "Created VM Scale Set ${app_name}-vmss" "INFO" "$LOG_FILE"
        log "Generated admin password saved to secrets manager" "INFO" "$LOG_FILE"
        
        # Save the password to a secure location
        local secrets_dir="${PROJECT_ROOT}/secrets/${ENVIRONMENT}"
        mkdir -p "$secrets_dir"
        chmod 700 "$secrets_dir"
        echo "$random_password" > "${secrets_dir}/vmss-password.txt"
        chmod 600 "${secrets_dir}/vmss-password.txt"
    fi
    
    # Configure auto-scaling if enabled
    if [[ "$AUTO_SCALE" == true ]]; then
        log "Configuring auto-scaling for ${app_name}-vmss" "INFO" "$LOG_FILE"
        
        # Check if auto-scale settings already exist
        local autoscale_name="${app_name}-autoscale"
        if az monitor autoscale show --resource-group "$resource_group" --resource-name "${app_name}-vmss" --resource-type "Microsoft.Compute/virtualMachineScaleSets" --name "$autoscale_name" --output none 2>/dev/null; then
            # Update existing autoscale settings
            az monitor autoscale update \
                --resource-group "$resource_group" \
                --resource "${app_name}-vmss" \
                --resource-type "Microsoft.Compute/virtualMachineScaleSets" \
                --name "$autoscale_name" \
                --min-count "$MIN_INSTANCES" \
                --max-count "$MAX_INSTANCES" \
                --count "$MIN_INSTANCES" || {
                    log "Failed to update autoscale settings for ${app_name}-vmss" "ERROR" "$LOG_FILE"
                    return 1
                }
                
            log "Updated autoscale settings for ${app_name}-vmss" "INFO" "$LOG_FILE"
        else
            # Create auto-scale settings
            az monitor autoscale create \
                --resource-group "$resource_group" \
                --resource "${app_name}-vmss" \
                --resource-type "Microsoft.Compute/virtualMachineScaleSets" \
                --name "$autoscale_name" \
                --min-count "$MIN_INSTANCES" \
                --max-count "$MAX_INSTANCES" \
                --count "$MIN_INSTANCES" || {
                    log "Failed to create autoscale settings for ${app_name}-vmss" "ERROR" "$LOG_FILE"
                    return 1
                }
                
            # Add CPU scale-out rule
            az monitor autoscale rule create \
                --resource-group "$resource_group" \
                --autoscale-name "$autoscale_name" \
                --scale out 1 \
                --cooldown 5 \
                --condition "Percentage CPU > 70 avg 10m" || {
                    log "Failed to create scale-out rule for ${app_name}-vmss" "WARNING" "$LOG_FILE"
                }
                
            # Add CPU scale-in rule
            az monitor autoscale rule create \
                --resource-group "$resource_group" \
                --autoscale-name "$autoscale_name" \
                --scale in 1 \
                --cooldown 5 \
                --condition "Percentage CPU < 30 avg 10m" || {
                    log "Failed to create scale-in rule for ${app_name}-vmss" "WARNING" "$LOG_FILE"
                }
                
            log "Auto-scaling configured for ${app_name}-vmss" "INFO" "$LOG_FILE"
        fi
    else
        # Check if autoscale exists and remove if --force is set
        local autoscale_name="${app_name}-autoscale"
        if az monitor autoscale show --resource-group "$resource_group" --resource-name "${app_name}-vmss" --resource-type "Microsoft.Compute/virtualMachineScaleSets" --name "$autoscale_name" --output none 2>/dev/null; then
            if [[ "$FORCE" == true ]]; then
                az monitor autoscale delete \
                    --resource-group "$resource_group" \
                    --name "$autoscale_name" || {
                        log "Failed to delete autoscale settings for ${app_name}-vmss" "WARNING" "$LOG_FILE"
                    }
                    
                log "Removed autoscale settings for ${app_name}-vmss" "INFO" "$LOG_FILE"
            fi
        fi
    fi
    
    log "Azure resource configuration completed" "INFO" "$LOG_FILE"
    return 0
}

# Configure GCP resources
configure_gcp_resources() {
    local cpu=$1
    local memory=$2
    local disk=$3
    local instance_type=$4
    
    log "Configuring GCP resources for $ENVIRONMENT environment in $REGION region" "INFO" "$LOG_FILE"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY RUN] Would configure GCP resources with:" "INFO" "$LOG_FILE"
        log "  - Machine Type: $instance_type" "INFO" "$LOG_FILE"
        log "  - Disk Size: ${disk}GB" "INFO" "$LOG_FILE"
        log "  - Auto-scaling: $AUTO_SCALE" "INFO" "$LOG_FILE"
        
        if [[ "$AUTO_SCALE" == true ]]; then
            log "  - Min Instances: $MIN_INSTANCES" "INFO" "$LOG_FILE"
            log "  - Max Instances: $MAX_INSTANCES" "INFO" "$LOG_FILE"
        fi
        return 0
    fi

    # Check GCP CLI availability
    if ! check_gcp_auth; then
        log "GCP CLI not installed or not authenticated" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    # Set GCP project if specified via profile
    if [[ -n "$PROFILE" ]]; then
        gcloud config set project "$PROFILE" || {
            log "Failed to set GCP project to $PROFILE" "ERROR" "$LOG_FILE"
            return 1
        }
    elif [[ -n "${GCP_PROJECT_ID:-}" ]]; then
        gcloud config set project "$GCP_PROJECT_ID" || {
            log "Failed to set GCP project to $GCP_PROJECT_ID" "ERROR" "$LOG_FILE"
            return 1
        }
    else
        local current_project
        current_project=$(gcloud config get-value project 2>/dev/null)
        if [[ -z "$current_project" ]]; then
            log "No GCP project specified and no default project set" "ERROR" "$LOG_FILE"
            return 1
        fi
        log "Using current GCP project: $current_project" "INFO" "$LOG_FILE"
    fi
    
    # Create instance template
    local app_name="${ENVIRONMENT}-cloud-platform"
    local template_name="${app_name}-template-${TIMESTAMP}"
    
    # Check if template exists and create a new one
    log "Creating instance template $template_name" "INFO" "$LOG_FILE"
    
    gcloud compute instance-templates create "$template_name" \
        --machine-type="$instance_type" \
        --boot-disk-size="${disk}GB" \
        --boot-disk-type="pd-ssd" \
        --tags="$app_name,http-server,https-server" \
        --metadata="environment=${ENVIRONMENT}" \
        --region="$REGION" || {
            log "Failed to create instance template $template_name" "ERROR" "$LOG_FILE"
            return 1
        }
        
    log "Created instance template $template_name" "INFO" "$LOG_FILE"
    
    # Check if instance group manager exists
    if gcloud compute instance-groups managed describe "${app_name}-mig" --region="$REGION" &>/dev/null; then
        if [[ "$FORCE" == true ]]; then
            log "Instance group ${app_name}-mig already exists, updating due to --force flag" "WARNING" "$LOG_FILE"
            
            # Update instance group to use new template
            gcloud compute instance-groups managed rolling-action start-update \
                "${app_name}-mig" \
                --version "template=${template_name}" \
                --max-unavailable=100% \
                --region="$REGION" || {
                    log "Failed to update instance group ${app_name}-mig" "ERROR" "$LOG_FILE"
                    return 1
                }
                
            # Update size if auto-scaling not enabled
            if [[ "$AUTO_SCALE" != true ]]; then
                gcloud compute instance-groups managed resize \
                    "${app_name}-mig" \
                    --size="$MIN_INSTANCES" \
                    --region="$REGION" || {
                        log "Failed to resize instance group ${app_name}-mig" "WARNING" "$LOG_FILE"
                    }
            fi
            
            log "Updated instance group ${app_name}-mig to use template $template_name" "INFO" "$LOG_FILE"
        else
            log "Instance group ${app_name}-mig already exists, use --force to update" "WARNING" "$LOG_FILE"
        fi
    else
        # Create managed instance group
        gcloud compute instance-groups managed create "${app_name}-mig" \
            --template="$template_name" \
            --size="$MIN_INSTANCES" \
            --region="$REGION" || {
                log "Failed to create managed instance group ${app_name}-mig" "ERROR" "$LOG_FILE"
                return 1
            }
            
        log "Created managed instance group ${app_name}-mig" "INFO" "$LOG_FILE"
    fi
    
    # Configure auto-scaling if enabled
    if [[ "$AUTO_SCALE" == true ]]; then
        log "Configuring auto-scaling for ${app_name}-mig" "INFO" "$LOG_FILE"
        
        # Set up autoscaling
        gcloud compute instance-groups managed set-autoscaling \
            "${app_name}-mig" \
            --min-num-replicas="$MIN_INSTANCES" \
            --max-num-replicas="$MAX_INSTANCES" \
            --target-cpu-utilization="0.7" \
            --cool-down-period="300" \
            --region="$REGION" || {
                log "Failed to configure auto-scaling for ${app_name}-mig" "ERROR" "$LOG_FILE"
                return 1
            }
            
        log "Auto-scaling configured for ${app_name}-mig" "INFO" "$LOG_FILE"
    else
        # Disable autoscaling if it was previously enabled
        if gcloud compute instance-groups managed describe "${app_name}-mig" --region="$REGION" | grep -q "autoscaler"; then
            gcloud compute instance-groups managed stop-autoscaling \
                "${app_name}-mig" \
                --region="$REGION" || {
                    log "Failed to disable auto-scaling for ${app_name}-mig" "WARNING" "$LOG_FILE"
                }
                
            log "Auto-scaling disabled for ${app_name}-mig" "INFO" "$LOG_FILE"
        fi
    fi
    
    log "GCP resource configuration completed" "INFO" "$LOG_FILE"
    return 0
}

# Configure Kubernetes resources
configure_kubernetes_resources() {
    local cpu=$1
    local memory=$2
    
    log "Configuring Kubernetes resources for $ENVIRONMENT environment" "INFO" "$LOG_FILE"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY RUN] Would configure Kubernetes resources with:" "INFO" "$LOG_FILE"
        log "  - CPU Limit: ${cpu}" "INFO" "$LOG_FILE"
        log "  - Memory Limit: ${memory}" "INFO" "$LOG_FILE"
        log "  - Auto-scaling: $AUTO_SCALE" "INFO" "$LOG_FILE"
        
        if [[ "$AUTO_SCALE" == true ]]; then
            log "  - Min Replicas: $MIN_INSTANCES" "INFO" "$LOG_FILE"
            log "  - Max Replicas: $MAX_INSTANCES" "INFO" "$LOG_FILE"
        fi
        return 0
    fi
    
    # Check kubectl availability
    if ! command_exists kubectl; then
        log "kubectl not installed" "ERROR" "$LOG_FILE"
        exit 1
    fi
    
    # Set kubectl context if specified via profile
    if [[ -n "$PROFILE" ]]; then
        kubectl config use-context "$PROFILE" || {
            log "Failed to set kubectl context to $PROFILE" "ERROR" "$LOG_FILE"
            return 1
        }
    fi
    
    local app_name="${ENVIRONMENT}-cloud-platform"
    local namespace="${ENVIRONMENT}"
    
    # Create namespace if it doesn't exist
    if ! kubectl get namespace "$namespace" &>/dev/null; then
        kubectl create namespace "$namespace" || {
            log "Failed to create namespace $namespace" "ERROR" "$LOG_FILE"
            return 1
        }
    fi
    
    # Extract numeric part of memory to calculate request (50% of limit)
    local memory_value
    memory_value=$(echo "$memory" | sed 's/[^0-9]//g')
    local memory_unit
    memory_unit=$(echo "$memory" | sed 's/[0-9]//g')
    local memory_request
    memory_request="$((memory_value / 2))${memory_unit}"
    
    # Create deployment config file
    local deploy_file=$(mktemp)
    cat > "$deploy_file" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $app_name
  namespace: $namespace
  labels:
    app: cloud-platform
    environment: $ENVIRONMENT
spec:
  replicas: $MIN_INSTANCES
  selector:
    matchLabels:
      app: cloud-platform
      environment: $ENVIRONMENT
  template:
    metadata:
      labels:
        app: cloud-platform
        environment: $ENVIRONMENT
    spec:
      containers:
      - name: cloud-platform
        image: cloud-platform:latest
        resources:
          limits:
            cpu: "${cpu}"
            memory: "${memory}"
          requests:
            cpu: "$((cpu / 2))"
            memory: "${memory_request}"
        ports:
        - containerPort: 80
        readinessProbe:
          httpGet:
            path: /api/health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /api/health
            port: 80
          initialDelaySeconds: 60
          periodSeconds: 15
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false
EOF
    
    # Apply or update the deployment
    if kubectl get deployment -n "$namespace" "$app_name" &>/dev/null; then
        if [[ "$FORCE" == true ]]; then
            log "Deployment $app_name already exists, updating due to --force flag" "WARNING" "$LOG_FILE"
            kubectl apply -f "$deploy_file" || {
                log "Failed to update deployment $app_name" "ERROR" "$LOG_FILE"
                rm -f "$deploy_file"
                return 1
            }
            log "Updated deployment $app_name" "INFO" "$LOG_FILE"
        else
            log "Deployment $app_name already exists, use --force to update" "WARNING" "$LOG_FILE"
        fi
    else
        kubectl apply -f "$deploy_file" || {
            log "Failed to create deployment $app_name" "ERROR" "$LOG_FILE"
            rm -f "$deploy_file"
            return 1
        }
        log "Created deployment $app_name" "INFO" "$LOG_FILE"
    fi
    
    # Configure auto-scaling if enabled
    if [[ "$AUTO_SCALE" == true ]]; then
        log "Configuring horizontal pod autoscaler for $app_name" "INFO" "$LOG_FILE"
        
        local hpa_file=$(mktemp)
        cat > "$hpa_file" <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: $app_name
  namespace: $namespace
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: $app_name
  minReplicas: $MIN_INSTANCES
  maxReplicas: $MAX_INSTANCES
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
EOF
        
        # Apply or update the HPA
        kubectl apply -f "$hpa_file" || {
            log "Failed to configure horizontal pod autoscaler for $app_name" "ERROR" "$LOG_FILE"
            rm -f "$hpa_file"
            return 1
        }
        log "Configured horizontal pod autoscaler for $app_name" "INFO" "$LOG_FILE"
        
        rm -f "$hpa_file"
    else
        # Remove HPA if it exists
        if kubectl get hpa -n "$namespace" "$app_name" &>/dev/null; then
            kubectl delete hpa -n "$namespace" "$app_name" || {
                log "Failed to remove horizontal pod autoscaler for $app_name" "WARNING" "$LOG_FILE"
            }
            log "Removed horizontal pod autoscaler for $app_name" "INFO" "$LOG_FILE"
        fi
    fi
    
    # Create or update service for the deployment
    local service_file=$(mktemp)
    cat > "$service_file" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $app_name
  namespace: $namespace
  labels:
    app: cloud-platform
    environment: $ENVIRONMENT
spec:
  selector:
    app: cloud-platform
    environment: $ENVIRONMENT
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
    name: http
  - port: 443
    targetPort: 80
    protocol: TCP
    name: https
  type: ClusterIP
EOF

    kubectl apply -f "$service_file" || {
        log "Failed to create/update service for $app_name" "WARNING" "$LOG_FILE"
    }
    
    # Clean up
    rm -f "$deploy_file"
    rm -f "$service_file"
    
    log "Kubernetes resource configuration completed" "INFO" "$LOG_FILE"
    return 0
}

# Main execution flow
main() {
    # Detect cloud provider
    CLOUD_PROVIDER=$(determine_cloud_provider)
    
    # Resolve region
    REGION=$(resolve_region "$CLOUD_PROVIDER")
    
    log "Starting resource configuration for $ENVIRONMENT environment" "INFO" "$LOG_FILE"
    log "Detected cloud provider: $CLOUD_PROVIDER" "INFO" "$LOG_FILE"
    log "Target region: $REGION" "INFO" "$LOG_FILE"
    
    # Determine CPU allocation
    CPU="${CPU_OVERRIDE:-${CPU_LIMITS[$ENVIRONMENT]}}"
    validate_cpu "$CPU"
    
    # Determine memory allocation
    MEMORY="${MEMORY_OVERRIDE:-${MEMORY_LIMITS[$ENVIRONMENT]}}"
    validate_memory "$MEMORY"
    
    # Determine disk size
    DISK="${DISK_OVERRIDE:-${DISK_SIZES[$ENVIRONMENT]}}"
    validate_disk "$DISK"
    
    # Determine instance type
    INSTANCE_TYPE="${INSTANCE_TYPE_OVERRIDE:-${INSTANCE_TYPES[$ENVIRONMENT]}}"
    
    log "Configuring resources with:" "INFO" "$LOG_FILE"
    log "  - CPU: $CPU cores" "INFO" "$LOG_FILE"
    log "  - Memory: $MEMORY" "INFO" "$LOG_FILE"
    log "  - Disk: ${DISK}GB" "INFO" "$LOG_FILE"
    log "  - Instance Type: $INSTANCE_TYPE" "INFO" "$LOG_FILE"
    log "  - Auto-scaling: $AUTO_SCALE" "INFO" "$LOG_FILE"
    
    if [[ "$AUTO_SCALE" == true ]]; then
        log "  - Min Instances: $MIN_INSTANCES" "INFO" "$LOG_FILE"
        log "  - Max Instances: $MAX_INSTANCES" "INFO" "$LOG_FILE"
        
        # Validate auto-scaling parameters
        if (( MIN_INSTANCES < 1 || MIN_INSTANCES > 1000 )); then
            log "Invalid min-instances value: $MIN_INSTANCES (must be between 1-1000)" "ERROR" "$LOG_FILE"
            exit 1
        fi
        
        if (( MAX_INSTANCES < MIN_INSTANCES || MAX_INSTANCES > 5000 )); then
            log "Invalid max-instances value: $MAX_INSTANCES (must be ≥ min-instances and ≤ 5000)" "ERROR" "$LOG_FILE"
            exit 1
        fi
    fi
    
    # Configure resources based on cloud provider
    case "$CLOUD_PROVIDER" in
        aws)
            configure_aws_resources "$CPU" "$MEMORY" "$DISK" "$INSTANCE_TYPE" || exit 1
            ;;
        azure)
            configure_azure_resources "$CPU" "$MEMORY" "$DISK" "$INSTANCE_TYPE" || exit 1
            ;;
        gcp)
            configure_gcp_resources "$CPU" "$MEMORY" "$DISK" "$INSTANCE_TYPE" || exit 1
            ;;
        *)
            log "No specific cloud provider detected, using Kubernetes" "INFO" "$LOG_FILE"
            configure_kubernetes_resources "$CPU" "$MEMORY" || exit 1
            ;;
    esac
    
    # Generate a summary file with the configuration
    SUMMARY_DIR="${PROJECT_ROOT}/deployment/outputs"
    SUMMARY_FILE="${SUMMARY_DIR}/resources-${ENVIRONMENT}-${TIMESTAMP}.json"
    
    # Create directory if it doesn't exist
    mkdir -p "$SUMMARY_DIR"
    
    # Create summary JSON
    cat > "$SUMMARY_FILE" <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "environment": "$ENVIRONMENT",
  "region": "$REGION",
  "cloud_provider": "$CLOUD_PROVIDER",
  "resources": {
    "cpu": "$CPU",
    "memory": "$MEMORY",
    "disk_gb": "$DISK",
    "instance_type": "$INSTANCE_TYPE"
  },
  "auto_scaling": {
    "enabled": $AUTO_SCALE,
    "min_instances": $MIN_INSTANCES,
    "max_instances": $MAX_INSTANCES
  },
  "configuration_status": "success"
}
EOF
    
    log "Resource configuration completed successfully" "INFO" "$LOG_FILE"
    log "Configuration summary saved to: $SUMMARY_FILE" "INFO" "$LOG_FILE"
    
    # DR Mode handling - log to DR events system
    if [[ "$ENVIRONMENT" == "dr-recovery" ]]; then
        log_dr_event "RESOURCE_CONFIGURATION" "$ENVIRONMENT" "$REGION" "SUCCESS" "CPU=$CPU,Memory=$MEMORY"
    fi
    
    # Send notification if configured in environment
    if [[ -n "${NOTIFICATIONS_ENABLED:-}" && "${NOTIFICATIONS_ENABLED:-}" == "true" ]]; then
        if command_exists send_notification; then
            send_notification \
                "Resource Configuration Completed" \
                "Successfully configured resources for $ENVIRONMENT environment in $REGION region.\nCloud Provider: $CLOUD_PROVIDER\nCPU: $CPU cores\nMemory: $MEMORY\nDisk: ${DISK}GB" \
                "low"
        fi
    fi
}

# Execute main function
main

exit 0