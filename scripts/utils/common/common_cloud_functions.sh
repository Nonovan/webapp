#######################################
# CLOUD PROVIDER UTILITIES
#######################################

# Check AWS CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_aws_auth() {
    if ! command_exists aws; then
        warn "AWS CLI not installed"
        return 1
    fi

    # Attempt to get caller identity
    if aws sts get-caller-identity &>/dev/null; then
        local identity=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)
        log "AWS authenticated as: $identity" "DEBUG"
        return 0
    else
        warn "AWS CLI not authenticated"
        return 1
    fi
}

# Check GCP CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_gcp_auth() {
    if ! command_exists gcloud; then
        warn "GCP CLI (gcloud) not installed"
        return 1
    fi

    # Check if user is authenticated
    local account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    if [[ -n "$account" ]]; then
        log "GCP authenticated as: $account" "DEBUG"
        return 0
    else
        warn "GCP CLI not authenticated"
        return 1
    fi
}

# Check Azure CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_azure_auth() {
    if ! command_exists az; then
        warn "Azure CLI not installed"
        return 1
    fi

    # Check if user is logged in
    if az account show &>/dev/null; then
        local account=$(az account show --query 'user.name' -o tsv 2>/dev/null)
        log "Azure authenticated as: $account" "DEBUG"
        return 0
    else
        warn "Azure CLI not authenticated"
        return 1
    fi
}

# Get AWS instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance-id, local-hostname)
# Returns: Metadata value
get_aws_metadata() {
    local metadata_key="$1"
    local result

    if command_exists curl && curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        result=$(curl -s "http://169.254.169.254/latest/meta-data/$metadata_key")
        echo "$result"
        return 0
    else
        warn "Unable to retrieve AWS instance metadata"
        return 1
    fi
}

# Get GCP instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance/id, instance/zone)
# Returns: Metadata value
get_gcp_metadata() {
    local metadata_key="$1"
    local result

    if command_exists curl && curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
        result=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$metadata_key")
        echo "$result"
        return 0
    else
        warn "Unable to retrieve GCP instance metadata"
        return 1
    fi
}

# Detect cloud provider
# Returns: Provider name (aws, gcp, azure, unknown)
detect_cloud_provider() {
    if command_exists curl; then
        # Check for AWS
        if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
            echo "aws"
            return 0
        fi

        # Check for GCP
        if curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
            echo "gcp"
            return 0
        fi

        # Check for Azure
        if curl -s --connect-timeout 2 http://169.254.169.254/metadata/instance?api-version=2020-09-01 -H "Metadata: true" &>/dev/null; then
            echo "azure"
            return 0
        fi
    fi

    # Check for provider-specific files
    if [[ -f /sys/hypervisor/uuid ]] && [[ "$(head -c 3 /sys/hypervisor/uuid)" == "ec2" ]]; then
        echo "aws"
        return 0
    fi

    if [[ -f /sys/class/dmi/id/product_name ]] && grep -q "Google Compute Engine" /sys/class/dmi/id/product_name; then
        echo "gcp"
        return 0
    fi

    if [[ -f /sys/class/dmi/id/chassis_asset_tag ]] && grep -q "7783-7084-3265-9085-8269-3286-77" /sys/class/dmi/id/chassis_asset_tag; then
        echo "azure"
        return 0
    fi

    echo "unknown"
    return 1
}

# Check TLS certificate expiration
# Arguments:
#   $1 - Domain name
#   $2 - Warning threshold in days (optional - defaults to 30)
# Returns: 0 if certificate is valid and not expiring soon, 1 otherwise
check_certificate_expiration() {
    local domain="$1"
    local threshold_days="${2:-30}"
    local expiry_date
    local days_remaining

    if ! command_exists openssl; then
        warn "OpenSSL not available, cannot check certificate expiration"
        return 2
    fi

    # Get certificate expiration date using OpenSSL
    expiry_date=$(echo | openssl s_client -servername "$domain" -connect "$domain":443 2>/dev/null | \
                 openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

    if [[ -z "$expiry_date" ]]; then
        warn "Failed to retrieve certificate for $domain"
        return 1
    fi

    # Calculate days remaining until expiration
    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local seconds_remaining=$((expiry_epoch - current_epoch))
    days_remaining=$((seconds_remaining / 86400))

    if (( days_remaining <= 0 )); then
        warn "Certificate for $domain has expired!"
        return 1
    elif (( days_remaining <= threshold_days )); then
        warn "Certificate for $domain will expire in $days_remaining days (threshold: $threshold_days days)"
        return 1
    fi

    return 0
}

# Monitor a service and restart if needed
# Arguments:
#   $1 - Service name
#   $2 - Restart command (optional - defaults to systemctl restart)
#   $3 - Health check command (optional - defaults to systemctl is-active)
# Returns: 0 if service is running or was successfully restarted, 1 otherwise
monitor_and_restart_service() {
    local service_name="$1"
    local restart_cmd="${2:-systemctl restart $service_name}"
    local health_check="${3:-systemctl is-active $service_name}"

    log "Checking service: $service_name"

    # Check if service is running using the provided health check command
    if eval "$health_check" &>/dev/null; then
        debug "Service $service_name is running correctly"
        return 0
    else
        warn "Service $service_name is not running properly, attempting restart"

        # Attempt to restart the service
        if eval "$restart_cmd" &>/dev/null; then
            log "Successfully restarted service: $service_name"

            # Verify service is now running
            sleep 2
            if eval "$health_check" &>/dev/null; then
                log "Service $service_name is now running properly after restart"
                return 0
            else
                error_exit "Service $service_name failed to restart properly" 1
            fi
        else
            error_exit "Failed to restart service: $service_name" 1
        fi
    fi
}

# Format timestamp for consistent usage
# Arguments:
#   $1 - Format (optional - defaults to "full")
# Returns: Formatted timestamp string
format_timestamp() {
    local format="${1:-full}"

    case "$format" in
        full)
            date '+%Y-%m-%d %H:%M:%S'
            ;;
        date)
            date '+%Y-%m-%d'
            ;;
        time)
            date '+%H:%M:%S'
            ;;
        iso8601)
            date -u '+%Y-%m-%dT%H:%M:%SZ'
            ;;
        filename)
            date '+%Y%m%d_%H%M%S'
            ;;
        *)
            date '+%Y-%m-%d %H:%M:%S'
            ;;
    esac
}

# Export cloud provider functions
export -f check_aws_auth
export -f check_gcp_auth
export -f check_azure_auth
export -f detect_cloud_provider
export -f check_certificate_expiration
export -f format_timestamp
