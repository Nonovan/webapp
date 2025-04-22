#!/bin/bash
# filepath: scripts/utils/common/common_cloud_functions.sh
#######################################
# CLOUD PROVIDER UTILITIES
#######################################

# Check AWS CLI availability and authentication
# Arguments:
#   None
# Returns:
#   0 if authenticated, 1 if not
check_aws_auth() {
    if ! command_exists aws; then
        warn "AWS CLI not installed"
        return 1
    fi

    # Attempt to get caller identity with timeout to prevent hanging
    if timeout 10 aws sts get-caller-identity &>/dev/null; then
        local identity
        identity=$(timeout 5 aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)
        debug "AWS authenticated as: $identity"
        return 0
    else
        warn "AWS CLI not authenticated"
        return 1
    fi
}

# Check GCP CLI availability and authentication
# Arguments:
#   None
# Returns:
#   0 if authenticated, 1 if not
check_gcp_auth() {
    if ! command_exists gcloud; then
        warn "GCP CLI (gcloud) not installed"
        return 1
    fi

    # Check if user is authenticated with timeout
    local account
    account=$(timeout 10 gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    if [[ -n "$account" ]]; then
        debug "GCP authenticated as: $account"
        return 0
    else
        warn "GCP CLI not authenticated"
        return 1
    fi
}

# Check Azure CLI availability and authentication
# Arguments:
#   None
# Returns:
#   0 if authenticated, 1 if not
check_azure_auth() {
    if ! command_exists az; then
        warn "Azure CLI not installed"
        return 1
    fi

    # Check if user is logged in with timeout
    if timeout 10 az account show &>/dev/null; then
        local account
        account=$(timeout 5 az account show --query 'user.name' -o tsv 2>/dev/null)
        debug "Azure authenticated as: $account"
        return 0
    else
        warn "Azure CLI not authenticated"
        return 1
    fi
}

# Get AWS instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance-id, local-hostname)
# Outputs:
#   Metadata value on stdout
# Returns:
#   0 on success, 1 on failure
get_aws_metadata() {
    local metadata_key="$1"
    local metadata_url="http://169.254.169.254/latest/meta-data"
    local result

    if [[ -z "$metadata_key" ]]; then
        warn "Metadata key must be provided"
        return 1
    fi

    # IMDSv2 token-based request with fallback to IMDSv1
    if command_exists curl; then
        # Try IMDSv2 first (more secure)
        local token
        token=$(curl -s -f -X PUT --connect-timeout 2 \
                "http://169.254.169.254/latest/api/token" \
                -H "X-aws-ec2-metadata-token-ttl-seconds: 30" 2>/dev/null)

        if [[ -n "$token" ]]; then
            result=$(curl -s -f --connect-timeout 2 \
                   -H "X-aws-ec2-metadata-token: $token" \
                   "$metadata_url/$metadata_key" 2>/dev/null)
        else
            # Fall back to IMDSv1
            result=$(curl -s -f --connect-timeout 2 "$metadata_url/$metadata_key" 2>/dev/null)
        fi

        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
    elif command_exists wget; then
        result=$(wget -q -T 2 -O - "$metadata_url/$metadata_key" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
    fi

    warn "Unable to retrieve AWS instance metadata: $metadata_key"
    return 1
}

# Get GCP instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance/id, instance/zone)
# Outputs:
#   Metadata value on stdout
# Returns:
#   0 on success, 1 on failure
get_gcp_metadata() {
    local metadata_key="$1"
    local metadata_url="http://metadata.google.internal/computeMetadata/v1"
    local result

    if [[ -z "$metadata_key" ]]; then
        warn "Metadata key must be provided"
        return 1
    fi

    if command_exists curl; then
        result=$(curl -s -f -H "Metadata-Flavor: Google" --connect-timeout 2 \
               "$metadata_url/$metadata_key" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
    elif command_exists wget; then
        result=$(wget -q -T 2 -O - --header="Metadata-Flavor: Google" \
               "$metadata_url/$metadata_key" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
    fi

    warn "Unable to retrieve GCP instance metadata: $metadata_key"
    return 1
}

# Get Azure instance metadata
# Arguments:
#   $1 - Metadata path (e.g., instance, network/interface)
# Outputs:
#   Metadata value on stdout in JSON format
# Returns:
#   0 on success, 1 on failure
get_azure_metadata() {
    local metadata_path="${1:-instance}"
    local api_version="2021-02-01"
    local metadata_url="http://169.254.169.254/metadata/$metadata_path"
    local result

    if command_exists curl; then
        result=$(curl -s -f -H "Metadata: true" --connect-timeout 2 \
               "$metadata_url?api-version=$api_version&format=json" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
    elif command_exists wget; then
        result=$(wget -q -T 2 -O - --header="Metadata: true" \
               "$metadata_url?api-version=$api_version&format=json" 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
    fi

    warn "Unable to retrieve Azure instance metadata: $metadata_path"
    return 1
}

# Detect cloud provider
# Arguments:
#   None
# Outputs:
#   Cloud provider name on stdout
# Returns:
#   0 if detected, 1 if not detected
detect_cloud_provider() {
    # Check for cached result to avoid multiple checks
    if [[ -n "${DETECTED_CLOUD_PROVIDER:-}" ]]; then
        echo "$DETECTED_CLOUD_PROVIDER"
        return 0
    fi

    local provider="unknown"

    # Use command substitution instead of if statements for each provider
    if command_exists curl; then
        # Try AWS IMDSv2 first
        local aws_token
        aws_token=$(curl -s -f -X PUT --connect-timeout 1 \
                   "http://169.254.169.254/latest/api/token" \
                   -H "X-aws-ec2-metadata-token-ttl-seconds: 5" 2>/dev/null)

        if [[ -n "$aws_token" ]] && curl -s -f -H "X-aws-ec2-metadata-token: $aws_token" \
           --connect-timeout 1 "http://169.254.169.254/latest/meta-data/" &>/dev/null; then
            provider="aws"
        elif curl -s -f -H "Metadata-Flavor: Google" --connect-timeout 1 \
             "http://metadata.google.internal/computeMetadata/v1/" &>/dev/null; then
            provider="gcp"
        elif curl -s -f -H "Metadata: true" --connect-timeout 1 \
             "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
            provider="azure"
        fi
    fi

    # Fallback to file-based detection if metadata service check is inconclusive
    if [[ "$provider" == "unknown" ]]; then
        if [[ -f /sys/hypervisor/uuid ]] && grep -i -q "ec2" /sys/hypervisor/uuid; then
            provider="aws"
        elif [[ -f /sys/class/dmi/id/product_name ]] && grep -i -q "Google Compute Engine" /sys/class/dmi/id/product_name; then
            provider="gcp"
        elif [[ -f /sys/class/dmi/id/chassis_asset_tag ]] && grep -i -q "7783-7084-3265-9085-8269-3286-77" /sys/class/dmi/id/chassis_asset_tag; then
            provider="azure"
        fi
    fi

    # Cache the result for future calls
    DETECTED_CLOUD_PROVIDER="$provider"
    export DETECTED_CLOUD_PROVIDER

    echo "$provider"
    [[ "$provider" != "unknown" ]] && return 0 || return 1
}

# Check TLS certificate expiration
# Arguments:
#   $1 - Domain name
#   $2 - Warning threshold in days (optional - defaults to 30)
# Returns:
#   0 if certificate is valid and not expiring soon
#   1 if certificate is expiring soon or expired
#   2 if check failed
check_certificate_expiration() {
    local domain="$1"
    local threshold_days="${2:-30}"
    local expiry_date=""
    local days_remaining=0
    local temp_cert=""

    if [[ -z "$domain" ]]; then
        warn "Domain name must be provided"
        return 2
    fi

    if ! is_valid_url "https://$domain"; then
        warn "Invalid domain: $domain"
        return 2
    fi

    if ! command_exists openssl; then
        warn "OpenSSL not available, cannot check certificate expiration"
        return 2
    fi

    # Create a temporary file for the certificate
    temp_cert="$(mktemp)"

    # Get certificate expiration date using OpenSSL
    if ! timeout 10 openssl s_client -servername "$domain" -connect "$domain:443" -verify_hostname "$domain" \
         </dev/null 2>/dev/null | openssl x509 -outform PEM -out "$temp_cert"; then
        warn "Failed to retrieve certificate for $domain"
        rm -f "$temp_cert"
        return 2
    fi

    # Extract expiration date
    expiry_date=$(openssl x509 -in "$temp_cert" -noout -enddate 2>/dev/null | cut -d= -f2)
    rm -f "$temp_cert"

    if [[ -z "$expiry_date" ]]; then
        warn "Failed to parse certificate expiration date for $domain"
        return 2
    fi

    # Calculate days remaining until expiration
    if command_exists date; then
        local expiry_epoch=""
        local current_epoch=""

        # Try GNU date format first, then BSD date format
        if date --version &>/dev/null; then
            # GNU date (Linux)
            expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
            current_epoch=$(date +%s)
        else
            # BSD date (macOS)
            expiry_epoch=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)
            current_epoch=$(date +%s)
        fi

        if [[ -n "$expiry_epoch" && -n "$current_epoch" ]]; then
            local seconds_remaining=$((expiry_epoch - current_epoch))
            days_remaining=$((seconds_remaining / 86400))
        else
            warn "Failed to calculate certificate expiration for $domain"
            return 2
        fi
    else
        warn "Date command not available, cannot calculate certificate expiration"
        return 2
    fi

    # Check if the certificate is expired or expiring soon
    if (( days_remaining <= 0 )); then
        warn "Certificate for $domain has EXPIRED!"
        return 1
    elif (( days_remaining <= threshold_days )); then
        warn "Certificate for $domain will expire in $days_remaining days (threshold: $threshold_days days)"
        return 1
    fi

    log "Certificate for $domain is valid for $days_remaining days" "INFO"
    return 0
}

# Monitor a service and restart if needed
# Arguments:
#   $1 - Service name
#   $2 - Restart command (optional - defaults to systemctl restart)
#   $3 - Health check command (optional - defaults to systemctl is-active)
# Returns:
#   0 if service is running or was successfully restarted, 1 otherwise
monitor_and_restart_service() {
    local service_name="$1"
    local restart_cmd="${2:-}"
    local health_check="${3:-}"
    local max_retries=3
    local retry_delay=5
    local retries=0

    if [[ -z "$service_name" ]]; then
        error_exit "Service name must be provided"
        return 1
    fi

    # Set default commands based on service name if not provided
    if [[ -z "$restart_cmd" ]]; then
        if command_exists systemctl; then
            restart_cmd="systemctl restart $service_name"
        elif command_exists service; then
            restart_cmd="service $service_name restart"
        else
            error_exit "Cannot determine how to restart service: $service_name"
            return 1
        fi
    fi

    if [[ -z "$health_check" ]]; then
        if command_exists systemctl; then
            health_check="systemctl is-active $service_name"
        elif command_exists service; then
            health_check="service $service_name status"
        else
            error_exit "Cannot determine how to check service status: $service_name"
            return 1
        fi
    fi

    log "Checking service: $service_name"

    # Check if service is running using the provided health check command
    if eval "$health_check" &>/dev/null; then
        debug "Service $service_name is running correctly"
        return 0
    fi

    # Service is not running, attempt to restart it
    warn "Service $service_name is not running properly, attempting restart"

    # Try restarting with retries
    while (( retries < max_retries )); do
        debug "Restart attempt #$((retries+1)) for $service_name"

        if eval "$restart_cmd" &>/dev/null; then
            log "Restarted service: $service_name, waiting $retry_delay seconds to verify..."
            sleep "$retry_delay"

            if eval "$health_check" &>/dev/null; then
                log "Service $service_name is now running properly"
                return 0
            fi
        fi

        ((retries++))
        warn "Restart attempt #$retries failed for $service_name"

        if (( retries < max_retries )); then
            warn "Retrying in $retry_delay seconds..."
            sleep "$retry_delay"
        fi
    done

    error_exit "Failed to restart service $service_name after $max_retries attempts" 1
}

# Format timestamp for consistent usage
# Arguments:
#   $1 - Format (optional - defaults to "full")
# Outputs:
#   Formatted timestamp string
# Returns:
#   0 always
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
        unix)
            date '+%s'
            ;;
        *)
            date '+%Y-%m-%d %H:%M:%S'
            ;;
    esac

    return 0
}

# Export cloud provider functions
export -f check_aws_auth
export -f check_gcp_auth
export -f check_azure_auth
export -f get_aws_metadata
export -f get_gcp_metadata
export -f get_azure_metadata
export -f detect_cloud_provider
export -f check_certificate_expiration
export -f monitor_and_restart_service
export -f format_timestamp
