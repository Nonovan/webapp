#!/bin/bash
# filepath: scripts/utils/common/common_advanced_functions.sh
# Advanced utility functions for Cloud Infrastructure Platform
# These functions provide specialized capabilities for specific use cases

# Check that this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    exit 1
fi

# Check if required variables and functions are defined
if [[ -z "$SCRIPT_DIR" || ! $(type -t log) == "function" ]]; then
    echo "Warning: This module requires core_functions to be loaded first"
    exit 1
fi

#######################################
# NOTIFICATION FUNCTIONS
#######################################

# Send email notification
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Recipient (optional - uses EMAIL_RECIPIENT from env if not provided)
#   $4 - Attachment file (optional)
# Returns: 0 on success, 1 on failure
send_email_notification() {
    local subject="$1"
    local message="$2"
    local recipient="${3:-${EMAIL_RECIPIENT:-}}"
    local attachment="${4:-}"

    # Check if recipient is provided
    if [[ -z "$recipient" ]]; then
        warn "No email recipient specified, notification not sent"
        return 1
    fi

    # Validate email format
    if ! is_valid_email "$recipient"; then
        warn "Invalid email recipient format: $recipient"
        return 1
    fi

    # Format subject with hostname for clarity
    local hostname=$(hostname -f 2>/dev/null || hostname)
    subject="[Cloud Platform ${hostname}] $subject"

    # Try different mail sending methods
    if command_exists mail; then
        if [[ -n "$attachment" && -f "$attachment" ]]; then
            echo -e "$message" | mail -s "$subject" -a "$attachment" "$recipient"
        else
            echo -e "$message" | mail -s "$subject" "$recipient"
        fi
        log "Email notification sent to $recipient: $subject" "INFO"
        return 0
    elif command_exists sendmail; then
        (
            echo "To: $recipient"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo
            echo -e "$message"
        ) | sendmail -t
        log "Email notification sent to $recipient via sendmail: $subject" "INFO"
        return 0
    elif command_exists aws && [[ -n "${AWS_SES_ENABLED:-}" && "$AWS_SES_ENABLED" == "true" ]]; then
        # AWS SES method
        local ses_region="${AWS_SES_REGION:-us-east-1}"
        local ses_from="${AWS_SES_FROM:-no-reply@example.com}"

        aws ses send-email \
            --region "$ses_region" \
            --from "$ses_from" \
            --destination "ToAddresses=$recipient" \
            --message "Subject={Data=$subject},Body={Text={Data=$message}}" \
            &>/dev/null

        log "Email notification sent via AWS SES to $recipient: $subject" "INFO"
        return 0
    else
        warn "No email sending method available, cannot send email notification"
        return 1
    fi
}

# Send Slack notification
# Arguments:
#   $1 - Message to send
#   $2 - Webhook URL (optional - uses SLACK_WEBHOOK_URL from env if not provided)
#   $3 - Channel (optional - uses default channel from webhook if not provided)
# Returns: 0 on success, 1 on failure
send_slack_notification() {
    local message="$1"
    local webhook="${2:-${SLACK_WEBHOOK_URL:-}}"
    local channel="${3:-}"
    local hostname=$(hostname -f 2>/dev/null || hostname)
    local environment="${ENVIRONMENT:-$(detect_environment)}"

    # Check if webhook URL is provided
    if [[ -z "$webhook" ]]; then
        warn "No Slack webhook URL specified, notification not sent"
        return 1
    fi

    # Check if curl is available
    if ! command_exists curl; then
        warn "curl command not available, cannot send Slack notification"
        return 1
    fi

    # Format the JSON payload - escaping special characters
    local sanitized_message="${message//\"/\\\"}"
    local payload
    if [[ -n "$channel" ]]; then
        payload="{\"text\":\"*[$environment - $hostname]* $sanitized_message\", \"channel\":\"$channel\"}"
    else
        payload="{\"text\":\"*[$environment - $hostname]* $sanitized_message\"}"
    fi

    # Send the notification with proper error handling
    local temp_file=$(mktemp)
    local status_code
    status_code=$(curl -s -w "%{http_code}" -X POST -H 'Content-type: application/json' \
        --data "$payload" "$webhook" -o "$temp_file")
    local curl_exit=$?

    # Check for successful HTTP status code and curl exit code
    if [[ $curl_exit -eq 0 && "$status_code" =~ ^2[0-9][0-9]$ ]]; then
        log "Slack notification sent: ${message:0:50}${message:50:+...}" "INFO"
        rm -f "$temp_file"
        return 0
    else
        local error_msg=$(cat "$temp_file")
        warn "Failed to send Slack notification. Status: $status_code, Error: ${error_msg:0:100}"
        rm -f "$temp_file"
        return 1
    fi
}

# Send notification (tries multiple methods)
# Arguments:
#   $1 - Subject/title
#   $2 - Message body
#   $3 - Priority (low, normal, high - optional, defaults to normal)
#   $4 - Attachment file path (optional)
# Returns: 0 if any method succeeds, 1 if all fail
send_notification() {
    local subject="$1"
    local message="$2"
    local priority="${3:-normal}"
    local attachment="${4:-}"
    local success=false

    # Add priority emoji based on level
    local emoji=""
    case "$priority" in
        high)
            emoji="🔴 "
            ;;
        normal)
            emoji="🟡 "
            ;;
        low)
            emoji="🟢 "
            ;;
    esac

    # Try Slack first if configured
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        if send_slack_notification "${emoji}${subject}\n${message}"; then
            success=true
        fi
    fi

    # Try email if configured
    if [[ -n "${EMAIL_RECIPIENT:-}" ]]; then
        if send_email_notification "${emoji}${subject}" "$message" "" "$attachment"; then
            success=true
        fi
    fi

    # Try Teams if configured
    if [[ -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
        if command_exists curl; then
            local sanitized_subject="${subject//\"/\\\"}"
            local sanitized_message="${message//\"/\\\"}"
            local teams_payload="{\"title\":\"${emoji}${sanitized_subject}\",\"text\":\"$sanitized_message\"}"

            local temp_file=$(mktemp)
            local status_code
            status_code=$(curl -s -w "%{http_code}" -H "Content-Type: application/json" \
                -d "$teams_payload" "${TEAMS_WEBHOOK_URL}" -o "$temp_file")
            local curl_exit=$?

            if [[ $curl_exit -eq 0 && "$status_code" =~ ^2[0-9][0-9]$ ]]; then
                log "Teams notification sent: $subject" "INFO"
                success=true
            else
                local error_msg=$(cat "$temp_file")
                warn "Failed to send Teams notification. Status: $status_code, Error: ${error_msg:0:100}"
            fi
            rm -f "$temp_file"
        fi
    fi

    if [[ "$success" == "true" ]]; then
        return 0
    else
        warn "No notification methods succeeded or were configured"
        return 1
    fi
}

#######################################
# STRING OPERATIONS
#######################################

# Generate a random string
# Arguments:
#   $1 - Length (optional - defaults to 16)
#   $2 - Character set (optional - defaults to alnum)
# Returns: Random string
generate_random_string() {
    local length="${1:-16}"
    local char_set="${2:-alnum}"
    local result

    # Validate length is a number
    if ! is_number "$length"; then
        log "Invalid length parameter: $length" "ERROR"
        return 1
    fi

    # Ensure length is reasonable
    if [[ "$length" -le 0 || "$length" -gt 1024 ]]; then
        log "Invalid length parameter: $length (must be between 1 and 1024)" "ERROR"
        return 1
    fi

    case "$char_set" in
        alnum)
            result=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length")
            ;;
        alpha)
            result=$(LC_ALL=C tr -dc 'a-zA-Z' < /dev/urandom | head -c "$length")
            ;;
        hex)
            result=$(LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c "$length")
            ;;
        secure)
            # Complex password with special chars
            result=$(LC_ALL=C tr -dc 'a-zA-Z0-9!@#$%^&*()_+?><~' < /dev/urandom | head -c "$length")
            ;;
        *)
            # Custom character set - sanitize input to prevent command injection
            local safe_charset="${char_set//[^a-zA-Z0-9!@#$%^&*()_+?><~=.,:;-]/}"
            if [[ -z "$safe_charset" ]]; then
                log "Invalid character set provided" "ERROR"
                return 1
            fi
            result=$(LC_ALL=C tr -dc "$safe_charset" < /dev/urandom | head -c "$length")
            ;;
    esac

    # Check if we successfully generated a string
    if [[ -z "$result" || ${#result} -lt "$length" ]]; then
        log "Failed to generate random string of requested length" "WARNING"
        # Fallback method for systems with issues
        local fallback=""
        for ((i=0; i<length; i++)); do
            fallback+=$(printf "%x" $((RANDOM % 16)))
        done
        echo "${fallback:0:$length}"
        return 0
    fi

    echo "$result"
    return 0
}

# URL encode a string
# Arguments:
#   $1 - String to encode
# Returns: URL-encoded string
url_encode() {
    local string="$1"
    local encoded=""
    local i

    for (( i=0; i<${#string}; i++ )); do
        local c="${string:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) printf -v encoded '%s%%%02X' "$encoded" "'$c" ;;
        esac
    done

    echo "$encoded"
    return 0
}

# Parse JSON string to extract a value
# Arguments:
#   $1 - JSON string
#   $2 - Key path (e.g., ".user.name" or ".users[0].email")
# Returns: Value at key path or empty string
parse_json() {
    local json="$1"
    local key_path="$2"
    local result=""

    # Validate inputs
    if [[ -z "$json" ]]; then
        warn "Empty JSON input provided to parse_json"
        return 1
    fi

    if [[ -z "$key_path" ]]; then
        warn "No key path provided to parse_json"
        return 1
    fi

    if command_exists jq; then
        result=$(echo "$json" | jq -r "$key_path" 2>/dev/null)
        if [[ $? -eq 0 && "$result" != "null" ]]; then
            echo "$result"
            return 0
        fi
        return 1
    else
        warn "jq not available for proper JSON parsing"

        # Simple fallback for very basic JSON (not recommended)
        # This will not work with nested objects or arrays
        if [[ "$key_path" =~ ^\. ]]; then
            # Remove leading dot
            key_path="${key_path:1}"
        fi

        result=$(echo "$json" | grep -o "\"$key_path\":\"[^\"]*\"" | cut -d'"' -f4)
        if [[ -n "$result" ]]; then
            echo "$result"
            return 0
        fi
        return 1
    fi
}

# Parse INI file section
# Arguments:
#   $1 - File path
#   $2 - Section name
#   $3 - Key (optional - if provided returns just this key's value)
# Returns: All key=value pairs in section or specific key value
parse_ini_section() {
    local file="$1"
    local section="$2"
    local key="${3:-}"

    if [[ ! -f "$file" ]]; then
        warn "INI file not found: $file"
        return 1
    fi

    # Validate file permission for security
    if [[ ! -r "$file" ]]; then
        warn "Permission denied reading INI file: $file"
        return 1
    fi

    local section_content
    section_content=$(sed -n "/^\[$section\]/,/^\[/p" "$file" | grep -v "^\[")

    # Check if section exists
    if [[ -z "$section_content" ]]; then
        warn "Section [$section] not found in INI file: $file"
        return 1
    fi

    if [[ -n "$key" ]]; then
        local value=$(echo "$section_content" | grep "^$key=" | cut -d= -f2-)
        if [[ -n "$value" ]]; then
            echo "$value"
            return 0
        else
            warn "Key '$key' not found in section [$section] of INI file: $file"
            return 1
        fi
    else
        echo "$section_content"
        return 0
    fi
}

# Convert YAML to JSON
# Arguments:
#   $1 - YAML file path
#   $2 - Output JSON file path (optional)
# Returns: JSON string if output file not provided
yaml_to_json() {
    local yaml_file="$1"
    local json_file="${2:-}"

    if [[ ! -f "$yaml_file" ]]; then
        log "YAML file not found: $yaml_file" "ERROR"
        return 1
    fi

    # Validate file permission for security
    if [[ ! -r "$yaml_file" ]]; then
        log "Permission denied reading YAML file: $yaml_file" "ERROR"
        return 1
    fi

    # Check file size for security
    local file_size=$(stat -c %s "$yaml_file" 2>/dev/null || stat -f %z "$yaml_file" 2>/dev/null)
    if [[ -n "$file_size" && "$file_size" -gt 10485760 ]]; then
        log "YAML file too large (>10MB): $yaml_file" "ERROR"
        return 1
    fi

    if command_exists python3; then
        if [[ -n "$json_file" ]]; then
            # Ensure directory exists for output file
            mkdir -p "$(dirname "$json_file")" || {
                log "Failed to create directory for JSON output file" "ERROR"
                return 1
            }
            python3 -c "
import yaml, json, sys
try:
    with open('$yaml_file', 'r') as yaml_input:
        data = yaml.safe_load(yaml_input)
    with open('$json_file', 'w') as json_output:
        json.dump(data, json_output, indent=2)
    sys.exit(0)
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
            return $?
        else
            python3 -c "
import yaml, json, sys
try:
    with open('$yaml_file', 'r') as yaml_input:
        data = yaml.safe_load(yaml_input)
    print(json.dumps(data, indent=2))
    sys.exit(0)
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
            return $?
        fi
    elif command_exists python; then
        if [[ -n "$json_file" ]]; then
            # Ensure directory exists for output file
            mkdir -p "$(dirname "$json_file")" || {
                log "Failed to create directory for JSON output file" "ERROR"
                return 1
            }
            python -c "
import yaml, json, sys
try:
    with open('$yaml_file', 'r') as yaml_input:
        data = yaml.safe_load(yaml_input)
    with open('$json_file', 'w') as json_output:
        json.dump(data, json_output, indent=2)
    sys.exit(0)
except Exception as e:
    print(str(e))
    sys.exit(1)
" 2>/dev/null
            return $?
        else
            python -c "
import yaml, json, sys
try:
    with open('$yaml_file', 'r') as yaml_input:
        data = yaml.safe_load(yaml_input)
    print(json.dumps(data, indent=2))
    sys.exit(0)
except Exception as e:
    print(str(e))
    sys.exit(1)
" 2>/dev/null
            return $?
        fi
    elif command_exists yq; then
        if [[ -n "$json_file" ]]; then
            yq eval -j "$yaml_file" > "$json_file" 2>/dev/null
            return $?
        else
            yq eval -j "$yaml_file" 2>/dev/null
            return $?
        fi
    else
        log "No YAML parsing tools available (python with yaml module or yq)" "ERROR"
        return 1
    fi
}

# Format JSON string
# Arguments:
#   $1 - JSON string or file
#   $2 - Indent level (optional, defaults to 2)
# Returns: Formatted JSON
format_json() {
    local json="$1"
    local indent="${2:-2}"

    # Check if input is a file
    if [[ -f "$json" ]]; then
        json=$(cat "$json")
    fi

    if command_exists jq; then
        echo "$json" | jq --indent "$indent" '.'
    elif command_exists python3; then
        echo "$json" | python3 -m json.tool --indent "$indent"
    elif command_exists python; then
        echo "$json" | python -m json.tool
    else
        # If no formatting tools are available, return the original JSON
        echo "$json"
    fi
}

# Export notification functions
export -f send_email_notification
export -f send_slack_notification
export -f send_notification

# Export string functions
export -f generate_random_string
export -f url_encode
export -f parse_json
export -f parse_ini_section
export -f yaml_to_json
export -f format_json
