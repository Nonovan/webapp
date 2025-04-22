#!/bin/bash
# Input Validation and Sanitization Library for Cloud Infrastructure Platform
#
# This script provides standardized functions for validating and sanitizing
# user input across all scripts in the Cloud Infrastructure Platform.
#
# Usage: source scripts/monitoring/common/validation.sh

# Import common utility functions if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
UTILS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"

if [[ -f "$UTILS_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$UTILS_PATH"
else
    echo "ERROR: Required utility functions not found at $UTILS_PATH"
    exit 1
fi

#######################################
# TEXT VALIDATION FUNCTIONS
#######################################

# Validate text input against a regex pattern
# Arguments:
#   $1 - Text to validate
#   $2 - Regex pattern
#   $3 - Error message (optional)
# Returns: 0 if valid, 1 if not
validate_pattern() {
    local text="$1"
    local pattern="$2"
    local error_msg="${3:-Invalid input format}"

    if [[ -z "$text" ]]; then
        log "Input is empty" "ERROR"
        return 1
    fi

    if [[ "$text" =~ $pattern ]]; then
        return 0
    else
        log "$error_msg: $text" "ERROR"
        return 1
    fi
}

# Validate input string length
# Arguments:
#   $1 - Text to validate
#   $2 - Minimum length (optional, default: 1)
#   $3 - Maximum length (optional, default: 255)
# Returns: 0 if valid, 1 if not
validate_length() {
    local text="$1"
    local min="${2:-1}"
    local max="${3:-255}"

    if [[ -z "$text" && "$min" -gt 0 ]]; then
        log "Input is empty" "ERROR"
        return 1
    fi

    local length=${#text}
    if (( length < min || length > max )); then
        log "Input length ($length) must be between $min and $max characters" "ERROR"
        return 1
    fi

    return 0
}

# Validate text contains only alphanumeric characters
# Arguments:
#   $1 - Text to validate
#   $2 - Allow spaces (true/false, default: false)
#   $3 - Allow underscores (true/false, default: true)
# Returns: 0 if valid, 1 if not
validate_alphanumeric() {
    local text="$1"
    local allow_spaces="${2:-false}"
    local allow_underscores="${3:-true}"
    local pattern="^[a-zA-Z0-9"

    if [[ "$allow_spaces" == "true" ]]; then
        pattern="${pattern} "
    fi

    if [[ "$allow_underscores" == "true" ]]; then
        pattern="${pattern}_"
    fi

    pattern="${pattern}]+$"

    validate_pattern "$text" "$pattern" "Input must contain only alphanumeric characters"
    return $?
}

# Validate alphanumeric with common special characters
# Arguments:
#   $1 - Text to validate
#   $2 - Allowed special chars (default: '.-_@')
# Returns: 0 if valid, 1 if not
validate_alphanumeric_special() {
    local text="$1"
    local special_chars="${2:-\.\-_@}"
    local pattern="^[a-zA-Z0-9${special_chars}]+$"

    validate_pattern "$text" "$pattern" "Input contains invalid characters"
    return $?
}

# Sanitize text by removing dangerous characters
# Arguments:
#   $1 - Text to sanitize
#   $2 - Replacement character (optional, default: '')
# Returns: Sanitized text
sanitize_text() {
    local text="$1"
    local replacement="${2:-}"

    # Remove dangerous characters (script tags, quotes, etc.)
    echo "$text" | sed -e 's/[<>();&|$]/'"$replacement"'/g'
}

# Escape text for shell usage
# Arguments:
#   $1 - Text to escape
# Returns: Escaped text
escape_shell() {
    local text="$1"
    printf '%q' "$text"
}

# Escape text for SQL usage
# Arguments:
#   $1 - Text to escape
# Returns: Escaped text
escape_sql() {
    local text="$1"
    # Replace single quotes with doubled single quotes
    echo "${text//\'/\'\'}"
}

# Escape text for usage in HTML
# Arguments:
#   $1 - Text to escape
# Returns: Escaped HTML
escape_html() {
    local text="$1"
    local result="$text"
    result="${result//&/&amp;}"
    result="${result//</&lt;}"
    result="${result//>/&gt;}"
    result="${result//\"/&quot;}"
    result="${result//\'/&#39;}"
    echo "$result"
}

#######################################
# NUMERIC VALIDATION FUNCTIONS
#######################################

# Check if input is a number (integer or float)
# Arguments:
#   $1 - Value to validate
#   $2 - Allow float (true/false, default: false)
# Returns: 0 if valid, 1 if not
is_number() {
    local value="$1"
    local allow_float="${2:-false}"

    if [[ -z "$value" ]]; then
        return 1
    fi

    if [[ "$allow_float" == "true" ]]; then
        # Allow float numbers
        if [[ "$value" =~ ^[+-]?[0-9]*\.?[0-9]+$ ]]; then
            return 0
        fi
    else
        # Only integers
        if [[ "$value" =~ ^[+-]?[0-9]+$ ]]; then
            return 0
        fi
    fi

    return 1
}

# Validate integer within range
# Arguments:
#   $1 - Value to validate
#   $2 - Minimum value (optional)
#   $3 - Maximum value (optional)
# Returns: 0 if valid, 1 if not
validate_integer() {
    local value="$1"
    local min="$2"
    local max="$3"

    # Check if value is an integer
    if ! is_number "$value"; then
        log "Input is not a valid integer: $value" "ERROR"
        return 1
    fi

    # Check minimum if provided
    if [[ -n "$min" ]]; then
        if (( value < min )); then
            log "Input ($value) is below minimum value ($min)" "ERROR"
            return 1
        fi
    fi

    # Check maximum if provided
    if [[ -n "$max" ]]; then
        if (( value > max )); then
            log "Input ($value) is above maximum value ($max)" "ERROR"
            return 1
        fi
    fi

    return 0
}

# Validate float within range
# Arguments:
#   $1 - Value to validate
#   $2 - Minimum value (optional)
#   $3 - Maximum value (optional)
# Returns: 0 if valid, 1 if not
validate_float() {
    local value="$1"
    local min="$2"
    local max="$3"

    # Check if value is a float
    if ! is_number "$value" "true"; then
        log "Input is not a valid number: $value" "ERROR"
        return 1
    fi

    # Check minimum if provided using bc for float comparison
    if [[ -n "$min" ]]; then
        if (( $(echo "$value < $min" | bc -l) )); then
            log "Input ($value) is below minimum value ($min)" "ERROR"
            return 1
        fi
    fi

    # Check maximum if provided using bc for float comparison
    if [[ -n "$max" ]]; then
        if (( $(echo "$value > $max" | bc -l) )); then
            log "Input ($value) is above maximum value ($max)" "ERROR"
            return 1
        fi
    fi

    return 0
}

# Validate port number
# Arguments:
#   $1 - Port number to validate
# Returns: 0 if valid, 1 if not
validate_port() {
    local port="$1"
    validate_integer "$port" 1 65535
    return $?
}

#######################################
# FILE AND PATH VALIDATION FUNCTIONS
#######################################

# Validate file path safety
# Arguments:
#   $1 - Path to validate
# Returns: 0 if safe, 1 if not
validate_path_safety() {
    local path="$1"

    # Check for directory traversal attempts
    if [[ "$path" == *".."* || "$path" == *"~"* ]]; then
        log "Path contains forbidden traversal sequences: $path" "ERROR"
        return 1
    fi

    # Check for absolute paths if not allowed
    if [[ "$path" == /* ]]; then
        log "Path cannot be absolute: $path" "ERROR"
        return 1
    fi

    # Validate characters
    if [[ ! "$path" =~ ^[a-zA-Z0-9_\./\-]+$ ]]; then
        log "Path contains invalid characters: $path" "ERROR"
        return 1
    fi

    return 0
}

# Validate file exists with sufficient permissions
# Arguments:
#   $1 - File path to check
#   $2 - Required permissions (r, w, x or combination)
# Returns: 0 if valid, 1 if not
validate_file_access() {
    local file_path="$1"
    local permissions="${2:-r}"
    local perm_flag=""

    # Build permission check flags
    if [[ "$permissions" == *"r"* ]]; then
        perm_flag="${perm_flag}r"
    fi
    if [[ "$permissions" == *"w"* ]]; then
        perm_flag="${perm_flag}w"
    fi
    if [[ "$permissions" == *"x"* ]]; then
        perm_flag="${perm_flag}x"
    fi

    if [[ ! -f "$file_path" ]]; then
        log "File does not exist: $file_path" "ERROR"
        return 1
    fi

    if [[ ! -"${perm_flag}" "$file_path" ]]; then
        log "Missing required permissions ($permissions) on file: $file_path" "ERROR"
        return 1
    fi

    return 0
}

# Validate directory exists with sufficient permissions
# Arguments:
#   $1 - Directory path to check
#   $2 - Required permissions (r, w, x or combination)
# Returns: 0 if valid, 1 if not
validate_directory_access() {
    local dir_path="$1"
    local permissions="${2:-r}"
    local perm_flag=""

    # Build permission check flags
    if [[ "$permissions" == *"r"* ]]; then
        perm_flag="${perm_flag}r"
    fi
    if [[ "$permissions" == *"w"* ]]; then
        perm_flag="${perm_flag}w"
    fi
    if [[ "$permissions" == *"x"* ]]; then
        perm_flag="${perm_flag}x"
    fi

    if [[ ! -d "$dir_path" ]]; then
        log "Directory does not exist: $dir_path" "ERROR"
        return 1
    fi

    if [[ ! -"${perm_flag}" "$dir_path" ]]; then
        log "Missing required permissions ($permissions) on directory: $dir_path" "ERROR"
        return 1
    fi

    return 0
}

#######################################
# NETWORK AND URL VALIDATION FUNCTIONS
#######################################

# Validate IP address format
# Arguments:
#   $1 - IP address to validate
#   $2 - IP version (4 or 6, default: 4)
# Returns: 0 if valid, 1 if not
validate_ip_address() {
    local ip="$1"
    local version="${2:-4}"

    if [[ -z "$ip" ]]; then
        log "IP address is empty" "ERROR"
        return 1
    fi

    if [[ "$version" == "4" ]]; then
        # IPv4 validation
        local ipv4_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
        if [[ ! "$ip" =~ $ipv4_pattern ]]; then
            log "Invalid IPv4 format: $ip" "ERROR"
            return 1
        fi

        # Validate each octet
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                log "Invalid IPv4 octet value: $octet" "ERROR"
                return 1
            fi
        done
    elif [[ "$version" == "6" ]]; then
        # Basic IPv6 validation - simplified pattern
        local ipv6_pattern='^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if [[ ! "$ip" =~ $ipv6_pattern ]]; then
            # Try regex for compressed IPv6
            ipv6_pattern='^([0-9a-fA-F]{0,4}:){1,7}(:[0-9a-fA-F]{0,4}){0,7}$'
            if [[ ! "$ip" =~ $ipv6_pattern || "$ip" != *:* ]]; then
                log "Invalid IPv6 format: $ip" "ERROR"
                return 1
            fi

            # Additional checks for valid compressed IPv6 could be added here
        fi
    else
        log "Invalid IP version specified: $version" "ERROR"
        return 1
    fi

    return 0
}

# Validate hostname format
# Arguments:
#   $1 - Hostname to validate
# Returns: 0 if valid, 1 if not
validate_hostname() {
    local hostname="$1"

    # Check length
    if [[ ${#hostname} -gt 255 ]]; then
        log "Hostname exceeds maximum length of 255 characters" "ERROR"
        return 1
    fi

    # Simplified hostname validation regex
    local pattern="^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$"

    if [[ ! "$hostname" =~ $pattern ]]; then
        log "Invalid hostname format: $hostname" "ERROR"
        return 1
    fi

    return 0
}

# Validate URL format
# Arguments:
#   $1 - URL to validate
#   $2 - Allow non-http protocols (true/false, default: false)
# Returns: 0 if valid, 1 if not
validate_url() {
    local url="$1"
    local allow_non_http="${2:-false}"

    # Basic URL validation with protocol
    local http_pattern='^(https?):\/\/([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:[0-9]{1,5})?(\/[a-zA-Z0-9\-._~:/?#[\]@!$&'\''()*+,;=]*)?$'

    # Check if URL has protocol
    if [[ ! "$url" =~ :// ]]; then
        log "URL is missing protocol (http:// or https://): $url" "ERROR"
        return 1
    fi

    # Check for http/https protocol
    if [[ "$url" =~ ^https?:// ]]; then
        if [[ "$url" =~ $http_pattern ]]; then
            return 0
        else
            log "Invalid URL format: $url" "ERROR"
            return 1
        fi
    elif [[ "$allow_non_http" == "true" ]]; then
        # Less strict check for non-http protocols if allowed
        local general_pattern='^[a-zA-Z]+:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(:[0-9]{1,5})?(\/[a-zA-Z0-9\-._~:/?#[\]@!$&'\''()*+,;=]*)?$'
        if [[ "$url" =~ $general_pattern ]]; then
            return 0
        else
            log "Invalid URL format: $url" "ERROR"
            return 1
        fi
    else
        log "URL must use http or https protocol: $url" "ERROR"
        return 1
    fi
}

# Check if URL is reachable
# Arguments:
#   $1 - URL to check
#   $2 - Timeout in seconds (default: 5)
# Returns: 0 if reachable, 1 if not
is_url_reachable() {
    local url="$1"
    local timeout="${2:-5}"

    if ! validate_url "$url"; then
        return 1
    fi

    # Try curl with timeout
    if command -v curl >/dev/null 2>&1; then
        if curl --silent --head --fail --max-time "$timeout" "$url" >/dev/null 2>&1; then
            return 0
        fi
    # Fallback to wget if curl is not available
    elif command -v wget >/dev/null 2>&1; then
        if wget --spider --timeout="$timeout" "$url" >/dev/null 2>&1; then
            return 0
        fi
    else
        log "Neither curl nor wget is available to check URL reachability" "WARNING"
        # We can't check, so assume it's reachable
        return 0
    fi

    log "URL is not reachable: $url" "ERROR"
    return 1
}

#######################################
# DATE AND TIME VALIDATION FUNCTIONS
#######################################

# Validate date format
# Arguments:
#   $1 - Date string to validate
#   $2 - Format string (default: "%Y-%m-%d")
# Returns: 0 if valid, 1 if not
validate_date() {
    local date_str="$1"
    local format="${2:-%Y-%m-%d}"

    # Use date command to verify the format
    if ! date -d "$date_str" +"$format" &>/dev/null 2>&1; then
        # Try macOS date syntax if Linux syntax fails
        if ! date -j -f "$format" "$date_str" &>/dev/null 2>&1; then
            log "Invalid date format: $date_str (expected format: $format)" "ERROR"
            return 1
        fi
    fi

    return 0
}

# Validate time format
# Arguments:
#   $1 - Time string to validate
#   $2 - Format string (default: "%H:%M:%S")
# Returns: 0 if valid, 1 if not
validate_time() {
    local time_str="$1"
    local format="${2:-%H:%M:%S}"

    # Use validate_date with appropriate format
    validate_date "$time_str" "$format"
    return $?
}

# Validate datetime format
# Arguments:
#   $1 - Datetime string to validate
#   $2 - Format string (default: "%Y-%m-%d %H:%M:%S")
# Returns: 0 if valid, 1 if not
validate_datetime() {
    local datetime_str="$1"
    local format="${2:-%Y-%m-%d %H:%M:%S}"

    validate_date "$datetime_str" "$format"
    return $?
}

#######################################
# DOMAIN-SPECIFIC VALIDATION FUNCTIONS
#######################################

# Validate email address format
# Arguments:
#   $1 - Email address to validate
# Returns: 0 if valid, 1 if not
validate_email() {
    local email="$1"
    local pattern='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    validate_pattern "$email" "$pattern" "Invalid email address format"
    return $?
}

# Validate environment name against allowed values
# Arguments:
#   $1 - Environment name to validate
# Returns: 0 if valid, 1 if not
validate_environment_name() {
    local env_name="$1"
    local valid_environments=("development" "staging" "production" "dr-recovery")

    for env in "${valid_environments[@]}"; do
        if [[ "$env_name" == "$env" ]]; then
            return 0
        fi
    done

    log "Invalid environment name: $env_name. Valid options: ${valid_environments[*]}" "ERROR"
    return 1
}

# Validate compliance standard name
# Arguments:
#   $1 - Compliance standard name to validate
# Returns: 0 if valid, 1 if not
validate_compliance_standard() {
    local standard="$1"
    local valid_standards=("pci-dss" "hipaa" "gdpr" "iso27001" "soc2" "security" "all")

    for std in "${valid_standards[@]}"; do
        if [[ "$standard" == "$std" ]]; then
            return 0
        fi
    done

    log "Invalid compliance standard: $standard. Valid options: ${valid_standards[*]}" "ERROR"
    return 1
}

# Validate output format against allowed values
# Arguments:
#   $1 - Format to validate
#   $2+ - Array of allowed formats (optional, defaults to common formats)
# Returns: 0 if valid, 1 if not
validate_output_format() {
    local format="$1"
    shift
    local valid_formats=("$@")

    # If no formats provided, use default ones
    if [[ ${#valid_formats[@]} -eq 0 ]]; then
        valid_formats=("json" "html" "text" "csv")
    fi

    for fmt in "${valid_formats[@]}"; do
        if [[ "$format" == "$fmt" ]]; then
            return 0
        fi
    done

    log "Invalid output format: $format. Valid options: ${valid_formats[*]}" "ERROR"
    return 1
}

# Validate AWS region name
# Arguments:
#   $1 - AWS region name to validate
# Returns: 0 if valid, 1 if not
validate_aws_region() {
    local region="$1"
    local valid_regions=(
        "us-east-1" "us-east-2" "us-west-1" "us-west-2"
        "eu-west-1" "eu-west-2" "eu-west-3" "eu-central-1" "eu-north-1" "eu-south-1"
        "ap-northeast-1" "ap-northeast-2" "ap-northeast-3" "ap-southeast-1" "ap-southeast-2"
        "ap-south-1" "ap-east-1" "sa-east-1" "ca-central-1" "me-south-1" "af-south-1"
    )

    for valid_region in "${valid_regions[@]}"; do
        if [[ "$region" == "$valid_region" ]]; then
            return 0
        fi
    done

    log "Invalid AWS region: $region" "ERROR"
    return 1
}

#######################################
# COMMAND-LINE ARGUMENT VALIDATION
#######################################

# Validate required command line arguments are present
# Arguments:
#   $1 - Associative array name containing arguments
#   $@ - List of required argument names
# Returns: 0 if all required args present, 1 if not
validate_required_args() {
    local args_array="$1"
    shift
    local required_args=("$@")
    local missing=0

    for arg in "${required_args[@]}"; do
        if [[ -z "${!args_array[$arg]}" ]]; then
            log "Required argument missing: $arg" "ERROR"
            ((missing++))
        fi
    done

    if [[ $missing -gt 0 ]]; then
        return 1
    fi

    return 0
}

# Validate command line argument count against expected range
# Arguments:
#   $1 - Actual argument count
#   $2 - Minimum expected count
#   $3 - Maximum expected count (optional, equal to min if not specified)
# Returns: 0 if valid, 1 if not
validate_arg_count() {
    local arg_count="$1"
    local min_count="$2"
    local max_count="${3:-$min_count}"

    if [[ $arg_count -lt $min_count ]]; then
        log "Too few arguments. Expected at least $min_count, got $arg_count" "ERROR"
        return 1
    fi

    if [[ $arg_count -gt $max_count && $max_count -ne $min_count ]]; then
        log "Too many arguments. Expected at most $max_count, got $arg_count" "ERROR"
        return 1
    fi

    return 0
}

# Parse command line flags into associative array
# Arguments:
#   $1 - Name of associative array to populate
#   $2+ - Command line arguments to parse
# Returns: 0 on success, 1 on failure
parse_command_line() {
    local -n args_array="$1"
    shift
    local args=("$@")
    local i=0

    while [[ $i -lt ${#args[@]} ]]; do
        local arg="${args[$i]}"

        # Check if argument is a flag (starts with -- or -)
        if [[ "$arg" == --* ]]; then
            # Long flag (--flag)
            local flag="${arg:2}"

            # Check if next item is a value (not a flag)
            if [[ $(( i + 1 )) -lt ${#args[@]} && ! "${args[$i+1]}" == -* ]]; then
                args_array["$flag"]="${args[$i+1]}"
                ((i+=2))
            else
                args_array["$flag"]="true"
                ((i++))
            fi
        elif [[ "$arg" == -* ]]; then
            # Short flag (-f)
            local flag="${arg:1}"

            # Check if next item is a value (not a flag)
            if [[ $(( i + 1 )) -lt ${#args[@]} && ! "${args[$i+1]}" == -* ]]; then
                args_array["$flag"]="${args[$i+1]}"
                ((i+=2))
            else
                args_array["$flag"]="true"
                ((i++))
            fi
        else
            # Not a flag, must be a positional argument
            args_array["positional_${#args_array[@]}"]="$arg"
            ((i++))
        fi
    done

    return 0
}

#######################################
# YAML/JSON VALIDATION FUNCTIONS
#######################################

# Validate JSON syntax
# Arguments:
#   $1 - JSON string or file path
#   $2 - Is file path (true/false, default: false)
# Returns: 0 if valid, 1 if not
validate_json_syntax() {
    local json="$1"
    local is_file="${2:-false}"
    local temp_file

    if [[ "$is_file" == "true" ]]; then
        if [[ ! -f "$json" ]]; then
            log "JSON file does not exist: $json" "ERROR"
            return 1
        fi

        if command -v jq &>/dev/null; then
            if ! jq empty "$json" 2>/dev/null; then
                log "Invalid JSON syntax in file: $json" "ERROR"
                return 1
            fi
        else
            # Fallback to Python if jq is not available
            if ! python3 -c "import json; json.load(open('$json'))" 2>/dev/null; then
                log "Invalid JSON syntax in file: $json" "ERROR"
                return 1
            fi
        fi
    else
        # Validate JSON string
        if command -v jq &>/dev/null; then
            temp_file=$(mktemp)
            echo "$json" > "$temp_file"

            if ! jq empty "$temp_file" 2>/dev/null; then
                rm -f "$temp_file"
                log "Invalid JSON syntax" "ERROR"
                return 1
            fi

            rm -f "$temp_file"
        else
            # Fallback to Python if jq is not available
            if ! python3 -c "import json; json.loads('$json')" 2>/dev/null; then
                log "Invalid JSON syntax" "ERROR"
                return 1
            fi
        fi
    fi

    return 0
}

# Validate YAML syntax
# Arguments:
#   $1 - YAML string or file path
#   $2 - Is file path (true/false, default: false)
# Returns: 0 if valid, 1 if not
validate_yaml_syntax() {
    local yaml="$1"
    local is_file="${2:-false}"
    local temp_file

    # Check if yamllint is available
    if ! command -v yamllint &>/dev/null; then
        log "yamllint not found, falling back to basic validation" "WARNING"

        # Fallback to Python for basic validation
        if [[ "$is_file" == "true" ]]; then
            if [[ ! -f "$yaml" ]]; then
                log "YAML file does not exist: $yaml" "ERROR"
                return 1
            fi

            if ! python3 -c "import yaml; yaml.safe_load(open('$yaml'))" 2>/dev/null; then
                log "Invalid YAML syntax in file: $yaml" "ERROR"
                return 1
            fi
        else
            temp_file=$(mktemp)
            echo "$yaml" > "$temp_file"

            if ! python3 -c "import yaml; yaml.safe_load(open('$temp_file'))" 2>/dev/null; then
                rm -f "$temp_file"
                log "Invalid YAML syntax" "ERROR"
                return 1
            fi

            rm -f "$temp_file"
        fi
    else
        # Use yamllint for more thorough validation
        if [[ "$is_file" == "true" ]]; then
            if [[ ! -f "$yaml" ]]; then
                log "YAML file does not exist: $yaml" "ERROR"
                return 1
            fi

            if ! yamllint -d "{extends: relaxed, rules: {line-length: {max: 120}}}" "$yaml" &>/dev/null; then
                log "Invalid YAML syntax in file: $yaml" "ERROR"
                return 1
            fi
        else
            temp_file=$(mktemp)
            echo "$yaml" > "$temp_file"

            if ! yamllint -d "{extends: relaxed, rules: {line-length: {max: 120}}}" "$temp_file" &>/dev/null; then
                rm -f "$temp_file"
                log "Invalid YAML syntax" "ERROR"
                return 1
            fi

            rm -f "$temp_file"
        fi
    fi

    return 0
}

#######################################
# SECURITY-SPECIFIC VALIDATION
#######################################

# Validate password strength
# Arguments:
#   $1 - Password to validate
#   $2 - Minimum length (default: 12)
#   $3 - Require uppercase (true/false, default: true)
#   $4 - Require lowercase (true/false, default: true)
#   $5 - Require numbers (true/false, default: true)
#   $6 - Require special chars (true/false, default: true)
# Returns: 0 if strong enough, 1 if not
validate_password_strength() {
    local password="$1"
    local min_length="${2:-12}"
    local require_upper="${3:-true}"
    local require_lower="${4:-true}"
    local require_numbers="${5:-true}"
    local require_special="${6:-true}"

    # Check length
    if [[ ${#password} -lt $min_length ]]; then
        log "Password too short (minimum $min_length characters)" "ERROR"
        return 1
    fi

    # Check for uppercase letters if required
    if [[ "$require_upper" == "true" && ! "$password" =~ [A-Z] ]]; then
        log "Password must contain at least one uppercase letter" "ERROR"
        return 1
    fi

    # Check for lowercase letters if required
    if [[ "$require_lower" == "true" && ! "$password" =~ [a-z] ]]; then
        log "Password must contain at least one lowercase letter" "ERROR"
        return 1
    fi

    # Check for numbers if required
    if [[ "$require_numbers" == "true" && ! "$password" =~ [0-9] ]]; then
        log "Password must contain at least one number" "ERROR"
        return 1
    fi

    # Check for special characters if required
    if [[ "$require_special" == "true" && ! "$password" =~ [^a-zA-Z0-9] ]]; then
        log "Password must contain at least one special character" "ERROR"
        return 1
    fi

    return 0
}

# Check if input contains potential command injection characters
# Arguments:
#   $1 - Input string to check
# Returns: 0 if safe, 1 if potentially unsafe
validate_command_injection() {
    local input="$1"
    local dangerous_chars=';|&$()`><'

    # Check for dangerous shell characters
    if [[ "$input" =~ [$dangerous_chars] ]]; then
        log "Input contains potentially dangerous characters: $input" "ERROR"
        return 1
    fi

    return 0
}

# Check if input contains patterns suggesting SQL injection
# Arguments:
#   $1 - Input string to check
# Returns: 0 if safe, 1 if potentially unsafe
validate_sql_injection() {
    local input="$1"

    # Check for common SQL injection patterns
    local patterns=(
        "--"
        "'"
        ";"
        "/*"
        "*/"
        "@@"
        "@variable"
        "char("
        "exec("
        "union select"
        "drop table"
        "drop database"
        "truncate table"
        "delete from"
        "insert into"
        "xp_cmdshell"
    )

    for pattern in "${patterns[@]}"; do
        if [[ "${input,,}" == *"${pattern,,}"* ]]; then
            log "Input contains potential SQL injection pattern: $pattern" "ERROR"
            return 1
        fi
    done

    return 0
}

# Export utility functions for use in other scripts
export -f validate_pattern
export -f validate_length
export -f validate_alphanumeric
export -f validate_alphanumeric_special
export -f sanitize_text
export -f escape_shell
export -f escape_sql
export -f escape_html
export -f is_number
export -f validate_integer
export -f validate_float
export -f validate_port
export -f validate_path_safety
export -f validate_file_access
export -f validate_directory_access
export -f validate_ip_address
export -f validate_hostname
export -f validate_url
export -f is_url_reachable
export -f validate_date
export -f validate_time
export -f validate_datetime
export -f validate_email
export -f validate_environment_name
export -f validate_compliance_standard
export -f validate_output_format
export -f validate_aws_region
export -f validate_required_args
export -f validate_arg_count
export -f parse_command_line
export -f validate_json_syntax
export -f validate_yaml_syntax
export -f validate_password_strength
export -f validate_command_injection
export -f validate_sql_injection

# Example usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    log "This script is intended to be sourced by other scripts, not executed directly."
    log "Example usage:"
    log "  source $(basename "${BASH_SOURCE[0]}")"
    log "  validate_integer \"\$port\" 1 65535 || exit 1"
    exit 1
fi
