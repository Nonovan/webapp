#!/bin/bash
# filepath: scripts/security/common/validation.sh
#
# Input Validation and Sanitization Utility for Security Scripts
# Part of Cloud Infrastructure Platform security module
#
# This script provides standardized validation functions for security-related
# scripts to prevent common injection attacks, ensure proper input formatting,
# and validate parameters against expected values or ranges.
#
# Usage: source scripts/security/common/validation.sh

# Ensure script is not executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: This script should be sourced, not executed directly."
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ===== Version information =====
readonly SECURITY_VALIDATION_VERSION="1.0.0"
readonly SECURITY_VALIDATION_DATE="2024-08-17"

# ===== Import dependencies =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source logging utility if available
if [[ -f "$SCRIPT_DIR/logging.sh" ]]; then
    # shellcheck source=./logging.sh
    source "$SCRIPT_DIR/logging.sh"
else
    # Define minimal logging functions if logging.sh is not available
    log_debug() { [[ "${SECURITY_LOG_LEVEL:-INFO}" == "DEBUG" ]] && echo "[DEBUG] $1" >&2 || true; }
    log_info() { echo "[INFO] $1" >&2; }
    log_warning() { echo "[WARNING] $1" >&2; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_critical() { echo "[CRITICAL] $1" >&2; }
fi

# ===== Configuration =====

# Set default values if not already defined
: "${SECURITY_VALIDATION_STRICT:=true}"
: "${SECURITY_VALIDATION_TIMEOUT:=5}"
: "${SECURITY_VALIDATION_MAX_LENGTH:=8192}"

# Define regular expressions for common validations
readonly REGEX_IPV4="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
readonly REGEX_IPV6="^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$"
readonly REGEX_HOSTNAME="^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
readonly REGEX_EMAIL="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
readonly REGEX_UUID="^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
readonly REGEX_PATH_TRAVERSAL="(\.\.|~)"
readonly REGEX_COMMAND_INJECTION="[;&|<>\`\$\(\)\\\"\']"
readonly REGEX_ALPHANUMERIC="^[a-zA-Z0-9]+$"
readonly REGEX_ALPHANUMERIC_EXTENDED="^[a-zA-Z0-9_\-\.]+$"

# ===== General Validation Functions =====

# Check if a value is empty
# Arguments:
#   $1 - Value to check
# Returns:
#   0 if the value is empty (null, undefined or empty string), 1 otherwise
is_empty() {
    local value="${1-}"
    [[ -z "$value" ]]
    return $?
}

# Check if a value is not empty
# Arguments:
#   $1 - Value to check
# Returns:
#   0 if the value is not empty, 1 if empty
is_not_empty() {
    ! is_empty "$1"
    return $?
}

# Check if a value is a valid number (integer or float based on flag)
# Arguments:
#   $1 - Value to check
#   $2 - Allow floating point (true/false, defaults to false)
# Returns:
#   0 if the value is a valid number, 1 otherwise
is_number() {
    local value="$1"
    local allow_float="${2:-false}"

    # Check for empty value
    if is_empty "$value"; then
        log_debug "Empty value provided to is_number"
        return 1
    fi

    # Check if it's a number
    if [[ "$allow_float" == "true" ]]; then
        # Allow floating point
        [[ "$value" =~ ^[+-]?[0-9]*\.?[0-9]+$ ]]
        return $?
    else
        # Integer only
        [[ "$value" =~ ^[+-]?[0-9]+$ ]]
        return $?
    fi
}

# Check if a value is within a specified range
# Arguments:
#   $1 - Value to check
#   $2 - Minimum value (inclusive)
#   $3 - Maximum value (inclusive)
#   $4 - Allow floating point (true/false, defaults to false)
# Returns:
#   0 if the value is within range, 1 otherwise
is_in_range() {
    local value="$1"
    local min="$2"
    local max="$3"
    local allow_float="${4:-false}"

    # Make sure it's a number first
    if ! is_number "$value" "$allow_float"; then
        log_debug "Value is not a number: $value"
        return 1
    fi

    # Check that min and max are numbers
    if ! is_number "$min" "$allow_float" || ! is_number "$max" "$allow_float"; then
        log_debug "Min or max is not a valid number: min=$min, max=$max"
        return 1
    fi

    # Use bc for floating point comparison if needed
    if [[ "$allow_float" == "true" ]]; then
        if (( $(echo "$value < $min" | bc -l) )) || (( $(echo "$value > $max" | bc -l) )); then
            log_debug "Value $value is outside range $min-$max"
            return 1
        fi
    else
        # Integer comparison
        if (( value < min )) || (( value > max )); then
            log_debug "Value $value is outside range $min-$max"
            return 1
        fi
    fi

    return 0
}

# Validate string length
# Arguments:
#   $1 - String to check
#   $2 - Minimum length (inclusive)
#   $3 - Maximum length (inclusive)
# Returns:
#   0 if the string length is within range, 1 otherwise
has_valid_length() {
    local value="$1"
    local min="${2:-0}"
    local max="${3:-$SECURITY_VALIDATION_MAX_LENGTH}"

    # Ensure value is a string
    if [[ -n "$value" ]]; then
        log_debug "Value is not a valid string"
        return 1
    fi

    # Get string length
    local length=${#value}

    # Check range
    if (( length < min )) || (( length > max )); then
        log_debug "String length $length is outside range $min-$max"
        return 1
    fi

    return 0
}

# Check if a string matches a regular expression pattern
# Arguments:
#   $1 - String to check
#   $2 - Regular expression pattern
# Returns:
#   0 if the string matches the pattern, 1 otherwise
matches_pattern() {
    local value="$1"
    local pattern="$2"

    # Check for empty value
    if is_empty "$value" || is_empty "$pattern"; then
        log_debug "Empty value or pattern provided to matches_pattern"
        return 1
    fi

    # Check if the string matches the pattern
    [[ "$value" =~ $pattern ]]
    return $?
}

# Check if a string contains only alphanumeric characters
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is alphanumeric, 1 otherwise
is_alphanumeric() {
    matches_pattern "$1" "$REGEX_ALPHANUMERIC"
    return $?
}

# Check if a string contains only alphanumeric characters plus some allowed special characters
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is valid, 1 otherwise
is_alphanumeric_extended() {
    matches_pattern "$1" "$REGEX_ALPHANUMERIC_EXTENDED"
    return $?
}

# Check if a string is a valid IPv4 address
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is a valid IPv4 address, 1 otherwise
is_ipv4() {
    local ip="$1"

    # Check basic pattern
    if ! matches_pattern "$ip" "$REGEX_IPV4"; then
        return 1
    fi

    # Validate each octet
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ! is_in_range "$octet" 0 255; then
            return 1
        fi
    done

    return 0
}

# Check if a string is a valid IPv6 address
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is a valid IPv6 address, 1 otherwise
is_ipv6() {
    matches_pattern "$1" "$REGEX_IPV6"
    return $?
}

# Check if a string is a valid IP address (IPv4 or IPv6)
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is a valid IP address, 1 otherwise
is_ip_address() {
    is_ipv4 "$1" || is_ipv6 "$1"
    return $?
}

# Check if a string is a valid hostname
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is a valid hostname, 1 otherwise
is_hostname() {
    local hostname="$1"

    # Check basic pattern
    if ! matches_pattern "$hostname" "$REGEX_HOSTNAME"; then
        return 1
    fi

    # Additional checks: hostname length should be ≤ 253 characters
    if (( ${#hostname} > 253 )); then
        return 1
    fi

    return 0
}

# Check if a string is a valid email address
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is a valid email address, 1 otherwise
is_email() {
    matches_pattern "$1" "$REGEX_EMAIL"
    return $?
}

# Check if a string is a valid UUID/GUID
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is a valid UUID, 1 otherwise
is_uuid() {
    matches_pattern "$1" "$REGEX_UUID"
    return $?
}

# ===== Security-Focused Validation Functions =====

# Check if a path contains directory traversal attempts
# Arguments:
#   $1 - Path to check
# Returns:
#   0 if the path is safe, 1 if it contains directory traversal
has_dir_traversal() {
    local path="$1"

    if is_empty "$path"; then
        log_debug "Empty path provided to has_dir_traversal"
        return 1
    fi

    if matches_pattern "$path" "$REGEX_PATH_TRAVERSAL"; then
        log_debug "Path contains directory traversal sequences: $path"
        return 1
    fi

    return 0
}

# Check if a string contains potential command injection characters
# Arguments:
#   $1 - String to check
# Returns:
#   0 if the string is safe, 1 if it contains command injection patterns
has_command_injection() {
    local input="$1"

    if is_empty "$input"; then
        log_debug "Empty input provided to has_command_injection"
        return 1
    fi

    if matches_pattern "$input" "$REGEX_COMMAND_INJECTION"; then
        log_debug "Input contains potential command injection patterns: $input"
        return 1
    fi

    return 0
}

# Validate that a file exists and has required permissions
# Arguments:
#   $1 - File path
#   $2 - Required permissions (r, w, x, or combination)
# Returns:
#   0 if the file exists with required permissions, 1 otherwise
validate_file() {
    local file_path="$1"
    local required_perms="${2:-r}"

    # Check for path safety
    if ! has_dir_traversal "$file_path"; then
        log_error "Path failed safety check: $file_path"
        return 1
    fi

    # Check file existence
    if [[ ! -f "$file_path" ]]; then
        log_debug "File does not exist: $file_path"
        return 1
    fi

    # Check permissions
    if [[ "$required_perms" == *"r"* && ! -r "$file_path" ]]; then
        log_debug "File is not readable: $file_path"
        return 1
    fi

    if [[ "$required_perms" == *"w"* && ! -w "$file_path" ]]; then
        log_debug "File is not writable: $file_path"
        return 1
    fi

    if [[ "$required_perms" == *"x"* && ! -x "$file_path" ]]; then
        log_debug "File is not executable: $file_path"
        return 1
    fi

    return 0
}

# Validate that a directory exists and has required permissions
# Arguments:
#   $1 - Directory path
#   $2 - Required permissions (r, w, x, or combination)
# Returns:
#   0 if the directory exists with required permissions, 1 otherwise
validate_directory() {
    local dir_path="$1"
    local required_perms="${2:-r}"

    # Check for path safety
    if ! has_dir_traversal "$dir_path"; then
        log_error "Path failed safety check: $dir_path"
        return 1
    fi

    # Check directory existence
    if [[ ! -d "$dir_path" ]]; then
        log_debug "Directory does not exist: $dir_path"
        return 1
    fi

    # Check permissions
    if [[ "$required_perms" == *"r"* && ! -r "$dir_path" ]]; then
        log_debug "Directory is not readable: $dir_path"
        return 1
    fi

    if [[ "$required_perms" == *"w"* && ! -w "$dir_path" ]]; then
        log_debug "Directory is not writable: $dir_path"
        return 1
    fi

    if [[ "$required_perms" == *"x"* && ! -x "$dir_path" ]]; then
        log_debug "Directory is not executable (searchable): $dir_path"
        return 1
    fi

    return 0
}

# Check if a file has secure permissions
# Arguments:
#   $1 - File path
#   $2 - Maximum allowed permission (octal, e.g., 600, 640)
# Returns:
#   0 if the file has secure permissions, 1 otherwise
has_secure_permissions() {
    local file_path="$1"
    local max_perms="${2:-640}" # Default to 640 (owner rw, group r, others none)

    # Check file existence
    if [[ ! -f "$file_path" ]]; then
        log_debug "File does not exist: $file_path"
        return 1
    }

    # Get file permissions in octal format
    local perms
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        perms=$(stat -f "%Lp" "$file_path")
    else
        # Linux
        perms=$(stat -c "%a" "$file_path")
    fi

    # Convert to numbers for comparison
    local actual_perms=$((10#$perms))
    local expected_max=$((10#$max_perms))

    if (( actual_perms > expected_max )); then
        log_debug "File has insecure permissions: $file_path (${perms}, should be at most ${max_perms})"
        return 1
    fi

    return 0
}

# ===== Input Sanitization Functions =====

# Sanitize a string for use in shell commands
# Arguments:
#   $1 - String to sanitize
# Returns:
#   Sanitized string, with potentially dangerous characters escaped
sanitize_shell_input() {
    local input="$1"

    if is_empty "$input"; then
        echo ""
        return
    fi

    # Replace problematic characters with escaped versions
    local sanitized="${input//\\/\\\\}"  # Escape backslashes
    sanitized="${sanitized//\"/\\\"}"    # Escape double quotes
    sanitized="${sanitized//\$/\\\$}"    # Escape dollar signs
    sanitized="${sanitized//\`/\\\`}"    # Escape backticks
    sanitized="${sanitized//\!/\\\!}"    # Escape exclamation marks

    echo "$sanitized"
}

# Sanitize a string for SQL queries (basic protection against SQL injection)
# Arguments:
#   $1 - String to sanitize
# Returns:
#   Sanitized string
sanitize_sql_input() {
    local input="$1"

    if is_empty "$input"; then
        echo ""
        return
    fi

    # Replace problematic characters
    local sanitized="${input//\\/\\\\}"   # Escape backslashes
    sanitized="${sanitized//\'/\\\'}"     # Escape single quotes
    sanitized="${sanitized//\"/\\\"}"     # Escape double quotes
    sanitized="${sanitized//;/\\;}"       # Escape semicolons

    echo "$sanitized"
}

# Sanitize HTML content to prevent XSS
# Arguments:
#   $1 - String to sanitize
# Returns:
#   Sanitized string with HTML special characters escaped
sanitize_html() {
    local input="$1"

    if is_empty "$input"; then
        echo ""
        return
    fi

    # Replace HTML special characters
    local sanitized="${input//&/&amp;}"    # Escape ampersands first to avoid double-escaping
    sanitized="${sanitized//</&lt;}"       # Escape less than
    sanitized="${sanitized//>/&gt;}"       # Escape greater than
    sanitized="${sanitized//\"/&quot;}"    # Escape double quotes
    sanitized="${sanitized//\'/&#39;}"     # Escape single quotes

    echo "$sanitized"
}

# ===== Command Line Argument Validation =====

# Validate a command line argument
# Arguments:
#   $1 - Argument name
#   $2 - Argument value
#   $3 - Validation type (required, numeric, ip, hostname, email, uuid, path, alphanumeric, etc.)
#   $4 - Validation parameters (e.g., min=1,max=100 for numeric)
# Returns:
#   0 if valid, 1 if invalid
validate_argument() {
    local arg_name="$1"
    local arg_value="$2"
    local val_type="$3"
    local val_params="$4"

    log_debug "Validating argument $arg_name of type $val_type with params $val_params"

    # Check if argument is required
    if [[ "$val_type" == "required" || "$val_type" == *"required"* ]]; then
        if is_empty "$arg_value"; then
            log_error "Required argument missing: $arg_name"
            return 1
        fi
    fi

    # Skip further validation if empty and not required
    if is_empty "$arg_value"; then
        return 0
    fi

    # Extract validation parameters
    local min max allow_float
    if [[ "$val_params" == *"min="* ]]; then
        min=$(echo "$val_params" | grep -o "min=[0-9]*" | sed 's/min=//')
    fi
    if [[ "$val_params" == *"max="* ]]; then
        max=$(echo "$val_params" | grep -o "max=[0-9]*" | sed 's/max=//')
    fi
    if [[ "$val_params" == *"float"* ]]; then
        allow_float="true"
    else
        allow_float="false"
    fi

    # Perform validation based on type
    case "$val_type" in
        numeric|number|int|integer|float)
            if ! is_number "$arg_value" "$allow_float"; then
                log_error "Argument $arg_name must be a valid number, got: $arg_value"
                return 1
            fi

            # Check range if specified
            if [[ -n "$min" && -n "$max" ]]; then
                if ! is_in_range "$arg_value" "$min" "$max" "$allow_float"; then
                    log_error "Argument $arg_name must be between $min and $max, got: $arg_value"
                    return 1
                fi
            elif [[ -n "$min" ]]; then
                if ! is_in_range "$arg_value" "$min" "999999999" "$allow_float"; then
                    log_error "Argument $arg_name must be >= $min, got: $arg_value"
                    return 1
                fi
            elif [[ -n "$max" ]]; then
                if ! is_in_range "$arg_value" "-999999999" "$max" "$allow_float"; then
                    log_error "Argument $arg_name must be <= $max, got: $arg_value"
                    return 1
                fi
            fi
            ;;
        ip|ipaddr|ipaddress)
            if ! is_ip_address "$arg_value"; then
                log_error "Argument $arg_name must be a valid IP address, got: $arg_value"
                return 1
            fi
            ;;
        ipv4)
            if ! is_ipv4 "$arg_value"; then
                log_error "Argument $arg_name must be a valid IPv4 address, got: $arg_value"
                return 1
            fi
            ;;
        ipv6)
            if ! is_ipv6 "$arg_value"; then
                log_error "Argument $arg_name must be a valid IPv6 address, got: $arg_value"
                return 1
            fi
            ;;
        hostname|domain)
            if ! is_hostname "$arg_value"; then
                log_error "Argument $arg_name must be a valid hostname, got: $arg_value"
                return 1
            fi
            ;;
        email)
            if ! is_email "$arg_value"; then
                log_error "Argument $arg_name must be a valid email address, got: $arg_value"
                return 1
            fi
            ;;
        uuid|guid)
            if ! is_uuid "$arg_value"; then
                log_error "Argument $arg_name must be a valid UUID, got: $arg_value"
                return 1
            fi
            ;;
        path)
            if ! has_dir_traversal "$arg_value"; then
                log_error "Argument $arg_name contains invalid path sequences, got: $arg_value"
                return 1
            fi
            ;;
        file)
            local perms="${val_params:-r}"
            if ! validate_file "$arg_value" "$perms"; then
                log_error "Argument $arg_name must be a valid readable file, got: $arg_value"
                return 1
            fi
            ;;
        directory|dir)
            local perms="${val_params:-r}"
            if ! validate_directory "$arg_value" "$perms"; then
                log_error "Argument $arg_name must be a valid readable directory, got: $arg_value"
                return 1
            fi
            ;;
        alphanumeric)
            if ! is_alphanumeric "$arg_value"; then
                log_error "Argument $arg_name must contain only alphanumeric characters, got: $arg_value"
                return 1
            fi
            ;;
        command)
            if ! has_command_injection "$arg_value"; then
                log_error "Argument $arg_name contains potentially unsafe command characters, got: $arg_value"
                return 1
            fi
            ;;
        *)
            log_warning "Unknown validation type: $val_type for argument: $arg_name"
            ;;
    esac

    return 0
}

# Validate environment variables
# Arguments:
#   $1 - Environment variable name
#   $2 - Validation type (required, numeric, etc.)
#   $3 - Validation parameters (e.g., min=1,max=100 for numeric)
# Returns:
#   0 if valid, 1 if invalid
validate_env_var() {
    local var_name="$1"
    local val_type="$2"
    local val_params="$3"

    # Get the value of the environment variable
    local var_value="${!var_name}"

    # Use the standard argument validation
    validate_argument "$var_name" "$var_value" "$val_type" "$val_params"
    return $?
}

# ===== Utility Functions =====

# Get the validation module version
# Arguments: None
# Returns: Version string
get_validation_version() {
    echo "$SECURITY_VALIDATION_VERSION ($SECURITY_VALIDATION_DATE)"
}

# Set validation strict mode
# Arguments:
#   $1 - Enable strict mode (true/false)
# Returns: None
set_validation_strict_mode() {
    SECURITY_VALIDATION_STRICT="$1"
    log_debug "Validation strict mode set to: $SECURITY_VALIDATION_STRICT"
}

# Set validation timeout
# Arguments:
#   $1 - Timeout in seconds
# Returns: None
set_validation_timeout() {
    if is_number "$1"; then
        SECURITY_VALIDATION_TIMEOUT="$1"
        log_debug "Validation timeout set to: $SECURITY_VALIDATION_TIMEOUT seconds"
    else
        log_error "Invalid timeout value: $1 (must be a number)"
    fi
}

# ===== Export public functions =====
log_debug "Initializing validation utility (version $SECURITY_VALIDATION_VERSION)"

# Export basic validation functions
export -f is_empty is_not_empty is_number is_in_range
export -f has_valid_length matches_pattern is_alphanumeric is_alphanumeric_extended

# Export network/addressing validation functions
export -f is_ipv4 is_ipv6 is_ip_address is_hostname is_email is_uuid

# Export security validation functions
export -f has_dir_traversal has_command_injection validate_file validate_directory has_secure_permissions

# Export sanitization functions
export -f sanitize_shell_input sanitize_sql_input sanitize_html

# Export argument validation functions
export -f validate_argument validate_env_var

# Export utility functions
export -f get_validation_version set_validation_strict_mode set_validation_timeout
