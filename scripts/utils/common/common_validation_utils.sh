#!/bin/bash
# filepath: scripts/utils/common/common_validation_utils.sh
#######################################
# VALIDATION FUNCTIONS
#######################################

# Version tracking
VALIDATION_UTILS_VERSION="1.0.0"
VALIDATION_UTILS_DATE="2024-07-30"

# Get version information for these utilities
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_validation_utils_version() {
    echo "${VALIDATION_UTILS_VERSION} (${VALIDATION_UTILS_DATE})"
}

# Check if required functions are available
for func in debug warn log error_exit; do
    if ! type -t "$func" &>/dev/null; then
        echo "Required function $func not available. Make sure to source common_core_utils.sh first." >&2
        exit 1
    fi
done

# Define validation constants
DEFAULT_VALIDATION_TIMEOUT=5    # Default timeout in seconds for validation operations
VALIDATION_EMPTY_STRING=""      # Constant for empty string validation

# Define secure permission constants for validation
DEFAULT_CONFIG_FILE_PERMS="644" # Default permissions for configuration files
DEFAULT_SECRET_FILE_PERMS="600" # Restrictive permissions for files with secrets
DEFAULT_SCRIPT_FILE_PERMS="755" # Default permissions for executable scripts
DEFAULT_KEY_FILE_PERMS="600"    # Restrictive permissions for key files
DEFAULT_CERT_FILE_PERMS="644"   # Default permissions for certificate files
DEFAULT_FILE_PERMS="644"        # Default file permissions if not otherwise specified

# Check if a command exists
# Arguments:
#   $1 - Command to check
#   $2 - Suggest installation command (optional)
# Returns:
#   0 if exists, 1 if not
command_exists() {
    local cmd="$1"
    local install_suggestion="${2:-}"

    command -v "$cmd" &>/dev/null
    local result=$?

    if [[ $result -ne 0 ]]; then
        if [[ -n "$install_suggestion" ]]; then
            debug "Command not found: $cmd. Try installing with: $install_suggestion"
        else
            debug "Command not found: $cmd"
        fi
    fi

    return $result
}

# Check if a file exists and is readable with proper permission validation
# Arguments:
#   $1 - File path
#   $2 - Error message (optional)
#   $3 - Expected permissions (optional - only warns if permissions exceed this)
#   $4 - File type (optional - for more specific permission checks and reporting)
# Returns:
#   0 if exists with proper permissions, 1 if not
file_exists() {
    local file="$1"
    local error_msg="${2:-File does not exist or is not readable: $file}"
    local expected_perms="${3:-}"
    local file_type="${4:-general}"

    # Validate input
    if [[ -z "$file" ]]; then
        log "No file path provided to file_exists" "ERROR"
        return 1
    fi

    # Check for directory traversal attempts
    if [[ "$file" == *".."* ]]; then
        log "Potential directory traversal in path: $file" "ERROR"
        return 1
    fi

    # Determine expected permissions based on file type if not explicitly provided
    if [[ -z "$expected_perms" ]]; then
        case "$file_type" in
            config)
                expected_perms="$DEFAULT_CONFIG_FILE_PERMS"
                ;;
            secret|key|password)
                expected_perms="$DEFAULT_SECRET_FILE_PERMS"
                ;;
            script|executable)
                expected_perms="$DEFAULT_SCRIPT_FILE_PERMS"
                ;;
            cert|certificate)
                expected_perms="$DEFAULT_CERT_FILE_PERMS"
                ;;
            *)
                expected_perms="$DEFAULT_FILE_PERMS"
                ;;
        esac
    fi

    if [[ ! -e "$file" ]]; then
        log "$error_msg" "ERROR"
        return 1
    fi

    if [[ ! -r "$file" ]]; then
        log "File exists but is not readable: $file" "ERROR"
        return 1
    fi

    # Check permissions
    local file_perms=""

    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_perms=$(stat -f '%A' "$file" 2>/dev/null)
        else
            # Linux version
            file_perms=$(stat -c '%a' "$file" 2>/dev/null)
        fi

        # Convert to octal number for comparison
        if [[ -n "$file_perms" ]]; then
            local numeric_file_perms=$((10#$file_perms))
            local numeric_expected_perms=$((10#$expected_perms))

            # Check for overly permissive files
            if (( numeric_file_perms > numeric_expected_perms )); then
                local recommendation=""

                # Give specific security recommendations based on file type
                case "$file_type" in
                    secret|key|password)
                        recommendation=" This file may contain sensitive information and should be restricted to owner access only."
                        ;;
                    config)
                        recommendation=" Configuration files should have appropriate permissions to prevent unauthorized modifications."
                        ;;
                    cert|certificate)
                        recommendation=" Certificate files should be readable but not writable by others."
                        ;;
                esac

                warn "File has overly permissive permissions: $file (current: $file_perms, recommended: $expected_perms or less).${recommendation}"
                warn "Suggested fix: chmod $expected_perms $file"

                # For sensitive files, return error instead of just warning
                if [[ "$file_type" == "secret" || "$file_type" == "key" || "$file_type" == "password" ]]; then
                    log "Security risk: $file has insecure permissions" "ERROR"
                    return 1
                fi
                # Continue despite warning for non-sensitive files
            fi
        fi
    fi

    return 0
}

# Validate file permissions and fix if requested
# Arguments:
#   $1 - File path
#   $2 - Expected permissions
#   $3 - Fix permissions if incorrect (true/false, defaults to false)
#   $4 - File type (optional - for more specific error messages)
# Returns:
#   0 if permissions are correct or fixed, 1 if incorrect and not fixed
validate_file_permissions() {
    local file="$1"
    local expected_perms="${2:-}"
    local fix_permissions="${3:-false}"
    local file_type="${4:-general}"

    # Validate input
    if [[ -z "$file" ]]; then
        log "No file path provided to validate_file_permissions" "ERROR"
        return 1
    fi

    # Check for directory traversal attempts
    if [[ "$file" == *".."* ]]; then
        log "Potential directory traversal in path: $file" "ERROR"
        return 1
    fi

    # Set default expected permissions based on file type if not provided
    if [[ -z "$expected_perms" ]]; then
        case "$file_type" in
            config)
                expected_perms="$DEFAULT_CONFIG_FILE_PERMS"
                ;;
            secret|key|password)
                expected_perms="$DEFAULT_SECRET_FILE_PERMS"
                ;;
            script|executable)
                expected_perms="$DEFAULT_SCRIPT_FILE_PERMS"
                ;;
            cert|certificate)
                expected_perms="$DEFAULT_CERT_FILE_PERMS"
                ;;
            *)
                expected_perms="$DEFAULT_FILE_PERMS"
                ;;
        esac
    fi

    if [[ ! -e "$file" ]]; then
        log "Cannot validate permissions for non-existent file: $file" "ERROR"
        return 1
    fi

    local file_perms=""
    local permissions_match=false

    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_perms=$(stat -f '%A' "$file" 2>/dev/null)
        else
            # Linux version
            file_perms=$(stat -c '%a' "$file" 2>/dev/null)
        fi

        if [[ -n "$file_perms" && "$file_perms" == "$expected_perms" ]]; then
            permissions_match=true
        fi
    else
        # If stat is not available, try to use ls
        local ls_output=$(ls -la "$file" 2>/dev/null)
        # This is a simplified approach and may not be accurate
        if [[ "$ls_output" == *"$expected_perms"* ]]; then
            permissions_match=true
        fi
    fi

    if [[ "$permissions_match" == "true" ]]; then
        debug "File permissions match expected value ($expected_perms) for: $file"
        return 0
    elif [[ "$fix_permissions" == "true" ]]; then
        debug "Fixing permissions for $file from $file_perms to $expected_perms"
        if ! chmod "$expected_perms" "$file" 2>/dev/null; then
            log "Failed to set permissions $expected_perms on file: $file" "ERROR"
            return 1
        fi
        log "Fixed permissions for $file (from $file_perms to $expected_perms)" "INFO"
        return 0
    else
        if [[ "$file_type" == "secret" || "$file_type" == "key" || "$file_type" == "password" ]]; then
            log "Security risk: File $file has incorrect permissions ($file_perms, should be $expected_perms)" "ERROR"
        else
            warn "File $file has incorrect permissions: $file_perms (expected: $expected_perms)"
        fi
        return 1
    fi
}

# Safely validate if a file with sensitive data is secure
# Arguments:
#   $1 - File path
#   $2 - Fix permissions if incorrect (true/false, defaults to false)
# Returns:
#   0 if file is secure, 1 if not
validate_sensitive_file() {
    local file="$1"
    local fix_permissions="${2:-false}"

    # Validate input
    if [[ -z "$file" ]]; then
        log "No file path provided to validate_sensitive_file" "ERROR"
        return 1
    fi

    # Check for directory traversal attempts
    if [[ "$file" == *".."* ]]; then
        log "Potential directory traversal in path: $file" "ERROR"
        return 1
    }

    # Check if file exists and is readable
    if [[ ! -f "$file" ]]; then
        log "Sensitive file does not exist: $file" "ERROR"
        return 1
    fi

    if [[ ! -r "$file" ]]; then
        log "Sensitive file exists but is not readable: $file" "ERROR"
        return 1
    fi

    # Validate owner-only permissions
    if ! validate_file_permissions "$file" "$DEFAULT_SECRET_FILE_PERMS" "$fix_permissions" "secret"; then
        return 1
    fi

    # Check if file is world-readable
    local world_readable=false
    local file_perms

    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_perms=$(stat -f '%A' "$file" 2>/dev/null)
            # Check last digit of octal permissions
            if [[ -n "$file_perms" && "${file_perms: -1}" != "0" ]]; then
                world_readable=true
            fi
        else
            # Linux version
            file_perms=$(stat -c '%a' "$file" 2>/dev/null)
            # Check last digit of octal permissions
            if [[ -n "$file_perms" && "${file_perms: -1}" != "0" ]]; then
                world_readable=true
            fi
        fi
    else
        # Fallback to basic check
        if [[ -r "$file" ]] && ls -la "$file" | grep -q -- "^-..r"; then
            world_readable=true
        fi
    fi

    if [[ "$world_readable" == "true" ]]; then
        if [[ "$fix_permissions" == "true" ]]; then
            if ! chmod "$DEFAULT_SECRET_FILE_PERMS" "$file" 2>/dev/null; then
                log "Failed to fix world-readable permissions on sensitive file: $file" "ERROR"
                return 1
            fi
            log "Fixed world-readable permissions on sensitive file: $file" "INFO"
        else
            log "Security risk: Sensitive file is world-readable: $file" "ERROR"
            return 1
        fi
    fi

    # Check if directory permissions are secure
    local dir=$(dirname "$file")
    if [[ -d "$dir" ]]; then
        local dir_perms=""
        local world_writable=false

        if command_exists stat; then
            if [[ "$(uname)" == "Darwin" ]]; then
                # macOS version
                dir_perms=$(stat -f '%A' "$dir" 2>/dev/null)
                # Check if world-writable (last digit > 4)
                if [[ -n "$dir_perms" && "${dir_perms: -1}" -gt "4" ]]; then
                    world_writable=true
                fi
            else
                # Linux version
                dir_perms=$(stat -c '%a' "$dir" 2>/dev/null)
                # Check if world-writable (last digit > 4)
                if [[ -n "$dir_perms" && "${dir_perms: -1}" -gt "4" ]]; then
                    world_writable=true
                fi
            fi
        else
            # Fallback to basic check
            if ls -ld "$dir" | grep -q -- "^d..w"; then
                world_writable=true
            fi
        fi

        # Directory should not be world-writable
        if [[ "$world_writable" == "true" ]]; then
            if [[ "$fix_permissions" == "true" ]]; then
                # Make directory not world-writable but keep other permissions
                local new_perms=""

                if [[ -n "$dir_perms" ]]; then
                    # Replace last digit with 4 (read-only) or 0 (no access)
                    new_perms=$(echo "$dir_perms" | sed 's/\(.*\)./\10/')
                    if ! chmod "$new_perms" "$dir" 2>/dev/null; then
                        warn "Failed to fix world-writable directory permissions: $dir"
                        # Continue despite warning
                    }
                    log "Fixed world-writable directory permissions for: $dir (from $dir_perms to $new_perms)" "INFO"
                else
                    # Fallback to conservative permissions
                    if ! chmod 750 "$dir" 2>/dev/null; then
                        warn "Failed to fix world-writable directory permissions: $dir"
                        # Continue despite warning
                    }
                    log "Fixed world-writable directory permissions for: $dir (to 750)" "INFO"
                fi
            else
                warn "Security risk: Directory containing sensitive file is world-writable: $dir"
                # This is a warning, not an error to return 1
            fi
        fi
    fi

    return 0
}

# Validate if a string is a valid IP address
# Arguments:
#   $1 - String to validate
#   $2 - Type (4 for IPv4, 6 for IPv6, both if not specified)
# Returns: 0 if valid, 1 if not
is_valid_ip() {
    local ip="$1"
    local type="${2:-both}"

    # Validate input
    if [[ -z "$ip" ]]; then
        debug "Empty IP address provided"
        return 1
    fi

    case "$type" in
        4|ipv4)
            # IPv4 validation
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                local IFS='.'
                read -ra ip_array <<< "$ip"

                for octet in "${ip_array[@]}"; do
                    if (( octet < 0 || octet > 255 )); then
                        debug "Invalid IPv4 address: $ip (octet out of range)"
                        return 1
                    fi
                done

                return 0
            fi
            debug "Invalid IPv4 format: $ip"
            return 1
            ;;
        6|ipv6)
            # IPv6 validation (simplified)
            if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
                return 0
            fi
            debug "Invalid IPv6 format: $ip"
            return 1
            ;;
        both)
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                return 0
            else
                debug "Invalid IP address (neither IPv4 nor IPv6): $ip"
                return 1
            fi
            ;;
        *)
            log "Invalid IP type specified: $type. Use 4, 6, or both" "ERROR"
            return 1
            ;;
    esac
}

# Check if a value is a number
# Arguments:
#   $1 - Value to check
#   $2 - Allow floating point (true/false, defaults to false)
# Returns: 0 if numeric, 1 if not
is_number() {
    local value="$1"
    local allow_float="${2:-false}"

    # Empty check
    if [[ -z "$value" ]]; then
        debug "Empty value provided to is_number"
        return 1
    fi

    if [[ "$allow_float" == "true" ]]; then
        if [[ "$value" =~ ^[+-]?[0-9]+(\.[0-9]+)?$ ]]; then
            return 0
        else
            debug "Not a valid floating point number: $value"
            return 1
        fi
    else
        if [[ "$value" =~ ^[+-]?[0-9]+$ ]]; then
            return 0
        else
            debug "Not a valid integer: $value"
            return 1
        fi
    fi
}

# Check if a value is within a numeric range
# Arguments:
#   $1 - Value to check
#   $2 - Minimum value (inclusive)
#   $3 - Maximum value (inclusive)
#   $4 - Allow floating point (true/false, defaults to false)
# Returns: 0 if in range, 1 if not or not a number
is_in_range() {
    local value="$1"
    local min="$2"
    local max="$3"
    local allow_float="${4:-false}"

    # Validate all inputs
    if [[ -z "$value" || -z "$min" || -z "$max" ]]; then
        debug "Missing parameter for is_in_range function"
        return 1
    fi

    # Check that value is a number
    if ! is_number "$value" "$allow_float"; then
        debug "Value is not a valid number: $value"
        return 1
    fi

    # Check that min and max are numbers
    if ! is_number "$min" "$allow_float" || ! is_number "$max" "$allow_float"; then
        debug "Min or max is not a valid number: min=$min, max=$max"
        return 1
    fi

    # Use bc for floating point comparison
    if [[ "$allow_float" == "true" ]]; then
        if (( $(echo "$value < $min" | bc -l) )) || (( $(echo "$value > $max" | bc -l) )); then
            debug "Value $value is outside range $min-$max"
            return 1
        fi
    else
        # Integer comparison
        if (( value < min )) || (( value > max )); then
            debug "Value $value is outside range $min-$max"
            return 1
        fi
    fi

    return 0
}

# Validate required parameters
# Arguments:
#   Variable number of parameter names to check
# Returns: 0 if all parameters exist, 1 if any are missing
validate_required_params() {
    local missing=0
    local missing_params=""

    for param in "$@"; do
        # Need to use indirect reference
        local param_value="${!param:-}"
        if [[ -z "$param_value" ]]; then
            missing=$((missing + 1))
            missing_params="$missing_params $param"
        fi
    done

    if (( missing > 0 )); then
        log "Required parameter(s) missing:$missing_params" "ERROR"
        return 1
    fi

    return 0
}

# Validate a URL format
# Arguments:
#   $1 - URL to validate
#   $2 - Require HTTPS (true/false, defaults to false)
# Returns: 0 if valid, 1 if not
is_valid_url() {
    local url="$1"
    local require_https="${2:-false}"

    if [[ -z "$url" ]]; then
        debug "Empty URL provided"
        return 1
    fi

    # Check for potentially dangerous characters indicating injection attempts
    if [[ "$url" =~ [\'\"\\<>\`$] ]]; then
        debug "URL contains potentially dangerous characters: $url"
        return 1
    fi

    # Check for HTTPS specifically if required
    if [[ "$require_https" == "true" ]]; then
        if [[ "$url" =~ ^https:// ]]; then
            return 0
        else
            debug "Invalid URL format: $url (must use HTTPS)"
            return 1
        fi
    else
        # Basic URL validation - requires http:// or https:// prefix
        if [[ "$url" =~ ^https?:// ]]; then
            return 0
        else
            debug "Invalid URL format: $url (must start with http:// or https://)"
            return 1
        fi
    fi
}

# Validate email format
# Arguments:
#   $1 - Email to validate
# Returns: 0 if valid, 1 if not
is_valid_email() {
    local email="$1"

    if [[ -z "$email" ]]; then
        debug "Empty email provided"
        return 1
    fi

    # Check for potentially dangerous characters indicating injection attempts
    if [[ "$email" =~ [\'\"\\<>\`$] ]]; then
        debug "Email contains potentially dangerous characters: $email"
        return 1
    fi

    # Basic email validation
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi

    debug "Invalid email format: $email"
    return 1
}

# Validate port number
# Arguments:
#   $1 - Port to validate
#   $2 - Allow system ports (requires root) (true/false, defaults to false)
# Returns: 0 if valid, 1 if not
is_valid_port() {
    local port="$1"
    local allow_system_ports="${2:-false}"

    # Empty check
    if [[ -z "$port" ]]; then
        debug "Empty port provided"
        return 1
    fi

    # Check if port is a number
    if ! is_number "$port"; then
        debug "Port must be a number: $port"
        return 1
    fi

    # Check port range
    if [[ "$allow_system_ports" == "true" ]]; then
        if (( port < 1 || port > 65535 )); then
            debug "Port out of range: $port (must be 1-65535)"
            return 1
        fi
    else
        # Non-privileged ports only (>1024)
        if (( port < 1024 || port > 65535 )); then
            debug "Port out of range: $port (must be 1024-65535 without root privileges)"
            return 1
        fi
    fi

    return 0
}

# Check if a string has a minimum length
# Arguments:
#   $1 - String to check
#   $2 - Minimum required length
# Returns: 0 if valid, 1 if not
has_min_length() {
    local string="$1"
    local min_length="$2"

    # Validate inputs
    if [[ -z "$min_length" ]]; then
        debug "Missing minimum length parameter"
        return 1
    fi

    if ! is_number "$min_length"; then
        debug "Minimum length must be a number: $min_length"
        return 1
    fi

    # Empty string check
    if [[ -z "$string" ]]; then
        debug "Empty string provided to has_min_length"
        return 1
    fi

    if (( ${#string} < min_length )); then
        debug "String length (${#string}) is less than minimum required ($min_length)"
        return 1
    fi

    return 0
}

# Sanitize input to prevent command injection
# Arguments:
#   $1 - Input to sanitize
# Returns: Sanitized string on stdout
sanitize_input() {
    local input="$1"

    # Remove dangerous characters
    local sanitized="${input//[;&|<>$\`\\]/_}"

    echo "$sanitized"
}

# Validate a path is safe (no directory traversal)
# Arguments:
#   $1 - Path to check
#   $2 - Base directory for relative paths (optional)
# Returns: 0 if safe, 1 if not
is_safe_path() {
    local path="$1"
    local base_dir="${2:-}"

    # Check for empty input
    if [[ -z "$path" ]]; then
        debug "Empty path provided"
        return 1
    }

    # Check for directory traversal attempts
    if [[ "$path" == *".."* || "$path" == *"~"* ]]; then
        debug "Path contains potentially unsafe components: $path"
        return 1
    fi

    # If base directory was provided, ensure path doesn't escape it
    if [[ -n "$base_dir" ]]; then
        # Convert to absolute paths for comparison
        local abs_base_dir
        local full_path

        # Get absolute path of base directory
        abs_base_dir=$(cd "$base_dir" 2>/dev/null && pwd)
        if [[ $? -ne 0 ]]; then
            debug "Invalid base directory: $base_dir"
            return 1
        fi

        # Combine and resolve the full path
        full_path="$abs_base_dir/$path"
        full_path=$(cd "$(dirname "$full_path")" 2>/dev/null && pwd)/$(basename "$full_path")
        if [[ $? -ne 0 ]]; then
            debug "Invalid path: $path"
            return 1
        fi

        # Check if the path stays within the base directory
        if [[ "$full_path" != "$abs_base_dir"/* ]]; then
            debug "Path escapes the base directory: $path"
            return 1
        fi
    fi

    return 0
}

# Export validation functions and constants
export -f command_exists
export -f file_exists
export -f validate_file_permissions
export -f validate_sensitive_file
export -f is_valid_ip
export -f is_number
export -f is_in_range
export -f validate_required_params
export -f is_valid_url
export -f is_valid_email
export -f is_valid_port
export -f has_min_length
export -f sanitize_input
export -f is_safe_path
export -f get_validation_utils_version

# Export constants
export DEFAULT_CONFIG_FILE_PERMS
export DEFAULT_SECRET_FILE_PERMS
export DEFAULT_SCRIPT_FILE_PERMS
export DEFAULT_KEY_FILE_PERMS
export DEFAULT_CERT_FILE_PERMS
export DEFAULT_FILE_PERMS
export DEFAULT_VALIDATION_TIMEOUT
export VALIDATION_EMPTY_STRING
export VALIDATION_UTILS_VERSION
export VALIDATION_UTILS_DATE
