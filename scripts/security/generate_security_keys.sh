#!/bin/bash
# filepath: scripts/security/generate_security_keys.sh
# Generate Security Keys Script for Cloud Infrastructure Platform
#
# Generates various cryptographic keys needed for secure application operations
# including session keys, JWT tokens, encryption keys, and more.
# Keys are output in formats suitable for environment files or configuration.

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEFAULT_OUTPUT_FORMAT="env"
OUTPUT_FILE=""
KEY_COUNT=6
VERBOSE=false
VALIDATE=true

# --- Logging Functions ---
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local level="${2:-INFO}"
    echo "[$timestamp] [$level] $1" >&2
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        log "$1" "DEBUG"
    fi
}

log_error() {
    log "$1" "ERROR"
}

# --- Helper Functions ---
usage() {
    cat <<EOF
Generate Security Keys Script for Cloud Infrastructure Platform

Usage: $0 [options]

Options:
  --output FILE, -o FILE     Write keys to a file instead of stdout
  --format FORMAT, -f FORMAT Output format: env (default), json, or yaml
  --key-types TYPES          Types of keys to generate (comma-separated)
                             Available types: all, session, jwt, encryption, api,
                             cookie, iv (default: all)
  --count N, -c N            Number of each key type to generate (default: 1)
  --validate, -v             Validate keys against security requirements
  --no-validate              Skip key validation
  --verbose                  Enable verbose logging
  --help, -h                 Display this help message

Examples:
  # Generate all keys in env format to stdout
  $0

  # Generate keys in JSON format
  $0 --format json

  # Output keys to a secure file
  $0 --output /etc/cloud-platform/secrets/app_keys.env

  # Generate only JWT and API keys in YAML format
  $0 --format yaml --key-types jwt,api

  # Generate 3 sets of each key type
  $0 --count 3
EOF
    exit 0
}

# Check if command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Generate a strong random hex string
# Args: $1 - length in bytes
generate_hex() {
    local length=${1:-32}
    if command_exists openssl; then
        openssl rand -hex "$length"
    else
        # Fallback to /dev/urandom if openssl not available
        head -c "$length" /dev/urandom | xxd -p | tr -d '\n'
    fi
}

# Generate a URL-safe base64 string
# Args: $1 - length in bytes
generate_urlsafe() {
    local length=${1:-32}
    if command_exists openssl; then
        openssl rand -base64 "$length" | tr '+/' '-_' | tr -d '='
    else
        # Fallback to /dev/urandom if openssl not available
        head -c "$length" /dev/urandom | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=' | head -c $((length * 4 / 3))
    fi
}

# Generate a base64-encoded string
# Args: $1 - length in bytes
generate_base64() {
    local length=${1:-32}
    if command_exists openssl; then
        openssl rand -base64 "$length"
    else
        # Fallback to /dev/urandom if openssl not available
        head -c "$length" /dev/urandom | base64 | tr -d '\n'
    fi
}

# Validate key strength against security requirements
# Args: $1 - key name, $2 - key value
validate_key() {
    local key_name="$1"
    local key_value="$2"
    local min_length=32

    # Different requirements for different key types
    case "$key_name" in
        *SECRET_KEY*|*JWT_SECRET*)
            min_length=32
            ;;
        *API_KEY*)
            min_length=32
            ;;
        *COOKIE*)
            min_length=24
            ;;
        *ENCRYPTION*)
            min_length=32
            ;;
        *)
            min_length=16
            ;;
    esac

    # Check key length
    if [[ ${#key_value} -lt $min_length ]]; then
        log_error "Key $key_name does not meet minimum length requirement"
        return 1
    fi

    return 0
}

# Generate keys in environment variable format
generate_env_format() {
    local keys_array=("$@")

    for ((i=0; i<${#keys_array[@]}; i+=2)); do
        local key="${keys_array[i]}"
        local value="${keys_array[i+1]}"
        echo "$key=$value"
    done
}

# Generate keys in JSON format
generate_json_format() {
    local keys_array=("$@")
    local first=true

    echo "{"

    for ((i=0; i<${#keys_array[@]}; i+=2)); do
        local key="${keys_array[i]}"
        local value="${keys_array[i+1]}"

        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi

        printf '  "%s": "%s"' "$key" "$value"
    done

    echo ""
    echo "}"
}

# Generate keys in YAML format
generate_yaml_format() {
    local keys_array=("$@")

    for ((i=0; i<${#keys_array[@]}; i+=2)); do
        local key="${keys_array[i]}"
        local value="${keys_array[i+1]}"
        echo "$key: '$value'"
    done
}

# Generate all security keys
generate_security_keys() {
    local count=${1:-1}
    local key_types=${2:-"all"}
    local keys=()

    log_debug "Generating $count set(s) of keys with types: $key_types"

    IFS=',' read -ra types_array <<< "$key_types"
    generate_all=false

    # Check if "all" is in the types list
    for type in "${types_array[@]}"; do
        if [[ "$type" == "all" ]]; then
            generate_all=true
            break
        fi
    done

    for ((i=1; i<=$count; i++)); do
        # Define keys to generate
        if [[ "$generate_all" == "true" ]] || [[ "$key_types" == *"session"* ]]; then
            local key_name="SECRET_KEY"
            [[ $count -gt 1 ]] && key_name="${key_name}_${i}"
            local key_value=$(generate_hex 32)
            keys+=("$key_name" "$key_value")
            log_debug "Generated $key_name"
        fi

        if [[ "$generate_all" == "true" ]] || [[ "$key_types" == *"jwt"* ]]; then
            local key_name="JWT_SECRET_KEY"
            [[ $count -gt 1 ]] && key_name="${key_name}_${i}"
            local key_value=$(generate_hex 32)
            keys+=("$key_name" "$key_value")
            log_debug "Generated $key_name"
        fi

        if [[ "$generate_all" == "true" ]] || [[ "$key_types" == *"encryption"* ]]; then
            local key_name="ENCRYPTION_KEY"
            [[ $count -gt 1 ]] && key_name="${key_name}_${i}"
            local key_value=$(generate_base64 32)
            keys+=("$key_name" "$key_value")
            log_debug "Generated $key_name"
        fi

        if [[ "$generate_all" == "true" ]] || [[ "$key_types" == *"api"* ]]; then
            local key_name="API_KEY"
            [[ $count -gt 1 ]] && key_name="${key_name}_${i}"
            local key_value=$(generate_urlsafe 32)
            keys+=("$key_name" "$key_value")
            log_debug "Generated $key_name"
        fi

        if [[ "$generate_all" == "true" ]] || [[ "$key_types" == *"cookie"* ]]; then
            local key_name="COOKIE_SECRET"
            [[ $count -gt 1 ]] && key_name="${key_name}_${i}"
            local key_value=$(generate_hex 24)
            keys+=("$key_name" "$key_value")
            log_debug "Generated $key_name"
        fi

        if [[ "$generate_all" == "true" ]] || [[ "$key_types" == *"iv"* ]]; then
            local key_name="ENCRYPTION_IV"
            [[ $count -gt 1 ]] && key_name="${key_name}_${i}"
            local key_value=$(generate_base64 16)
            keys+=("$key_name" "$key_value")
            log_debug "Generated $key_name"
        fi
    done

    # Validate keys if requested
    if [[ "$VALIDATE" == "true" ]]; then
        log_debug "Validating generated keys"
        for ((i=0; i<${#keys[@]}; i+=2)); do
            local key="${keys[i]}"
            local value="${keys[i+1]}"
            if ! validate_key "$key" "$value"; then
                log_error "Key validation failed: $key"
                return 1
            fi
        done
    fi

    # Output keys in requested format
    case "$OUTPUT_FORMAT" in
        json)
            generate_json_format "${keys[@]}"
            ;;
        yaml)
            generate_yaml_format "${keys[@]}"
            ;;
        *)
            generate_env_format "${keys[@]}"
            ;;
    esac
}

# --- Argument Parsing ---
OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
KEY_TYPES="all"

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -f|--format)
            case "$2" in
                env|json|yaml)
                    OUTPUT_FORMAT="$2"
                    ;;
                *)
                    log_error "Invalid format: $2. Use env, json, or yaml."
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --key-types)
            KEY_TYPES="$2"
            shift 2
            ;;
        -c|--count)
            if [[ "$2" =~ ^[0-9]+$ && "$2" -gt 0 ]]; then
                KEY_COUNT="$2"
            else
                log_error "Invalid count: $2. Must be a positive integer."
                exit 1
            fi
            shift 2
            ;;
        --validate|-v)
            VALIDATE=true
            shift
            ;;
        --no-validate)
            VALIDATE=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Main Execution ---
main() {
    # Check for required dependencies
    local missing_deps=()
    if ! command_exists openssl; then
        missing_deps+=("openssl")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "WARNING: Some tools are missing (${missing_deps[*]}). Falling back to less secure alternatives." "WARN"
    fi

    # Generate keys
    local output
    if ! output=$(generate_security_keys "$KEY_COUNT" "$KEY_TYPES"); then
        log_error "Failed to generate security keys"
        exit 1
    fi

    # Write output to file or stdout
    if [[ -n "$OUTPUT_FILE" ]]; then
        # Create parent directories if needed
        mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true

        # Write with restrictive permissions
        if echo "$output" > "$OUTPUT_FILE"; then
            chmod 600 "$OUTPUT_FILE"
            log "Security keys written to $OUTPUT_FILE with restricted permissions"
        else
            log_error "Failed to write keys to $OUTPUT_FILE"
            exit 1
        fi
    else
        # Write to stdout
        echo "$output"
    fi

    exit 0
}

main "$@"
