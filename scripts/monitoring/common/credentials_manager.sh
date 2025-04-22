#!/bin/bash
# Credentials Manager for Cloud Infrastructure Platform
#
# This script provides secure handling of authentication credentials for
# monitoring scripts and other components. It handles credential retrieval,
# secure storage, temporary access, and proper security measures.
#
# Usage: source credentials_manager.sh

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
UTILS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"

# Load common utility functions
if [[ -f "$UTILS_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$UTILS_PATH"
else
    echo "ERROR: Required utility functions not found at $UTILS_PATH"
    exit 1
fi

# Default locations and settings
CREDENTIALS_DIR="${PROJECT_ROOT}/secrets"
VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com:8200}"
KEYRING_SERVICE="cloud_platform"
ENV_PREFIX="CP_"
TEMP_CREDS_DIR="/tmp/cp-credentials"
DEFAULT_CREDS_FILE="${CREDENTIALS_DIR}/credentials.json"
KUBERNETES_SERVICE_ACCOUNT="/var/run/secrets/kubernetes.io/serviceaccount"
AWS_CREDS_PATH="${HOME}/.aws/credentials"
GCP_CREDS_PATH="${HOME}/.config/gcloud"
AZURE_CREDS_PATH="${HOME}/.azure"

# Create temporary credentials directory with secure permissions
mkdir -p "$TEMP_CREDS_DIR" 2>/dev/null
chmod 700 "$TEMP_CREDS_DIR" 2>/dev/null

#######################################
# CREDENTIAL RETRIEVAL FUNCTIONS
#######################################

# Get credential from secure storage
# Uses multiple fallback mechanisms in order of security preference
# Arguments:
#   $1 - Credential key/name
#   $2 - Default value if credential not found (optional)
#   $3 - Environment to use (optional, defaults to current environment)
# Returns: Credential value or default
get_credential() {
    local cred_key="$1"
    local default_val="$2"
    local env="${3:-$(detect_environment)}"
    local cred_value=""

    debug "Retrieving credential: $cred_key for environment: $env"

    # Try to get from Vault first (most secure)
    if command_exists vault && [[ -n "$VAULT_TOKEN" || -f "$HOME/.vault-token" ]]; then
        if cred_value=$(get_vault_secret "$cred_key" "$env"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Try to get from system keyring
    if command_exists keyring && [[ -z "$cred_value" ]]; then
        if cred_value=$(get_keyring_secret "$cred_key" "$env"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Try environment variable
    local env_var="${ENV_PREFIX}${env^^}_${cred_key^^}"
    if [[ -n "${!env_var}" ]]; then
        echo "${!env_var}"
        return 0
    fi

    # Try environment-specific credentials file
    local env_creds_file="${CREDENTIALS_DIR}/${env}/credentials.json"
    if [[ -f "$env_creds_file" ]]; then
        if cred_value=$(get_json_secret "$cred_key" "$env_creds_file"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Try default credentials file
    if [[ -f "$DEFAULT_CREDS_FILE" ]]; then
        if cred_value=$(get_json_secret "$cred_key" "$DEFAULT_CREDS_FILE"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Return default value if provided
    if [[ -n "$default_val" ]]; then
        echo "$default_val"
        return 0
    fi

    warn "Credential not found: $cred_key for environment: $env"
    return 1
}

# Get credential from HashiCorp Vault
# Arguments:
#   $1 - Secret key
#   $2 - Environment (optional)
# Returns: Secret value or empty string
get_vault_secret() {
    local secret_key="$1"
    local env="${2:-$(detect_environment)}"
    local secret_path="secret/cloud-platform/$env"
    local response

    # Check if we have a valid VAULT_TOKEN or vault is authenticated
    if [[ -z "$VAULT_TOKEN" && ! -f "$HOME/.vault-token" ]]; then
        debug "No Vault token available"
        return 1
    fi

    # Try to get the secret from Vault
    response=$(VAULT_FORMAT=json vault kv get -field="$secret_key" "$secret_path" 2>/dev/null)
    if [[ $? -eq 0 && -n "$response" ]]; then
        echo "$response"
        return 0
    fi

    # Try alternative path format
    secret_path="cloud-platform/$env"
    response=$(VAULT_FORMAT=json vault kv get -field="$secret_key" "$secret_path" 2>/dev/null)
    if [[ $? -eq 0 && -n "$response" ]]; then
        echo "$response"
        return#!/bin/bash
# Credentials Manager for Cloud Infrastructure Platform
#
# This script provides secure handling of authentication credentials for
# monitoring scripts and other components. It handles credential retrieval,
# secure storage, temporary access, and proper security measures.
#
# Usage: source credentials_manager.sh

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
UTILS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"

# Load common utility functions
if [[ -f "$UTILS_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$UTILS_PATH"
else
    echo "ERROR: Required utility functions not found at $UTILS_PATH"
    exit 1
fi

# Default locations and settings
CREDENTIALS_DIR="${PROJECT_ROOT}/secrets"
VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com:8200}"
KEYRING_SERVICE="cloud_platform"
ENV_PREFIX="CP_"
TEMP_CREDS_DIR="/tmp/cp-credentials"
DEFAULT_CREDS_FILE="${CREDENTIALS_DIR}/credentials.json"
KUBERNETES_SERVICE_ACCOUNT="/var/run/secrets/kubernetes.io/serviceaccount"
AWS_CREDS_PATH="${HOME}/.aws/credentials"
GCP_CREDS_PATH="${HOME}/.config/gcloud"
AZURE_CREDS_PATH="${HOME}/.azure"

# Create temporary credentials directory with secure permissions
mkdir -p "$TEMP_CREDS_DIR" 2>/dev/null
chmod 700 "$TEMP_CREDS_DIR" 2>/dev/null

#######################################
# CREDENTIAL RETRIEVAL FUNCTIONS
#######################################

# Get credential from secure storage
# Uses multiple fallback mechanisms in order of security preference
# Arguments:
#   $1 - Credential key/name
#   $2 - Default value if credential not found (optional)
#   $3 - Environment to use (optional, defaults to current environment)
# Returns: Credential value or default
get_credential() {
    local cred_key="$1"
    local default_val="$2"
    local env="${3:-$(detect_environment)}"
    local cred_value=""

    debug "Retrieving credential: $cred_key for environment: $env"

    # Try to get from Vault first (most secure)
    if command_exists vault && [[ -n "$VAULT_TOKEN" || -f "$HOME/.vault-token" ]]; then
        if cred_value=$(get_vault_secret "$cred_key" "$env"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Try to get from system keyring
    if command_exists keyring && [[ -z "$cred_value" ]]; then
        if cred_value=$(get_keyring_secret "$cred_key" "$env"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Try environment variable
    local env_var="${ENV_PREFIX}${env^^}_${cred_key^^}"
    if [[ -n "${!env_var}" ]]; then
        echo "${!env_var}"
        return 0
    fi

    # Try environment-specific credentials file
    local env_creds_file="${CREDENTIALS_DIR}/${env}/credentials.json"
    if [[ -f "$env_creds_file" ]]; then
        if cred_value=$(get_json_secret "$cred_key" "$env_creds_file"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Try default credentials file
    if [[ -f "$DEFAULT_CREDS_FILE" ]]; then
        if cred_value=$(get_json_secret "$cred_key" "$DEFAULT_CREDS_FILE"); then
            echo "$cred_value"
            return 0
        fi
    fi

    # Return default value if provided
    if [[ -n "$default_val" ]]; then
        echo "$default_val"
        return 0
    fi

    warn "Credential not found: $cred_key for environment: $env"
    return 1
}

# Get credential from HashiCorp Vault
# Arguments:
#   $1 - Secret key
#   $2 - Environment (optional)
# Returns: Secret value or empty string
get_vault_secret() {
    local secret_key="$1"
    local env="${2:-$(detect_environment)}"
    local secret_path="secret/cloud-platform/$env"
    local response

    # Check if we have a valid VAULT_TOKEN or vault is authenticated
    if [[ -z "$VAULT_TOKEN" && ! -f "$HOME/.vault-token" ]]; then
        debug "No Vault token available"
        return 1
    fi

    # Try to get the secret from Vault
    response=$(VAULT_FORMAT=json vault kv get -field="$secret_key" "$secret_path" 2>/dev/null)
    if [[ $? -eq 0 && -n "$response" ]]; then
        echo "$response"
        return 0
    fi

    # Try alternative path format
    secret_path="cloud-platform/$env"
    response=$(VAULT_FORMAT=json vault kv get -field="$secret_key" "$secret_path" 2>/dev/null)
    if [[ $? -eq 0 && -n "$response" ]]; then
        echo "$response"
        return
