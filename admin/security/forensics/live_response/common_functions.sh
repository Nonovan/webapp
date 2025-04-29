#!/bin/bash
# Common utility functions for Live Response Forensic Tools
# Provides shared functionality for logging, hashing, error handling,
# and evidence management used by live response scripts.

# Version tracking
LIVE_RESPONSE_COMMON_VERSION="1.0.0"
LIVE_RESPONSE_COMMON_DATE="2024-07-31"

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error when substituting.
# Prevent errors in a pipeline from being masked.
set -euo pipefail

# --- Configuration (Defaults, can be overridden by sourcing script or env vars) ---
DEFAULT_LOG_LEVEL="INFO" # Supported: DEBUG, INFO, WARN, ERROR, AUDIT
DEFAULT_HASH_ALGO="sha256" # Default algorithm for hashing evidence
DEFAULT_TIMESTAMP_FORMAT="+%Y-%m-%d %H:%M:%S %Z" # ISO 8601 like format with timezone
DEFAULT_OUTPUT_DIR="/tmp/live_response_output_$$" # Default temporary output directory
DEFAULT_EVIDENCE_PERMS="600" # Permissions for evidence files
DEFAULT_DIR_PERMS="700"      # Permissions for output directories

# --- Global Variables (Set by calling scripts if needed) ---
LOG_FILE="" # Path to the main log file for the collection
AUDIT_LOG_FILE="" # Path to the chain of custody/audit log file
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR" # Base directory for collected evidence
VERBOSE=false
QUIET=false

# --- Logging Functions ---

# Internal log function
# Arguments:
#   $1: Log Level (DEBUG, INFO, WARN, ERROR, AUDIT)
#   $2: Message
_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "$DEFAULT_TIMESTAMP_FORMAT")

    # Check log level (simple comparison)
    case "$DEFAULT_LOG_LEVEL" in
        DEBUG) ;; # Log everything
        INFO) [[ "$level" == "DEBUG" ]] && return ;;
        WARN) [[ "$level" == "DEBUG" || "$level" == "INFO" ]] && return ;;
        ERROR) [[ "$level" != "ERROR" && "$level" != "AUDIT" ]] && return ;;
        AUDIT) [[ "$level" != "AUDIT" ]] && return ;;
        *) ;; # Default to INFO level behavior if unknown
    esac

    local log_entry="[$timestamp] [$level] $message"

    # Echo to stderr if not quiet and level is WARN or ERROR
    if [[ "$QUIET" != "true" ]]; then
        if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then
            echo "$log_entry" >&2
        elif [[ "$VERBOSE" == "true" && "$level" != "AUDIT" ]]; then
             echo "$log_entry" >&2
        fi
    fi

    # Write to main log file if defined
    if [[ -n "$LOG_FILE" ]]; then
        echo "$log_entry" >> "$LOG_FILE"
    fi

    # Write AUDIT messages to audit log file if defined
    if [[ "$level" == "AUDIT" && -n "$AUDIT_LOG_FILE" ]]; then
        echo "$log_entry" >> "$AUDIT_LOG_FILE"
    fi
}

log_info() { _log "INFO" "$1"; }
log_warn() { _log "WARN" "$1"; }
log_error() { _log "ERROR" "$1"; }
log_debug() { [[ "$VERBOSE" == "true" ]] && _log "DEBUG" "$1"; }
log_audit() { _log "AUDIT" "$1"; } # For chain of custody and critical actions

# --- Error Handling ---

# Log an error message and exit
# Arguments:
#   $1: Error message
#   $2: Exit code (optional, default: 1)
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    log_error "FATAL: $message"
    exit "$exit_code"
}

# --- Timestamp Functions ---

# Get current timestamp in the default format
# Arguments: None
# Returns: Timestamp string
get_timestamp() {
    date "$DEFAULT_TIMESTAMP_FORMAT"
}

# --- Hashing Functions ---

# Calculate hash of a file using the specified algorithm
# Arguments:
#   $1: File path
#   $2: Algorithm (optional, default: DEFAULT_HASH_ALGO)
# Returns: Hash string or empty string on failure
calculate_hash() {
    local file_path="$1"
    local algo="${2:-$DEFAULT_HASH_ALGO}"
    local hash_cmd=""
    local hash_output=""

    if [[ ! -f "$file_path" ]]; then
        log_warn "File not found for hashing: $file_path"
        return 1
    fi

    case "$algo" in
        md5) hash_cmd="md5sum" ;;
        sha1) hash_cmd="sha1sum" ;;
        sha256) hash_cmd="sha256sum" ;;
        sha512) hash_cmd="sha512sum" ;;
        *)
            log_warn "Unsupported hash algorithm: $algo. Using $DEFAULT_HASH_ALGO."
            algo="$DEFAULT_HASH_ALGO"
            calculate_hash "$file_path" "$algo" # Recurse with default
            return $?
            ;;
    esac

    if ! command -v "$hash_cmd" &>/dev/null; then
        log_warn "Hashing tool not found: $hash_cmd"
        return 1
    fi

    # Calculate hash and extract only the hash value
    hash_output=$("$hash_cmd" "$file_path" 2>/dev/null | awk '{print $1}')
    if [[ -n "$hash_output" ]]; then
        echo "$hash_output"
        return 0
    else
        log_warn "Failed to calculate $algo hash for $file_path"
        return 1
    fi
}

# Verify the hash of a file against an expected value
# Arguments:
#   $1: File path
#   $2: Expected hash value
#   $3: Algorithm (optional, default: DEFAULT_HASH_ALGO)
# Returns: 0 if hash matches, 1 otherwise
verify_hash() {
    local file_path="$1"
    local expected_hash="$2"
    local algo="${3:-$DEFAULT_HASH_ALGO}"
    local calculated_hash

    log_debug "Verifying $algo hash for file: $file_path"
    calculated_hash=$(calculate_hash "$file_path" "$algo")

    if [[ $? -ne 0 ]]; then
        log_warn "Could not calculate hash for verification: $file_path"
        return 1
    fi

    if [[ "$calculated_hash" == "$expected_hash" ]]; then
        log_debug "Hash verification successful for $file_path"
        return 0
    else
        log_warn "Hash mismatch for $file_path. Expected: $expected_hash, Calculated: $calculated_hash"
        return 1
    fi
}

# --- File and Directory Operations ---

# Create output directory if it doesn't exist, with secure permissions
# Arguments:
#   $1: Directory path
# Returns: 0 on success, 1 on failure
ensure_output_dir() {
    local dir_path="$1"
    if [[ -z "$dir_path" ]]; then
        log_warn "No directory path provided to ensure_output_dir"
        return 1
    fi

    if [[ ! -d "$dir_path" ]]; then
        log_debug "Creating directory: $dir_path"
        mkdir -p "$dir_path" || {
            log_error "Failed to create directory: $dir_path"
            return 1
        }
        chmod "$DEFAULT_DIR_PERMS" "$dir_path" || log_warn "Failed to set permissions on $dir_path"
        log_audit "Created output directory: $dir_path"
    fi
    return 0
}

# Securely write content to a file, setting permissions
# Arguments:
#   $1: File path
#   $2: Content to write (can be piped in)
# Returns: 0 on success, 1 on failure
secure_write_file() {
    local file_path="$1"
    local parent_dir
    parent_dir=$(dirname "$file_path")

    ensure_output_dir "$parent_dir" || return 1

    log_debug "Writing content to file: $file_path"
    # Use cat to handle piped input or direct argument
    if [[ -t 0 ]]; then # Check if stdin is a terminal (no pipe)
        if [[ $# -lt 2 ]]; then
             log_warn "secure_write_file requires content as second argument or via pipe"
             return 1
        fi
        echo "$2" > "$file_path"
    else
        cat > "$file_path" # Read from stdin (pipe)
    fi

    if [[ $? -eq 0 ]]; then
        chmod "$DEFAULT_EVIDENCE_PERMS" "$file_path" || log_warn "Failed to set permissions on $file_path"
        log_audit "Wrote content to file: $file_path"
        return 0
    else
        log_error "Failed to write to file: $file_path"
        return 1
    fi
}

# --- Dependency Checking ---

# Check if a required tool exists
# Arguments:
#   $1: Tool name (e.g., "lsof", "tcpdump")
#   $2: Tool path (optional, from config)
# Returns: 0 if found, 1 if not found
check_tool_dependency() {
    local tool_name="$1"
    local tool_path="${2:-}"

    # Try configured path first
    if [[ -n "$tool_path" ]]; then
        if [[ -x "$tool_path" ]]; then
            log_debug "Tool '$tool_name' found at configured path: $tool_path"
            return 0
        else
            log_debug "Tool '$tool_name' not found at configured path: $tool_path. Checking PATH."
        fi
    fi

    # Fallback to checking PATH
    if command -v "$tool_name" &>/dev/null; then
        log_debug "Tool '$tool_name' found in PATH: $(command -v "$tool_name")"
        return 0
    else
        log_warn "Required tool not found: $tool_name"
        return 1
    fi
}

# --- Chain of Custody Logging ---

# Log an event related to evidence handling
# Arguments:
#   $1: Action performed (e.g., "Collected", "Hashed", "Copied")
#   $2: Evidence item description (e.g., "Memory dump", "/dev/sda")
#   $3: Details (optional, e.g., "SHA256: <hash>", "To: /evidence/case1")
log_coc_event() {
    local action="$1"
    local item="$2"
    local details="${3:-}"
    local user
    user=$(whoami)
    local hostname
    hostname=$(hostname)

    local message="CoC: Action='$action', Item='$item', User='$user@$hostname'"
    if [[ -n "$details" ]]; then
        message+=", Details='$details'"
    fi
    log_audit "$message"
}

# --- Initialization ---

# Function to initialize common settings, log files etc.
# Arguments:
#   $1: Main log file path (optional)
#   $2: Audit log file path (optional)
#   $3: Base output directory (optional)
init_common_functions() {
    LOG_FILE="${1:-$LOG_FILE}"
    AUDIT_LOG_FILE="${2:-$AUDIT_LOG_FILE}"
    OUTPUT_DIR="${3:-$OUTPUT_DIR}"

    # Ensure log directories exist if paths are set
    if [[ -n "$LOG_FILE" ]]; then
        ensure_output_dir "$(dirname "$LOG_FILE")" || error_exit "Cannot create log directory for $LOG_FILE"
        # Set permissions on log file if it exists or gets created
        touch "$LOG_FILE" && chmod "$DEFAULT_EVIDENCE_PERMS" "$LOG_FILE" || log_warn "Could not set permissions on $LOG_FILE"
    fi
    if [[ -n "$AUDIT_LOG_FILE" ]]; then
         ensure_output_dir "$(dirname "$AUDIT_LOG_FILE")" || error_exit "Cannot create audit log directory for $AUDIT_LOG_FILE"
         touch "$AUDIT_LOG_FILE" && chmod "$DEFAULT_EVIDENCE_PERMS" "$AUDIT_LOG_FILE" || log_warn "Could not set permissions on $AUDIT_LOG_FILE"
    fi

    # Ensure base output directory exists
    ensure_output_dir "$OUTPUT_DIR" || error_exit "Cannot create base output directory: $OUTPUT_DIR"

    log_info "Common functions initialized. Version: $LIVE_RESPONSE_COMMON_VERSION ($LIVE_RESPONSE_COMMON_DATE)"
    log_debug "Log File: ${LOG_FILE:-Not Set}"
    log_debug "Audit Log File: ${AUDIT_LOG_FILE:-Not Set}"
    log_debug "Output Directory: $OUTPUT_DIR"
    log_debug "Log Level: $DEFAULT_LOG_LEVEL"
}

# --- Version Info ---
get_common_live_response_version() {
    echo "${LIVE_RESPONSE_COMMON_VERSION} (${LIVE_RESPONSE_COMMON_DATE})"
}

# --- End of Functions ---
log_debug "common_functions.sh sourced successfully."
