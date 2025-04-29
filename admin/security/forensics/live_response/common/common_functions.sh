#!/bin/bash
# Common utility functions for Live Response Forensic Tools
# Provides shared functionality for logging, hashing, error handling,
# and evidence management used by live response scripts.

# Version tracking
LIVE_RESPONSE_COMMON_VERSION="1.1.0"
LIVE_RESPONSE_COMMON_DATE="2024-08-02"

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
DEFAULT_COMPRESSION="zstd"   # Default compression algorithm (zstd, gzip, none)
DEFAULT_MAX_EVIDENCE_SIZE="4G" # Default maximum size for evidence files (split if larger)
DEFAULT_CONCURRENT_TASKS=2   # Default number of concurrent tasks for parallelization

# --- Global Variables (Set by calling scripts if needed) ---
LOG_FILE="" # Path to the main log file for the collection
AUDIT_LOG_FILE="" # Path to the chain of custody/audit log file
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR" # Base directory for collected evidence
VERBOSE=false
QUIET=false
CASE_ID="" # Case identifier for evidence tracking
EXAMINER_ID="" # Examiner identifier

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
        # Add colored output for better visibility
        if [[ "$level" == "ERROR" ]]; then
            echo -e "\033[1;31m$log_entry\033[0m" >&2
        elif [[ "$level" == "WARN" ]]; then
            echo -e "\033[1;33m$log_entry\033[0m" >&2
        elif [[ "$VERBOSE" == "true" && "$level" == "DEBUG" ]]; then
            echo -e "\033[0;36m$log_entry\033[0m" >&2
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
log_success() { _log "INFO" "\033[0;32m✓\033[0m $1"; } # Success indicator

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

# Trap handler for creating a clean exit
# This handler will be set by init_common_functions
cleanup_on_exit() {
    local exit_code=$?
    log_debug "Cleanup on exit triggered with code: $exit_code"

    # Cleanup temp files if any exist
    if [[ -n "${TEMP_FILES_TO_REMOVE[*]:-}" ]]; then
        log_debug "Cleaning up ${#TEMP_FILES_TO_REMOVE[@]} temporary files"
        for temp_file in "${TEMP_FILES_TO_REMOVE[@]}"; do
            if [[ -f "$temp_file" ]]; then
                rm -f "$temp_file" 2>/dev/null || log_warn "Failed to remove temporary file: $temp_file"
            fi
        done
    fi

    # Close log files with proper summary
    if [[ -n "$LOG_FILE" ]] || [[ -n "$AUDIT_LOG_FILE" ]]; then
        if [[ $exit_code -eq 0 ]]; then
            log_info "Script completed successfully"
        else
            log_warn "Script exited with code $exit_code"
        fi
    fi

    exit "$exit_code"
}

# --- Timestamp Functions ---

# Get current timestamp in the default format
# Arguments: None
# Returns: Timestamp string
get_timestamp() {
    date "$DEFAULT_TIMESTAMP_FORMAT"
}

# Get timestamp in format suitable for filenames
# Arguments: None
# Returns: Timestamp string for filenames
get_filename_timestamp() {
    date "+%Y%m%d_%H%M%S"
}

# Format elapsed time in human-readable format
# Arguments:
#   $1: Start time in seconds (from date +%s)
#   $2: End time in seconds (optional, defaults to current time)
# Returns: Formatted elapsed time string (e.g. "2m 30s")
format_elapsed_time() {
    local start_time=$1
    local end_time=${2:-$(date +%s)}
    local elapsed=$((end_time - start_time))

    local days=$((elapsed / 86400))
    local hours=$(( (elapsed % 86400) / 3600 ))
    local minutes=$(( (elapsed % 3600) / 60 ))
    local seconds=$((elapsed % 60))

    local result=""
    [[ $days -gt 0 ]] && result+="${days}d "
    [[ $hours -gt 0 ]] && result+="${hours}h "
    [[ $minutes -gt 0 ]] && result+="${minutes}m "
    [[ $seconds -gt 0 || -z "$result" ]] && result+="${seconds}s"

    echo "$result"
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
        # Fallback to OpenSSL if available
        if command -v openssl &>/dev/null; then
            log_debug "Using OpenSSL fallback for $algo hashing"
            case "$algo" in
                md5) hash_output=$(openssl md5 "$file_path" 2>/dev/null | awk '{print $NF}') ;;
                sha1) hash_output=$(openssl sha1 "$file_path" 2>/dev/null | awk '{print $NF}') ;;
                sha256) hash_output=$(openssl sha256 "$file_path" 2>/dev/null | awk '{print $NF}') ;;
                sha512) hash_output=$(openssl sha512 "$file_path" 2>/dev/null | awk '{print $NF}') ;;
            esac

            if [[ -n "$hash_output" ]]; then
                echo "$hash_output"
                return 0
            fi
        fi

        log_warn "No suitable hashing tool found for algorithm: $algo"
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

# Calculate multiple hash types for a file simultaneously
# Arguments:
#   $1: File path
#   $2: Comma-separated list of algorithms (optional, defaults to "md5,sha1,sha256")
# Returns: JSON-formatted string with hashes
calculate_multiple_hashes() {
    local file_path="$1"
    local algos="${2:-md5,sha1,sha256}"
    local result="{"
    local first=true

    if [[ ! -f "$file_path" ]]; then
        log_warn "File not found for hashing: $file_path"
        echo "{\"error\": \"File not found\"}"
        return 1
    fi

    log_debug "Calculating multiple hashes for: $file_path"

    # Process each algorithm
    IFS=',' read -ra ALGO_ARRAY <<< "$algos"
    for algo in "${ALGO_ARRAY[@]}"; do
        local hash_value
        hash_value=$(calculate_hash "$file_path" "$algo")
        local status=$?

        if [[ $first == true ]]; then
            first=false
        else
            result+=", "
        fi

        if [[ $status -eq 0 ]]; then
            result+="\"$algo\": \"$hash_value\""
        else
            result+="\"$algo\": \"ERROR\""
        fi
    done

    result+="}"
    echo "$result"
    return 0
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
        # Use temp file for atomic write
        local temp_file
        temp_file=$(mktemp)
        TEMP_FILES_TO_REMOVE+=("$temp_file")

        echo "$2" > "$temp_file" &&
        mv "$temp_file" "$file_path"
    else
        # Use temp file for atomic write from pipe
        local temp_file
        temp_file=$(mktemp)
        TEMP_FILES_TO_REMOVE+=("$temp_file")

        cat > "$temp_file" &&
        mv "$temp_file" "$file_path"
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

# Create a temporary file for evidence collection
# Arguments:
#   $1: Prefix for the temporary file (optional)
# Returns: Path to the temporary file
create_temp_file() {
    local prefix="${1:-evidence_}"
    local temp_file

    temp_file=$(mktemp "/tmp/${prefix}_XXXXXX") || {
        log_error "Failed to create temporary file"
        return 1
    }
    chmod "$DEFAULT_EVIDENCE_PERMS" "$temp_file" || log_warn "Failed to set permissions on $temp_file"

    # Add to global list for cleanup
    TEMP_FILES_TO_REMOVE+=("$temp_file")

    echo "$temp_file"
    return 0
}

# Compress evidence file using the specified algorithm
# Arguments:
#   $1: Source file path
#   $2: Output file path (optional, defaults to source + compression extension)
#   $3: Compression algorithm (optional, defaults to DEFAULT_COMPRESSION)
# Returns: 0 on success, 1 on failure, outputs compressed file path
compress_evidence_file() {
    local source_file="$1"
    local compress_algo="${3:-$DEFAULT_COMPRESSION}"
    local output_file="$2"

    if [[ ! -f "$source_file" ]]; then
        log_warn "Source file not found for compression: $source_file"
        return 1
    fi

    # Use provided output file or generate name based on algorithm
    if [[ -z "$output_file" ]]; then
        case "$compress_algo" in
            zstd) output_file="${source_file}.zst" ;;
            gzip) output_file="${source_file}.gz" ;;
            xz) output_file="${source_file}.xz" ;;
            zip) output_file="${source_file}.zip" ;;
            none)
                # No compression, just return the source file
                echo "$source_file"
                return 0
                ;;
            *)
                log_warn "Unsupported compression algorithm: $compress_algo. Using zstd."
                compress_algo="zstd"
                output_file="${source_file}.zst"
                ;;
        esac
    fi

    log_info "Compressing $source_file using $compress_algo"
    local start_time=$(date +%s)
    local status=0

    case "$compress_algo" in
        zstd)
            if command -v zstd &>/dev/null; then
                zstd -q -f "$source_file" -o "$output_file" || status=1
            else
                log_warn "zstd not found, falling back to gzip"
                if command -v gzip &>/dev/null; then
                    gzip -c "$source_file" > "$output_file" || status=1
                else
                    log_error "Neither zstd nor gzip found for compression"
                    return 1
                fi
            fi
            ;;
        gzip)
            if command -v gzip &>/dev/null; then
                gzip -c "$source_file" > "$output_file" || status=1
            else
                log_error "gzip not found for compression"
                return 1
            fi
            ;;
        xz)
            if command -v xz &>/dev/null; then
                xz -c "$source_file" > "$output_file" || status=1
            else
                log_error "xz not found for compression"
                return 1
            fi
            ;;
        zip)
            if command -v zip &>/dev/null; then
                zip -q -j "$output_file" "$source_file" || status=1
            else
                log_error "zip not found for compression"
                return 1
            fi
            ;;
    esac

    if [[ $status -eq 0 ]]; then
        local end_time=$(date +%s)
        local elapsed=$(format_elapsed_time "$start_time" "$end_time")

        # Log compression stats
        local original_size=$(stat -c %s "$source_file" 2>/dev/null || stat -f %z "$source_file")
        local compressed_size=$(stat -c %s "$output_file" 2>/dev/null || stat -f %z "$output_file")
        local ratio=$(( (original_size - compressed_size) * 100 / original_size ))

        log_success "Compression completed in $elapsed (${ratio}% reduction)"

        # Set permissions
        chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file" || log_warn "Failed to set permissions on $output_file"

        # Log hashes for chain of custody
        local hash=$(calculate_hash "$output_file")
        log_coc_event "Compressed" "$source_file" "Algorithm: $compress_algo, Output: $output_file, Hash: $hash"

        echo "$output_file"
        return 0
    else
        log_error "Failed to compress $source_file"
        return 1
    fi
}

# Split a large file into smaller chunks
# Arguments:
#   $1: Source file path
#   $2: Output directory (optional, defaults to dirname of source file)
#   $3: Chunk size with suffix (optional, e.g. "1G", defaults to DEFAULT_MAX_EVIDENCE_SIZE)
# Returns: 0 on success, 1 on failure
split_large_file() {
    local source_file="$1"
    local output_dir="${2:-$(dirname "$source_file")}"
    local chunk_size="${3:-$DEFAULT_MAX_EVIDENCE_SIZE}"

    if [[ ! -f "$source_file" ]]; then
        log_warn "Source file not found for splitting: $source_file"
        return 1
    fi

    # Ensure output directory exists
    ensure_output_dir "$output_dir" || return 1

    # Calculate base output name
    local base_name
    base_name=$(basename "$source_file")
    local output_prefix="${output_dir}/${base_name}.part-"

    log_info "Splitting $source_file into chunks of $chunk_size"
    local start_time=$(date +%s)

    # Check for split command
    if ! command -v split &>/dev/null; then
        log_error "split command not found, cannot split file"
        return 1
    fi

    # Split the file
    split --suffix-length=4 --numeric-suffixes=1 --bytes="$chunk_size" "$source_file" "$output_prefix" || {
        log_error "Failed to split file $source_file"
        return 1
    }

    local end_time=$(date +%s)
    local elapsed=$(format_elapsed_time "$start_time" "$end_time")

    # Check if any parts were created
    local part_count
    part_count=$(find "$output_dir" -name "${base_name}.part-*" | wc -l)

    if [[ $part_count -eq 0 ]]; then
        log_warn "No file parts created, possibly file is smaller than chunk size"
        return 1
    fi

    # Calculate hash for each part and create a manifest
    local manifest_file="${output_dir}/${base_name}.manifest"
    {
        echo "Original file: $source_file"
        echo "Split timestamp: $(get_timestamp)"
        echo "Chunk size: $chunk_size"
        echo "Number of parts: $part_count"
        echo "Original hash (${DEFAULT_HASH_ALGO}): $(calculate_hash "$source_file")"
        echo ""
        echo "Parts:"

        find "$output_dir" -name "${base_name}.part-*" | sort | while read -r part_file; do
            local part_hash
            part_hash=$(calculate_hash "$part_file")
            local part_basename
            part_basename=$(basename "$part_file")
            echo "  $part_basename: $part_hash"

            # Set permissions for each part
            chmod "$DEFAULT_EVIDENCE_PERMS" "$part_file" || log_warn "Failed to set permissions on $part_file"
        done
    } > "$manifest_file"

    chmod "$DEFAULT_EVIDENCE_PERMS" "$manifest_file" || log_warn "Failed to set permissions on $manifest_file"

    log_success "Split completed in $elapsed ($part_count parts created)"
    log_coc_event "Split" "$source_file" "Parts: $part_count, Manifest: $manifest_file"

    return 0
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

# Load tools from configuration file
# Arguments:
#   $1: Path to tool dependencies configuration file
# Returns: 0 on success, non-zero on failure
load_tool_dependencies() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        log_warn "Tool dependencies config file not found: $config_file"
        return 1
    }

    log_debug "Loading tool dependencies from: $config_file"

    # Parse config file sections
    local current_section=""
    local section_count=0
    local tool_count=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Check for section header
        if [[ "$line" =~ ^\[(.*)\]$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            ((section_count++))
            log_debug "Processing config section: $current_section"
            continue
        fi

        # Process key-value pairs
        if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
            local tool_name="${BASH_REMATCH[1]}"
            local tool_path="${BASH_REMATCH[2]}"

            # Trim whitespace
            tool_name=$(echo "$tool_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            tool_path=$(echo "$tool_path" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # Skip tool line if it contains comment marker
            [[ "$tool_name" == *"#"* ]] && continue

            # Store in associative array for later use
            TOOL_PATHS["${current_section}.${tool_name}"]="$tool_path"

            # Only check existence if path is not empty
            if [[ -n "$tool_path" && -n "$tool_name" ]]; then
                if [[ -x "$tool_path" ]]; then
                    log_debug "Verified tool: $tool_name -> $tool_path"
                    ((tool_count++))
                else
                    log_warn "Tool not found or not executable: $tool_name -> $tool_path"
                    # Check for fallback
                    local fallback_key="fallback_options.${tool_name}_fallback"
                    if [[ -n "${TOOL_PATHS[$fallback_key]:-}" ]]; then
                        log_info "Fallback found for $tool_name: ${TOOL_PATHS[$fallback_key]}"
                    fi
                fi
            fi
        fi
    done < "$config_file"

    log_info "Loaded $tool_count tools from $section_count sections"
    return 0
}

# Get tool path from loaded configuration
# Arguments:
#   $1: Section name
#   $2: Tool name
# Returns: Tool path if found, otherwise empty string
get_tool_path() {
    local section="$1"
    local tool="$2"
    local key="${section}.${tool}"

    echo "${TOOL_PATHS[$key]:-}"
}

# Execute a command with the configured tool
# Arguments:
#   $1: Section name
#   $2: Tool name
#   $3+: Arguments to pass to the tool
# Returns: Exit code from the tool
execute_tool() {
    local section="$1"
    local tool="$2"
    shift 2

    local tool_path
    tool_path=$(get_tool_path "$section" "$tool")

    if [[ -z "$tool_path" || ! -x "$tool_path" ]]; then
        # Try fallback
        local fallback_key="fallback_options.${tool}_fallback"
        local fallback_tool="${TOOL_PATHS[$fallback_key]:-}"

        if [[ -n "$fallback_tool" ]]; then
            log_debug "Using fallback $fallback_tool for $tool"
            # Fallback might be a tool name or a command sequence
            if [[ "$fallback_tool" =~ [[:space:]] ]]; then
                # Multiple words, treat as a command
                eval "$fallback_tool" "$@"
                return $?
            else
                # Single word, look up the path
                local fallback_path
                fallback_path=$(get_tool_path "$(echo "$fallback_key" | cut -d. -f1)" "$fallback_tool")
                if [[ -n "$fallback_path" && -x "$fallback_path" ]]; then
                    "$fallback_path" "$@"
                    return $?
                fi
            fi
        fi

        # Try PATH as last resort
        if command -v "$tool" &>/dev/null; then
            log_debug "Tool $tool not found in config, using from PATH"
            "$tool" "$@"
            return $?
        else
            log_error "Tool $tool not available and no fallback found"
            return 1
        fi
    else
        "$tool_path" "$@"
        return $?
    fi
}

# --- Parallel Execution Support ---

# Execute a command with a timeout
# Arguments:
#   $1: Timeout in seconds
#   $2+: Command to execute
# Returns: Command exit status or 124 if timed out
execute_with_timeout() {
    local timeout=$1
    shift

    if command -v timeout &>/dev/null; then
        timeout "$timeout" "$@"
        return $?
    else
        # Fall back to manual timeout using background jobs
        "$@" &
        local pid=$!
        local count=0

        while [[ $count -lt $timeout ]]; do
            sleep 1
            if ! kill -0 $pid 2>/dev/null; then
                # Process completed
                wait $pid
                return $?
            fi
            ((count++))
        done

        # Process still running after timeout
        kill -TERM $pid 2>/dev/null || kill -KILL $pid 2>/dev/null
        wait $pid 2>/dev/null
        return 124  # Same as GNU timeout
    fi
}

# Run multiple commands in parallel with control over concurrency
# Arguments:
#   $1: Maximum concurrent tasks
#   $2: Command array (command strings)
# Returns: 0 if all commands succeed, 1 if any fail
run_parallel() {
    local max_concurrent=$1
    shift
    local -a commands=("$@")
    local -a pids=()
    local -a results=()
    local cmd_count=${#commands[@]}
    local next_cmd=0
    local completed=0
    local failed=0

    log_info "Running $cmd_count commands with max concurrency of $max_concurrent"

    # Start initial batch of commands
    while [[ ${#pids[@]} -lt $max_concurrent && $next_cmd -lt $cmd_count ]]; do
        log_debug "Starting command[$next_cmd]: ${commands[$next_cmd]}"
        eval "${commands[$next_cmd]}" &
        pids+=($!)
        results[$next_cmd]=-1  # -1 indicates in progress
        ((next_cmd++))
    done

    # Process remaining commands as others finish
    while [[ $completed -lt $cmd_count ]]; do
        # Check for completed processes
        for i in "${!pids[@]}"; do
            if [[ ${pids[$i]} -eq 0 ]]; then
                # Already processed
                continue
            fi

            if ! kill -0 ${pids[$i]} 2>/dev/null; then
                # Process completed, get its exit status
                wait ${pids[$i]} 2>/dev/null
                results[$i]=$?

                if [[ ${results[$i]} -ne 0 ]]; then
                    ((failed++))
                    log_warn "Command[$i] failed with exit code ${results[$i]}"
                else
                    log_debug "Command[$i] completed successfully"
                fi

                # Mark as processed
                pids[$i]=0
                ((completed++))

                # Start next command if available
                if [[ $next_cmd -lt $cmd_count ]]; then
                    log_debug "Starting command[$next_cmd]: ${commands[$next_cmd]}"
                    eval "${commands[$next_cmd]}" &
                    pids+=($!)
                    results[$next_cmd]=-1  # -1 indicates in progress
                    ((next_cmd++))
                fi
            fi
        done

        # Brief pause to avoid CPU spinning
        sleep 0.1
    done

    if [[ $failed -gt 0 ]]; then
        log_warn "$failed out of $cmd_count commands failed"
        return 1
    else
        log_success "All $cmd_count commands completed successfully"
        return 0
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
    local timestamp
    timestamp=$(get_timestamp)

    local message="CoC: Action='$action', Item='$item', User='$user@$hostname', Timestamp='$timestamp'"
    if [[ -n "$CASE_ID" ]]; then
        message+=", CaseID='$CASE_ID'"
    fi
    if [[ -n "$EXAMINER_ID" ]]; then
        message+=", ExaminerID='$EXAMINER_ID'"
    fi
    if [[ -n "$details" ]]; then
        message+=", Details='$details'"
    fi

    log_audit "$message"

    # Create a structured representation for potential export
    if [[ -d "$OUTPUT_DIR/coc" ]]; then
        local coc_record="{
  \"timestamp\": \"$timestamp\",
  \"action\": \"$action\",
  \"item\": \"$item\",
  \"user\": \"$user@$hostname\",
  \"case_id\": \"${CASE_ID:-N/A}\",
  \"examiner_id\": \"${EXAMINER_ID:-N/A}\",
  \"details\": \"${details:-N/A}\"
}"
        echo "$coc_record" >> "$OUTPUT_DIR/coc/coc-log.jsonl"
    fi
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

    # Initialize tool paths associative array
    declare -A TOOL_PATHS

    # Initialize temp files array
    declare -a TEMP_FILES_TO_REMOVE=()

    # Set up trap for cleanup
    trap cleanup_on_exit EXIT INT TERM QUIT HUP

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

    # Create chain of custody directory
    ensure_output_dir "$OUTPUT_DIR/coc"

    # Initialize CoC log
    if [[ -d "$OUTPUT_DIR/coc" ]]; then
        local coc_jsonl="$OUTPUT_DIR/coc/coc-log.jsonl"
        touch "$coc_jsonl" && chmod "$DEFAULT_EVIDENCE_PERMS" "$coc_jsonl"
    fi

    log_info "Common functions initialized. Version: $LIVE_RESPONSE_COMMON_VERSION ($LIVE_RESPONSE_COMMON_DATE)"
    log_debug "Log File: ${LOG_FILE:-Not Set}"
    log_debug "Audit Log File: ${AUDIT_LOG_FILE:-Not Set}"
    log_debug "Output Directory: $OUTPUT_DIR"
    log_debug "Log Level: $DEFAULT_LOG_LEVEL"

    # Export variables for global access
    export TOOL_PATHS
    export TEMP_FILES_TO_REMOVE
}

# --- Version Info ---
get_common_live_response_version() {
    echo "${LIVE_RESPONSE_COMMON_VERSION} (${LIVE_RESPONSE_COMMON_DATE})"
}

# --- End of Functions ---
log_debug "common_functions.sh sourced successfully."
