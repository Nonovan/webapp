#!/bin/bash
# filepath: scripts/utils/common/common_file_ops_utils.sh
# File operations utility functions for Cloud Infrastructure Platform
# These functions provide secure file handling operations for various tasks

#######################################
# FILE OPERATIONS FUNCTIONS
#######################################

# Version tracking
FILE_OPERATIONS_UTILS_VERSION="1.1.0"
FILE_OPERATIONS_UTILS_DATE="2024-07-27"

# Get script version information
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_file_operations_utils_version() {
    echo "${FILE_OPERATIONS_UTILS_VERSION} (${FILE_OPERATIONS_UTILS_DATE})"
}

# Define secure permission constants for file operations
DEFAULT_BACKUP_FILE_PERMS="600"  # Restrictive permissions for backup files
DEFAULT_TEMP_FILE_PERMS="600"    # Restrictive permissions for temporary files
DEFAULT_LOCK_FILE_TIMEOUT=300    # Default timeout for lock files (seconds)

# Check if required functions are available
for func in command_exists error_exit warn debug; do
    if ! type -t "$func" &>/dev/null; then
        echo "Required function $func not available. Make sure to source common_core_utils.sh first." >&2
        exit 1
    fi
done

# Create and manage lock files for process synchronization
# Arguments:
#   $1 - Lock file path
#   $2 - Timeout in seconds (optional - defaults to DEFAULT_LOCK_FILE_TIMEOUT)
#   $3 - Wait for lock (true/false, defaults to true)
# Returns:
#   0 if lock acquired, 1 if failed
acquire_lock() {
    local lock_file="$1"
    local timeout="${2:-$DEFAULT_LOCK_FILE_TIMEOUT}"
    local wait="${3:-true}"
    local lock_dir
    local start_time
    local current_time
    local elapsed
    local lock_pid

    # Check arguments
    if [[ -z "$lock_file" ]]; then
        error_exit "Missing lock file path for acquire_lock"
        return 1
    fi

    # Validate timeout
    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        warn "Invalid timeout value for acquire_lock: $timeout, using default"
        timeout="$DEFAULT_LOCK_FILE_TIMEOUT"
    fi

    # Create parent directory for lock file if it doesn't exist
    lock_dir=$(dirname "$lock_file")
    ensure_directory "$lock_dir" || return 1

    start_time=$(date +%s)

    # Try to acquire the lock
    while true; do
        # Create lock file atomically
        if (set -o noclobber; echo "$$" > "$lock_file") 2>/dev/null; then
            # Lock acquired
            debug "Acquired lock: $lock_file (PID: $$)"
            # Register cleanup handler for automatic lock release on exit
            trap "release_lock \"$lock_file\" \"$$\"" EXIT
            return 0
        fi

        # Check if the lock is stale
        if [[ -f "$lock_file" ]]; then
            # Read PID from lock file
            lock_pid=$(cat "$lock_file" 2>/dev/null)

            if [[ -n "$lock_pid" && "$lock_pid" =~ ^[0-9]+$ ]]; then
                # Check if process is still running
                if ! ps -p "$lock_pid" > /dev/null 2>&1; then
                    # Process is no longer running, remove stale lock
                    debug "Removing stale lock held by PID $lock_pid"
                    rm -f "$lock_file"
                    continue  # Try again immediately
                fi
            fi
        fi

        # If not waiting, exit now
        if [[ "$wait" != "true" ]]; then
            warn "Could not acquire lock: $lock_file (already held)"
            return 1
        fi

        # Check if we've timed out
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))

        if ((elapsed >= timeout)); then
            error_exit "Timed out waiting for lock: $lock_file after ${elapsed}s"
            return 1
        fi

        # Wait before retrying (use exponential backoff)
        local wait_time=$((1 + (elapsed / 10)))
        wait_time=$((wait_time > 5 ? 5 : wait_time))  # Cap at 5 seconds
        debug "Waiting for lock: $lock_file (retry in ${wait_time}s, held by PID $lock_pid)"
        sleep "$wait_time"
    done
}

# Release a previously acquired lock file
# Arguments:
#   $1 - Lock file path
#   $2 - Expected PID (optional, defaults to current PID)
# Returns:
#   0 if lock released or not held, 1 on error
release_lock() {
    local lock_file="$1"
    local expected_pid="${2:-$$}"
    local actual_pid

    if [[ -z "$lock_file" ]]; then
        error_exit "Missing lock file path for release_lock"
        return 1
    fi

    # Check if lock file exists
    if [[ ! -f "$lock_file" ]]; then
        debug "Lock file does not exist: $lock_file"
        return 0
    fi

    # Read PID from lock file
    actual_pid=$(cat "$lock_file" 2>/dev/null)

    # Only remove the lock if it belongs to us
    if [[ "$actual_pid" == "$expected_pid" ]]; then
        if rm -f "$lock_file"; then
            debug "Released lock: $lock_file"
            return 0
        else
            warn "Failed to release lock: $lock_file"
            return 1
        fi
    else
        warn "Not removing lock file $lock_file: owned by PID $actual_pid, not $expected_pid"
        return 1
    fi
}

# Create a backup of a file with secure permissions
# Arguments:
#   $1 - File to backup
#   $2 - Backup directory (optional - defaults to DEFAULT_BACKUP_DIR)
#   $3 - Custom permissions (optional - defaults to DEFAULT_BACKUP_FILE_PERMS)
# Returns:
#   Path to backup file on stdout on success, 1 on failure
backup_file() {
    local file="$1"
    local backup_dir="${2:-$DEFAULT_BACKUP_DIR}"
    local perms="${3:-$DEFAULT_BACKUP_FILE_PERMS}"
    local retries=3
    local retry_delay=2
    local attempt=1
    local lock_acquired=false
    local lock_file

    # Check for required parameters
    if [[ -z "$file" ]]; then
        error_exit "Missing required file parameter for backup_file"
        return 1
    fi

    # Validate file path for basic security
    if [[ "$file" == *".."* || "$file" == *"~"* ]]; then
        error_exit "Invalid file path with potentially unsafe components: $file"
        return 1
    }

    # Handle undefined DEFAULT_BACKUP_DIR gracefully
    if [[ -z "$backup_dir" ]]; then
        backup_dir="./backups"
    fi

    # Generate timestamp if not defined
    local timestamp="${TIMESTAMP:-$(date +%Y%m%d%H%M%S)}"
    local filename=$(basename "$file")
    local backup_file="${backup_dir}/${filename}.${timestamp}.bak"

    # Create lock file for safer concurrent access
    lock_file="/tmp/backup_$(echo "$file" | md5sum | cut -d' ' -f1).lock"

    if acquire_lock "$lock_file" 30; then
        lock_acquired=true
    else
        warn "Could not acquire lock for backup operation: $file"
        # Continue without lock, but with caution
    fi

    # Ensure backup directory exists with proper permissions
    ensure_directory "$backup_dir" "$DEFAULT_DIR_PERMS" || {
        [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
        error_exit "Failed to create backup directory: $backup_dir"
        return 1
    }

    # Check if source file exists
    if [[ ! -f "$file" ]]; then
        [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
        error_exit "Cannot backup file, source does not exist: $file"
        return 1
    }

    # Implement retry logic for backup operation
    while ((attempt <= retries)); do
        # Create backup with explicit error handling
        if cp -p "$file" "$backup_file" 2>/dev/null; then
            # Set secure permissions for backup file
            if ! chmod "$perms" "$backup_file" 2>/dev/null; then
                warn "Failed to set permissions $perms on backup file: $backup_file (continuing anyway)"
            fi

            debug "Created backup of $file at $backup_file with permissions $perms"
            [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
            echo "$backup_file"
            return 0
        else
            warn "Backup attempt $attempt/$retries failed for $file"
            ((attempt++))

            if ((attempt <= retries)); then
                debug "Retrying backup in $retry_delay seconds..."
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))  # Exponential backoff
            fi
        fi
    done

    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
    error_exit "Failed to create backup of $file after $retries attempts"
    return 1
}

# Create directory if it doesn't exist with proper permissions
# Arguments:
#   $1 - Directory path
#   $2 - Permissions (optional - defaults to DEFAULT_DIR_PERMS)
#   $3 - Owner:Group (optional - format "user:group")
#   $4 - Create parent directories (optional - defaults to true)
# Returns:
#   0 if created or exists with proper permissions, 1 on failure
ensure_directory() {
    local dir="$1"
    local perms="${2:-$DEFAULT_DIR_PERMS}"
    local owner="${3:-}"
    local create_parents="${4:-true}"
    local mkdiropts=""
    local retries=3
    local retry_delay=2
    local attempt=1

    # Check for required parameters
    if [[ -z "$dir" ]]; then
        error_exit "Missing required directory path parameter for ensure_directory"
        return 1
    }

    # Handle undefined DEFAULT_DIR_PERMS gracefully
    if [[ -z "$perms" ]]; then
        perms="755"
    fi

    # Security check for directory traversal
    if [[ "$dir" == *".."* ]]; then
        error_exit "Directory path contains potentially unsafe '..' components: $dir"
        return 1
    fi

    # Set mkdir options based on create_parents flag
    if [[ "$create_parents" == "true" ]]; then
        mkdiropts="-p"
    fi

    # Check if directory already exists
    if [[ -d "$dir" ]]; then
        # Directory exists, check if we need to update permissions
        local current_perms
        local update_perms=false

        if command_exists stat; then
            if [[ "$(uname)" == "Darwin" ]]; then
                # macOS version
                current_perms=$(stat -f '%A' "$dir" 2>/dev/null)
            else
                # Linux version
                current_perms=$(stat -c '%a' "$dir" 2>/dev/null)
            fi

            # Check if current permissions match expected
            if [[ -n "$current_perms" && "$current_perms" != "$perms" ]]; then
                # Only try to change permissions if we have write access to parent
                if [[ -w "$(dirname "$dir")" ]]; then
                    update_perms=true
                fi
            fi
        fi

        # Try to update permissions if needed
        if [[ "$update_perms" == "true" ]]; then
            # Implement retry logic for chmod
            attempt=1
            while ((attempt <= retries)); do
                if chmod "$perms" "$dir" 2>/dev/null; then
                    debug "Updated permissions for directory: $dir from $current_perms to $perms"
                    break
                else
                    warn "Chmod attempt $attempt/$retries failed for $dir"
                    ((attempt++))

                    if ((attempt <= retries)); then
                        sleep $retry_delay
                        retry_delay=$((retry_delay * 2))  # Exponential backoff
                    else
                        warn "Failed to update permissions on existing directory: $dir (continuing anyway)"
                    fi
                fi
            done
        fi

        # Set owner if specified and running as root
        if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
            if command_exists stat; then
                local current_owner
                current_owner=$(stat -c '%U:%G' "$dir" 2>/dev/null || echo "unknown:unknown")
                if [[ "$current_owner" != "$owner" ]]; then
                    # Implement retry logic for chown
                    attempt=1
                    while ((attempt <= retries)); do
                        if chown "$owner" "$dir" 2>/dev/null; then
                            debug "Updated owner for directory: $dir from $current_owner to $owner"
                            break
                        else
                            warn "Chown attempt $attempt/$retries failed for $dir"
                            ((attempt++))

                            if ((attempt <= retries)); then
                                sleep $retry_delay
                                retry_delay=$((retry_delay * 2))  # Exponential backoff
                            else
                                warn "Failed to update owner for directory: $dir (continuing anyway)"
                            fi
                        fi
                    done
                }
            }
        }
    else
        # Directory doesn't exist, try to create it
        attempt=1
        while ((attempt <= retries)); do
            if mkdir $mkdiropts "$dir" 2>/dev/null; then
                # Set owner if specified and running as root
                if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
                    chown "$owner" "$dir" 2>/dev/null || {
                        warn "Failed to set owner $owner for directory: $dir (continuing anyway)"
                    }
                fi

                # Set permissions
                chmod "$perms" "$dir" 2>/dev/null || {
                    warn "Failed to set permissions $perms on directory: $dir"
                    # Continue despite warning as directory was created
                }

                debug "Created directory: $dir with permissions $perms"
                break
            else
                warn "Directory creation attempt $attempt/$retries failed for $dir"
                ((attempt++))

                if ((attempt <= retries)); then
                    sleep $retry_delay
                    retry_delay=$((retry_delay * 2))  # Exponential backoff
                else
                    error_exit "Failed to create directory: $dir after $retries attempts"
                    return 1
                fi
            fi
        done
    fi

    # Check if directory is writable regardless of creation
    if [[ ! -w "$dir" ]]; then
        error_exit "Directory is not writable: $dir"
        return 1
    }

    return 0
}

# Safely write content to a file with error handling and proper permissions
# Arguments:
#   $1 - Content to write
#   $2 - Output file
#   $3 - Create backup (true/false, defaults to true)
#   $4 - File permissions (optional, defaults to DEFAULT_FILE_PERMS)
#   $5 - Owner:Group (optional - format "user:group")
#   $6 - Atomic write (optional - true/false, defaults to true)
# Returns: 0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local output_file="$2"
    local create_backup="${3:-true}"
    local perms="${4:-$DEFAULT_FILE_PERMS}"
    local owner="${5:-}"
    local atomic="${6:-true}"
    local temp_file=""
    local lock_file=""
    local lock_acquired=false
    local retries=3
    local retry_delay=2
    local attempt=1

    # Check for required parameters
    if [[ -z "$output_file" ]]; then
        error_exit "Missing required output file parameter for safe_write_file"
        return 1
    }

    # Validate file path for basic security
    if [[ "$output_file" == *".."* || "$output_file" == *"~"* ]]; then
        error_exit "Invalid output file path with potentially unsafe components: $output_file"
        return 1
    }

    # Handle undefined DEFAULT_FILE_PERMS gracefully
    if [[ -z "$perms" ]]; then
        perms="644"
    fi

    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$output_file")" || {
        error_exit "Failed to ensure parent directory exists for: $output_file"
        return 1
    }

    # Create and acquire lock file for this operation
    lock_file="/tmp/fileop_$(echo "$output_file" | md5sum | cut -d' ' -f1).lock"

    if acquire_lock "$lock_file" 30; then
        lock_acquired=true
        debug "Acquired lock for file operation: $output_file"
    else
        warn "Could not acquire lock for file operation: $output_file, proceeding with caution"
    fi

    # Backup existing file if requested
    if [[ "$create_backup" == "true" && -f "$output_file" ]]; then
        if ! backup_file "$output_file" >/dev/null; then
            warn "Failed to back up existing file: $output_file (continuing anyway)"
        fi
    fi

    # Check if we're doing atomic write or direct write
    if [[ "$atomic" == "true" ]]; then
        # Create a secure temporary file
        temp_file=$(create_secure_temp "$(basename "$output_file")" "$DEFAULT_TEMP_FILE_PERMS")

        if [[ -z "$temp_file" || ! -f "$temp_file" ]]; then
            [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
            error_exit "Failed to create temporary file for: $output_file"
            return 1
        fi

        # Write content to temporary file with retry logic
        attempt=1
        while ((attempt <= retries)); do
            # Using printf instead of echo to handle special characters better
            if printf "%s\n" "$content" > "$temp_file" 2>/dev/null; then
                break
            else
                warn "Write attempt $attempt/$retries failed for temporary file"
                ((attempt++))

                if ((attempt <= retries)); then
                    debug "Retrying write in $retry_delay seconds..."
                    sleep $retry_delay
                    retry_delay=$((retry_delay * 2))  # Exponential backoff
                else
                    rm -f "$temp_file"
                    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
                    error_exit "Failed to write content to temporary file after $retries attempts"
                    return 1
                fi
            fi
        done

        # Set final permissions on temporary file before moving
        chmod "$perms" "$temp_file" 2>/dev/null || {
            warn "Failed to set permissions $perms on temporary file (continuing anyway)"
        }

        # Set owner if specified and running as root
        if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
            chown "$owner" "$temp_file" 2>/dev/null || {
                warn "Failed to set owner $owner for file (continuing anyway)"
            }
        }

        # Move temporary file to destination (preserves permissions)
        attempt=1
        retry_delay=2

        while ((attempt <= retries)); do
            if mv "$temp_file" "$output_file" 2>/dev/null; then
                debug "Successfully wrote content to $output_file with permissions $perms"
                [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
                return 0
            else
                warn "Move attempt $attempt/$retries failed from $temp_file to $output_file"
                ((attempt++))

                if ((attempt <= retries)); then
                    debug "Retrying move in $retry_delay seconds..."
                    sleep $retry_delay
                    retry_delay=$((retry_delay * 2))  # Exponential backoff
                else
                    rm -f "$temp_file"
                    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
                    error_exit "Failed to write to final destination: $output_file after $retries attempts"
                    return 1
                fi
            fi
        done
    else
        # Direct write (non-atomic)
        attempt=1
        while ((attempt <= retries)); do
            if printf "%s\n" "$content" > "$output_file" 2>/dev/null; then
                # Set permissions
                chmod "$perms" "$output_file" 2>/dev/null || {
                    warn "Failed to set permissions $perms on file: $output_file (continuing anyway)"
                }

                # Set owner if specified and running as root
                if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
                    chown "$owner" "$output_file" 2>/dev/null || {
                        warn "Failed to set owner $owner for file: $output_file (continuing anyway)"
                    }
                }

                debug "Successfully wrote content directly to $output_file with permissions $perms"
                [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
                return 0
            else
                warn "Write attempt $attempt/$retries failed for $output_file"
                ((attempt++))

                if ((attempt <= retries)); then
                    debug "Retrying write in $retry_delay seconds..."
                    sleep $retry_delay
                    retry_delay=$((retry_delay * 2))  # Exponential backoff
                else
                    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
                    error_exit "Failed to write to file: $output_file after $retries attempts"
                    return 1
                fi
            fi
        done
    fi

    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
    return 1  # Should not reach here
}

# Get file age in seconds with performance optimization
# Arguments:
#   $1 - File path
#   $2 - Cache results (optional - true/false, defaults to true)
# Returns: File age in seconds on stdout or -1 if file not found/error
file_age() {
    local file="$1"
    local use_cache="${2:-true}"
    local file_time
    local current_time
    local cache_key
    local cache_file

    # Check for required parameters
    if [[ -z "$file" ]]; then
        warn "Missing required file parameter for file_age"
        echo "-1"
        return 1
    }

    # Validate file path for basic security
    if [[ "$file" == *".."* || "$file" == *"~"* ]]; then
        warn "Invalid file path with potentially unsafe components: $file"
        echo "-1"
        return 1
    }

    if [[ ! -f "$file" ]]; then
        warn "Cannot get age of non-existent file: $file"
        echo "-1"
        return 1
    }

    # Use a simple caching mechanism to avoid repeated calls for the same file
    # within a short time window (5 minutes)
    if [[ "$use_cache" == "true" ]]; then
        cache_key=$(echo "$file" | md5sum | cut -d' ' -f1)
        cache_file="/tmp/file_age_cache_${cache_key}"

        # Check if valid cache exists and is less than 5 minutes old
        if [[ -f "$cache_file" ]]; then
            # Cache format: mtime|current_time|age
            local cached_data
            IFS='|' read -r cached_mtime cached_current cached_age < "$cache_file"

            # Check if file modification time has changed
            local actual_mtime
            if [[ "$(uname)" == "Darwin" ]]; then
                actual_mtime=$(stat -f %m "$file" 2>/dev/null)
            else
                actual_mtime=$(stat -c %Y "$file" 2>/dev/null)
            fi

            if [[ "$cached_mtime" == "$actual_mtime" ]]; then
                # File hasn't changed, update age based on elapsed time
                current_time=$(date +%s)
                local elapsed=$((current_time - cached_current))
                local updated_age=$((cached_age + elapsed))
                echo "$updated_age"

                # Update cache with new timestamp (but don't update too frequently)
                if ((elapsed > 60)); then
                    echo "${actual_mtime}|${current_time}|${updated_age}" > "$cache_file"
                fi
                return 0
            fi
        fi
    fi

    # Get file modification time
    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_time=$(stat -f %m "$file" 2>/dev/null)
        else
            # Linux version
            file_time=$(stat -c %Y "$file" 2>/dev/null)
        fi
    else
        # Fallback method using ls
        if ls --time-style=+%s /dev/null &>/dev/null; then
            # GNU ls version with --time-style
            file_time=$(ls -l --time-style=+%s "$file" 2>/dev/null | awk '{print $6}')
        else
            # Fallback to perl for timestamp conversion
            if command_exists perl; then
                file_time=$(perl -e 'print ((stat($ARGV[0]))[9])' "$file" 2>/dev/null)
            else
                warn "Cannot determine file age: compatible stat, ls, or perl not available"
                echo "-1"
                return 1
            fi
        fi
    fi

    if [[ -z "$file_time" || ! "$file_time" =~ ^[0-9]+$ ]]; then
        warn "Failed to get file modification time: $file"
        echo "-1"
        return 1
    fi

    current_time=$(date +%s)
    local age=$((current_time - file_time))

    # Update cache if enabled
    if [[ "$use_cache" == "true" && -n "$cache_file" ]]; then
        echo "${file_time}|${current_time}|${age}" > "$cache_file"
    fi

    echo "$age"
    return 0
}

# Check if file is older than specified time period
# Arguments:
#   $1 - File path
#   $2 - Max age in seconds
#   $3 - Default result if file doesn't exist (optional - true/false, defaults to true)
# Returns: 0 if file is older than max age or doesn't exist (and default is true),
#          1 if file is newer or doesn't exist (and default is false)
is_file_older_than() {
    local file="$1"
    local max_age="$2"
    local default_if_missing="${3:-true}"

    # Validate input
    if [[ -z "$file" ]]; then
        warn "Missing required file parameter for is_file_older_than"
        return 1
    }

    # Validate file path for basic security
    if [[ "$file" == *".."* || "$file" == *"~"* ]]; then
        warn "Invalid file path with potentially unsafe components: $file"
        return 1
    }

    if [[ -z "$max_age" || ! "$max_age" =~ ^[0-9]+$ ]]; then
        error_exit "Invalid max_age parameter: $max_age (must be a positive number)"
        return 1
    }

    if [[ ! -f "$file" ]]; then
        # File doesn't exist, return based on default_if_missing
        debug "File does not exist, returning $default_if_missing: $file"
        if [[ "$default_if_missing" == "true" ]]; then
            return 0
        else
            return 1
        fi
    fi

    local age
    age=$(file_age "$file")
    local status=$?

    if [[ $status -ne 0 || "$age" == "-1" ]]; then
        # Error getting age, assume file is too new
        warn "Failed to determine file age, assuming file is newer than threshold: $file"
        return 1
    }

    if (( age > max_age )); then
        # File is older than max_age
        debug "File is older than $max_age seconds (actual age: $age): $file"
        return 0
    else
        # File is newer than max_age
        debug "File is newer than $max_age seconds (actual age: $age): $file"
        return 1
    fi
}

# Copy a file with proper permissions and retry logic
# Arguments:
#   $1 - Source file
#   $2 - Destination file
#   $3 - Permissions (optional, defaults to source file permissions or DEFAULT_FILE_PERMS)
#   $4 - Owner:Group (optional - format "user:group")
#   $5 - Try hard link first (optional - true/false, defaults to false)
# Returns: 0 on success, 1 on failure
secure_copy_file() {
    local source="$1"
    local dest="$2"
    local perms="${3:-}"
    local owner="${4:-}"
    local try_link="${5:-false}"
    local retries=3
    local retry_delay=2
    local attempt=1
    local lock_file
    local lock_acquired=false

    # Check for required parameters
    if [[ -z "$source" || -z "$dest" ]]; then
        error_exit "Missing required parameters for secure_copy_file"
        return 1
    }

    # Validate paths for basic security
    if [[ "$source" == *".."* || "$source" == *"~"* || "$dest" == *".."* || "$dest" == *"~"* ]]; then
        error_exit "Invalid path with potentially unsafe components"
        return 1
    }

    # Check if source file exists
    if [[ ! -f "$source" ]]; then
        error_exit "Source file does not exist: $source"
        return 1
    }

    # Get source permissions if not specified
    if [[ -z "$perms" ]]; then
        if command_exists stat; then
            if [[ "$(uname)" == "Darwin" ]]; then
                # macOS version
                perms=$(stat -f '%A' "$source" 2>/dev/null)
            else
                # Linux version
                perms=$(stat -c '%a' "$source" 2>/dev/null)
            fi
        fi

        # Default to DEFAULT_FILE_PERMS if we couldn't determine source perms
        if [[ -z "$perms" ]]; then
            perms="${DEFAULT_FILE_PERMS:-644}"
        fi
    fi

    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$dest")" || {
        error_exit "Failed to ensure parent directory exists for: $dest"
        return 1
    }

    # Acquire lock for this operation
    lock_file="/tmp/filecopy_$(echo "${source}:${dest}" | md5sum | cut -d' ' -f1).lock"

    if acquire_lock "$lock_file" 30; then
        lock_acquired=true
    else
        warn "Could not acquire lock for file copy: $source -> $dest"
        # Continue without lock, but with caution
    fi

    # Try using hard link first if requested (faster and more atomic)
    if [[ "$try_link" == "true" ]]; then
        if ln "$source" "$dest" 2>/dev/null; then
            # Hard link succeeded, set permissions and owner
            chmod "$perms" "$dest" 2>/dev/null || {
                warn "Failed to set permissions $perms on linked file: $dest (continuing anyway)"
            }

            # Set owner if specified and running as root
            if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
                chown "$owner" "$dest" 2>/dev/null || {
                    warn "Failed to set owner $owner for linked file: $dest (continuing anyway)"
                }
            }

            debug "Created hard link from $source to $dest with permissions $perms"
            [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
            return 0
        fi
        # If hard link fails, fall back to copy
    }

    # Copy the file with retry logic
    attempt=1
    while ((attempt <= retries)); do
        if cp -f "$source" "$dest" 2>/dev/null; then
            # Set permissions
            chmod "$perms" "$dest" 2>/dev/null || {
                warn "Failed to set permissions $perms on file: $dest (continuing anyway)"
            }

            # Set owner if specified and running as root
            if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
                chown "$owner" "$dest" 2>/dev/null || {
                    warn "Failed to set owner $owner for file: $dest (continuing anyway)"
                }
            }

            debug "Copied file from $source to $dest with permissions $perms"
            [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
            return 0
        else
            warn "Copy attempt $attempt/$retries failed from $source to $dest"
            ((attempt++))

            if ((attempt <= retries)); then
                debug "Retrying copy in $retry_delay seconds..."
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))  # Exponential backoff
            fi
        fi
    done

    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
    error_exit "Failed to copy file from $source to $dest after $retries attempts"
    return 1
}

# Create a temporary file with secure permissions
# Arguments:
#   $1 - Prefix for temp file name (optional)
#   $2 - Permissions (optional, defaults to DEFAULT_TEMP_FILE_PERMS)
#   $3 - Directory to create temp file in (optional, uses system default)
# Returns: Path to temporary file on stdout, or 1 on failure
create_secure_temp() {
    local prefix="${1:-temp}"
    local perms="${2:-$DEFAULT_TEMP_FILE_PERMS}"
    local temp_dir="${3:-}"
    local temp_file
    local retries=3
    local retry_delay=2
    local attempt=1

    # Sanitize prefix to prevent command injection
    prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_.-')

    # Handle undefined DEFAULT_TEMP_FILE_PERMS gracefully
    if [[ -z "$perms" ]]; then
        perms="600"
    fi

    # If no directory specified, find the best temp directory
    if [[ -z "$temp_dir" ]]; then
        # Ensure temp directory exists and is writable
        # Try different directories in order of preference
        for d in "/tmp" "/var/tmp" "$HOME/tmp" "."; do
            if [[ -d "$d" && -w "$d" ]]; then
                temp_dir="$d"
                break
            fi
        done
    elif [[ ! -d "$temp_dir" ]]; then
        # Create specified directory if it doesn't exist
        ensure_directory "$temp_dir" "700" || {
            error_exit "Failed to create temporary directory: $temp_dir"
            return 1
        }
    }

    # Use builtin mktemp with retry logic
    attempt=1
    while ((attempt <= retries)); do
        temp_file=$(mktemp "${temp_dir}/${prefix}.XXXXXXXX" 2>/dev/null)

        if [[ $? -eq 0 && -n "$temp_file" && -f "$temp_file" ]]; then
            # Set restrictive permissions immediately
            chmod "$perms" "$temp_file" 2>/dev/null || {
                warn "Failed to set permissions on temporary file: $temp_file (continuing anyway)"
            }

            echo "$temp_file"
            return 0
        else
            warn "Failed to create temporary file with mktemp (attempt $attempt/$retries)"
            ((attempt++))

            if ((attempt <= retries)); then
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))  # Exponential backoff
            fi
        fi
    done

    # Fallback method if all mktemp attempts fail
    local ts=$(date +%s)$$
    temp_file="${temp_dir}/${prefix}.${ts}"

    # Try to create the file atomically to avoid race conditions
    if (umask 077; touch "$temp_file" 2>/dev/null); then
        chmod "$perms" "$temp_file" 2>/dev/null || {
            warn "Failed to set permissions on fallback temporary file: $temp_file"
            # Continue despite warning
        }

        debug "Created fallback temporary file: $temp_file"
        echo "$temp_file"
        return 0
    fi

    error_exit "Failed to create temporary file with prefix: $prefix"
    return 1
}

# Securely remove a file (overwrite then delete)
# Arguments:
#   $1 - File to remove
#   $2 - Secure overwrite passes (optional, defaults to 1)
#   $3 - Force removal (optional, defaults to false)
# Returns: 0 on success, 1 on failure
secure_remove_file() {
    local file="$1"
    local passes="${2:-1}"
    local force="${3:-false}"
    local retries=3
    local retry_delay=2
    local attempt=1
    local lock_file
    local lock_acquired=false

    # Check for required parameters
    if [[ -z "$file" ]]; then
        warn "Missing required file parameter for secure_remove_file"
        return 1
    }

    # Validate file path for basic security
    if [[ "$file" == *".."* || "$file" == *"~"* ]]; then
        error_exit "Invalid file path with potentially unsafe components: $file"
        return 1
    }

    if [[ ! -f "$file" && "$force" != "true" ]]; then
        # File doesn't exist, consider it success
        debug "File already doesn't exist, nothing to remove: $file"
        return 0
    fi

    # Create and acquire lock for this file
    lock_file="/tmp/filerem_$(echo "$file" | md5sum | cut -d' ' -f1).lock"

    if acquire_lock "$lock_file" 20; then
        lock_acquired=true
    else
        warn "Could not acquire lock for file removal: $file"
        # Continue without lock if force is true, otherwise fail
        if [[ "$force" != "true" ]]; then
            warn "Aborting secure removal due to lock acquisition failure"
            return 1
        fi
    fi

    # Check if file is writable if it exists
    if [[ -f "$file" && ! -w "$file" ]]; then
        # Try to make it writable first
        chmod u+w "$file" 2>/dev/null || {
            warn "File is not writable and couldn't change permissions: $file"
            # Continue anyway, as we'll try to remove it
        }
    fi

    # Validate passes parameter
    if [[ ! "$passes" =~ ^[0-9]+$ ]]; then
        warn "Invalid passes parameter: $passes (must be a non-negative number)"
        passes=1
    fi

    # Check if shred command exists for secure deletion
    if command_exists shred; then
        attempt=1
        while ((attempt <= retries)); do
            if shred -f -z -u -n "$passes" "$file" 2>/dev/null; then
                [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
                debug "Securely removed file with shred: $file ($passes passes)"
                return 0
            else
                warn "Shred attempt $attempt/$retries failed for $file"
                ((attempt++))

                if ((attempt <= retries)); then
                    debug "Retrying shred in $retry_delay seconds..."
                    sleep $retry_delay
                    retry_delay=$((retry_delay * 2))  # Exponential backoff
                else
                    # If all shred attempts fail, fall back to basic removal
                    warn "Failed to securely shred file after $retries attempts, falling back to basic removal"
                    break
                fi
            fi
        done
    fi

    # Fallback if shred is not available or failed
    if [[ "$passes" -gt 0 && -f "$file" ]]; then
        # Basic secure deletion: overwrite with random data
        local success=false

        for ((i=1; i<=passes; i++)); do
            debug "Secure deletion pass $i/$passes for $file"

            if command_exists dd && [[ -r "/dev/urandom" ]]; then
                # Get file size to avoid reading more than necessary from /dev/urandom
                local file_size=0
                if command_exists stat; then
                    if [[ "$(uname)" == "Darwin" ]]; then
                        # macOS version
                        file_size=$(stat -f %z "$file" 2>/dev/null || echo 0)
                    else
                        # Linux version
                        file_size=$(stat -c %s "$file" 2>/dev/null || echo 0)
                    fi
                fi

                # Use reasonable default if size couldn't be determined
                if [[ "$file_size" -eq 0 ]]; then
                    file_size=4096
                fi

                # Use smaller block size for large files to show progress
                local bs=4096
                local count=$((file_size / bs + 1))

                if dd if=/dev/urandom of="$file" bs=$bs count=$count conv=notrunc status=none 2>/dev/null; then
                    success=true
                else
                    success=false
                    break
                fi
            else
                # Even more basic fallback: overwrite with zeros
                if command_exists truncate; then
                    if truncate -s 0 "$file" 2>/dev/null; then
                        success=true
                    else
                        success=false
                        break
                    fi
                elif command_exists cp; then
                    # Final fallback: empty the file using cp
                    if cp /dev/null "$file" 2>/dev/null; then
                        success=true
                    else
                        success=false
                        break
                    fi
                else
                    warn "No secure overwrite tools available"
                    success=false
                    break
                fi
            fi
        done

        if [[ "$success" != "true" ]]; then
            warn "Failed during secure overwrite phase, still attempting to delete file"
        }
    fi

    # Finally, remove the file
    attempt=1
    while ((attempt <= retries)); do
        if rm -f "$file" 2>/dev/null; then
            [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
            debug "File removed: $file"
            return 0
        else
            warn "Remove attempt $attempt/$retries failed for $file"
            ((attempt++))

            if ((attempt <= retries)); then
                debug "Retrying remove in $retry_delay seconds..."
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))  # Exponential backoff
            fi
        fi
    done

    [[ "$lock_acquired" == "true" ]] && release_lock "$lock_file"
    error_exit "Failed to remove file: $file after $retries attempts"
    return 1
}

# Calculate and print hash of a file (supports multiple algorithms)
# Arguments:
#   $1 - File path
#   $2 - Algorithm (md5, sha1, sha256, sha512, defaults to sha256)
#   $3 - Use cache (optional - true/false, defaults to true)
# Returns: Hash value on stdout, 1 on failure
get_file_hash() {
    local file="$1"
    local algorithm="${2:-sha256}"
    local use_cache="${3:-true}"
    local hash_result
    local cache_file

    # Check for required parameters
    if [[ -z "$file" ]]; then
        error_exit "Missing required file parameter for get_file_hash"
        return 1
    }

    # Validate file path for basic security
    if [[ "$file" == *".."* || "$file" == *"~"* ]]; then
        error_exit "Invalid file path with potentially unsafe components: $file"
        return 1
    }

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        error_exit "File does not exist: $file"
        return 1
    }

    # Convert algorithm to lowercase
    algorithm=$(echo "$algorithm" | tr '[:upper:]' '[:lower:]')

    # Check cache first if enabled
    if [[ "$use_cache" == "true" ]]; then
        cache_file="/tmp/filehash_$(echo "${algorithm}:${file}" | md5sum | cut -d' ' -f1)"

        if [[ -f "$cache_file" ]]; then
            # Cache format: mtime|hash
            local cached_mtime cached_hash
            IFS='|' read -r cached_mtime cached_hash < "$cache_file"

            # Check if file has been modified
            local actual_mtime
            if [[ "$(uname)" == "Darwin" ]]; then
                actual_mtime=$(stat -f %m "$file" 2>/dev/null)
            else
                actual_mtime=$(stat -c %Y "$file" 2>/dev/null)
            fi

            if [[ "$cached_mtime" == "$actual_mtime" ]]; then
                # File hasn't changed, return cached hash
                echo "$cached_hash"
                return 0
            fi
        fi
    fi

    # Calculate hash based on algorithm
    case "$algorithm" in
        md5)
            if command_exists md5sum; then
                hash_result=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
            elif command_exists md5; then  # macOS
                hash_result=$(md5 -q "$file" 2>/dev/null)
            else
                error_exit "No MD5 hash command available"
                return 1
            fi
            ;;
        sha1)
            if command_exists sha1sum; then
                hash_result=$(sha1sum "$file" 2>/dev/null | awk '{print $1}')
            elif command_exists shasum; then  # macOS
                hash_result=$(shasum -a 1 "$file" 2>/dev/null | awk '{print $1}')
            else
                error_exit "No SHA1 hash command available"
                return 1
            fi
            ;;
        sha256)
            if command_exists sha256sum; then
                hash_result=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            elif command_exists shasum; then  # macOS
                hash_result=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
            else
                error_exit "No SHA256 hash command available"
                return 1
            fi
            ;;
        sha512)
            if command_exists sha512sum; then
                hash_result=$(sha512sum "$file" 2>/dev/null | awk '{print $1}')
            elif command_exists shasum; then  # macOS
                hash_result=$(shasum -a 512 "$file" 2>/dev/null | awk '{print $1}')
            else
                error_exit "No SHA512 hash command available"
                return 1
            fi
            ;;
        *)
            error_exit "Unsupported hash algorithm: $algorithm"
            return 1
            ;;
    esac

    # Check if hash calculation was successful
    if [[ -z "$hash_result" ]]; then
        error_exit "Failed to calculate $algorithm hash for file: $file"
        return 1
    fi

    # Update cache if enabled
    if [[ "$use_cache" == "true" && -n "$cache_file" ]]; then
        local mtime
        if [[ "$(uname)" == "Darwin" ]]; then
            mtime=$(stat -f %m "$file" 2>/dev/null)
        else
            mtime=$(stat -c %Y "$file" 2>/dev/null)
        fi

        echo "${mtime}|${hash_result}" > "$cache_file" 2>/dev/null
    fi

    echo "$hash_result"
    return 0
}

# Verify file integrity by comparing with a stored hash
# Arguments:
#   $1 - File path
#   $2 - Expected hash or hash file path
#   $3 - Algorithm (md5, sha1, sha256, sha512, defaults to sha256)
# Returns: 0 if hash matches, 1 if mismatch or error
verify_file_integrity() {
    local file="$1"
    local expected="$2"
    local algorithm="${3:-sha256}"
    local actual_hash
    local expected_hash="$expected"

    # Check for required parameters
    if [[ -z "$file" || -z "$expected" ]]; then
        error_exit "Missing required parameters for verify_file_integrity"
        return 1
    }

    # Validate file path for basic security
    if [[ "$file" == *".."* || "$file" == *"~"* ]]; then
        error_exit "Invalid file path with potentially unsafe components: $file"
        return 1
    }

    # Check if file exists
    if [[ ! -f "$file" ]]; then
        error_exit "File does not exist: $file"
        return 1
    }

    # If expected is a file path, read hash from it
    if [[ -f "$expected" ]]; then
        expected_hash=$(cat "$expected" 2>/dev/null | tr -d '[:space:]')
        if [[ -z "$expected_hash" ]]; then
            error_exit "Failed to read hash from file: $expected"
            return 1
        }
    fi

    # Calculate actual hash
    actual_hash=$(get_file_hash "$file" "$algorithm")
    if [[ $? -ne 0 || -z "$actual_hash" ]]; then
        error_exit "Failed to calculate hash for file: $file"
        return 1
    }

    # Compare hashes
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        debug "File integrity verified: $file ($algorithm hash matches)"
        return 0
    else
        warn "File integrity verification failed: $file ($algorithm hash mismatch)"
        debug "Expected: $expected_hash"
        debug "Actual  : $actual_hash"
        return 1
    fi
}

# Find files matching a pattern and optionally execute a command on them
# Arguments:
#   $1 - Base directory
#   $2 - File pattern (glob or regular expression)
#   $3 - Use regex for pattern (true/false, defaults to false)
#   $4 - Maximum depth (optional, defaults to unlimited)
#   $5 - Command to execute (optional, uses printf "%s\n" by default)
#   $6 - Concurrency level (optional, defaults to 1 - sequential)
# Returns: 0 on success, 1 on failure
find_files() {
    local base_dir="$1"
    local pattern="$2"
    local use_regex="${3:-false}"
    local max_depth="$4"
    local command="${5:-printf \"%s\n\"}"
    local concurrency="${6:-1}"
    local find_args=()
    local tempfile
    local result=0

    # Check for required parameters
    if [[ -z "$base_dir" || -z "$pattern" ]]; then
        error_exit "Missing required parameters for find_files"
        return 1
    }

    # Validate path for basic security
    if [[ "$base_dir" == *".."* || "$base_dir" == *"~"* ]]; then
        error_exit "Invalid directory path with potentially unsafe components: $base_dir"
        return 1
    }

    # Check if base directory exists
    if [[ ! -d "$base_dir" ]]; then
        error_exit "Base directory does not exist: $base_dir"
        return 1
    }

    # Validate concurrency parameter
    if ! [[ "$concurrency" =~ ^[0-9]+$ ]] || ((concurrency < 1)); then
        warn "Invalid concurrency parameter: $concurrency (must be a positive number)"
        concurrency=1
    fi

    # Add max depth parameter if specified
    if [[ -n "$max_depth" ]]; then
        if ! [[ "$max_depth" =~ ^[0-9]+$ ]]; then
            error_exit "Invalid max_depth parameter: $max_depth (must be a positive number)"
            return 1
        fi
        find_args+=(-maxdepth "$max_depth")
    fi

    # Use -regex or -name depending on use_regex parameter
    if [[ "$use_regex" == "true" ]]; then
        find_args+=(-regex "$pattern")
    else
        find_args+=(-name "$pattern")
    fi

    # Create a temporary file for results
    tempfile=$(create_secure_temp "find_results" "$DEFAULT_TEMP_FILE_PERMS")
    if [[ $? -ne 0 || -z "$tempfile" ]]; then
        error_exit "Failed to create temporary file for find_files"
        return 1
    }

    # Execute the find command first
    if ! find "$base_dir" "${find_args[@]}" -type f > "$tempfile" 2>/dev/null; then
        secure_remove_file "$tempfile"
        error_exit "Failed to execute find command"
        return 1
    fi

    if [[ "$concurrency" -gt 1 ]]; then
        # Run commands with parallelism if concurrency > 1
        if command_exists xargs; then
            if ! xargs -a "$tempfile" -P "$concurrency" -I{} bash -c "$command {}" 2>/dev/null; then
                warn "Some commands may have failed during parallel execution"
                result=1
            fi
        else
            # Fall back to sequential processing if xargs is not available
            warn "xargs not available for parallel processing, falling back to sequential"
            while IFS= read -r file; do
                if ! bash -c "$command \"$file\"" 2>/dev/null; then
                    warn "Command failed for file: $file"
                    result=1
                fi
            done < "$tempfile"
        fi
    else
        # Run commands sequentially
        while IFS= read -r file; do
            if ! bash -c "$command \"$file\"" 2>/dev/null; then
                warn "Command failed for file: $file"
                result=1
            fi
        done < "$tempfile"
    fi

    secure_remove_file "$tempfile"
    return $result
}

# Authenticate a file access operation against a user's credentials
# Arguments:
#   $1 - Operation type (read, write, execute, delete)
#   $2 - File path
#   $3 - User identity (optional, defaults to current user)
#   $4 - Auth token file or token string (optional)
# Returns:
#   0 if authorized, 1 if not authorized
authenticate_file_access() {
    local operation="$1"
    local file_path="$2"
    local user="${3:-$(whoami)}"
    local token="$4"
    local auth_result=1

    # Check for required parameters
    if [[ -z "$operation" || -z "$file_path" ]]; then
        error_exit "Missing required parameters for authenticate_file_access"
        return 1
    }

    # Validate operation
    case "$operation" in
        read|write|execute|delete)
            # Valid operation
            ;;
        *)
            error_exit "Invalid operation: $operation (must be read, write, execute, or delete)"
            return 1
            ;;
    esac

    # Validate file path for basic security
    if [[ "$file_path" == *".."* || "$file_path" == *"~"* ]]; then
        error_exit "Invalid file path with potentially unsafe components: $file_path"
        return 1
    }

    # Check if current user has permission via operating system
    if [[ -e "$file_path" ]]; then
        case "$operation" in
            read)
                if [[ -r "$file_path" ]]; then
                    auth_result=0
                fi
                ;;
            write)
                if [[ -w "$file_path" ]]; then
                    auth_result=0
                fi
                ;;
            execute)
                if [[ -x "$file_path" ]]; then
                    auth_result=0
                fi
                ;;
            delete)
                if [[ -w "$(dirname "$file_path")" ]]; then
                    auth_result=0
                fi
                ;;
        esac
    else
        # If file doesn't exist, check parent directory permissions for write/create
        if [[ "$operation" == "write" && -w "$(dirname "$file_path")" ]]; then
            auth_result=0
        fi
    fi

    # If OS permissions failed and we have a token, try token-based auth
    if [[ $auth_result -ne 0 && -n "$token" ]]; then
        local token_value="$token"

        # If token points to a file, read it
        if [[ -f "$token" ]]; then
            token_value=$(cat "$token" 2>/dev/null)
        fi

        # Check if token is valid
        if [[ -n "$token_value" ]]; then
            local auth_dir="/etc/cloud-platform/auth"

            # Check if custom authentication hook exists
            if [[ -x "$auth_dir/authenticate_file_hook.sh" ]]; then
                if "$auth_dir/authenticate_file_hook.sh" "$operation" "$file_path" "$user" "$token_value"; then
                    debug "Token-based authentication successful for $user to $operation $file_path"
                    auth_result=0
                fi
            fi
        fi
    fi

    if [[ $auth_result -eq 0 ]]; then
        debug "Authentication successful: $user can $operation $file_path"
    else
        warn "Authentication failed: $user cannot $operation $file_path"
    fi

    return $auth_result
}

# Monitor a directory for changes with configurable actions
# Arguments:
#   $1 - Directory path to monitor
#   $2 - Command to run when changes detected
#   $3 - Polling interval in seconds (optional, defaults to 5)
#   $4 - File pattern to watch (optional, defaults to "*")
#   $5 - Max runtime in seconds (optional, defaults to 3600 - 1 hour)
# Returns: 0 on success, 1 on error
monitor_directory_changes() {
    local dir="$1"
    local command="$2"
    local interval="${3:-5}"
    local pattern="${4:-*}"
    local max_runtime="${5:-3600}"
    local checksum_file
    local start_time
    local current_time

    # Check for required parameters
    if [[ -z "$dir" || -z "$command" ]]; then
        error_exit "Missing required parameters for monitor_directory_changes"
        return 1
    }

    # Validate directory path for basic security
    if [[ "$dir" == *".."* || "$dir" == *"~"* ]]; then
        error_exit "Invalid directory path with potentially unsafe components: $dir"
        return 1
    }

    # Check if directory exists
    if [[ ! -d "$dir" ]]; then
        error_exit "Directory does not exist: $dir"
        return 1
    }

    # Validate numeric parameters
    if ! [[ "$interval" =~ ^[0-9]+$ ]]; then
        warn "Invalid interval: $interval, using default of 5 seconds"
        interval=5
    fi

    if ! [[ "$max_runtime" =~ ^[0-9]+$ ]]; then
        warn "Invalid max runtime: $max_runtime, using default of 3600 seconds"
        max_runtime=3600
    fi

    # Create temporary file for checksums
    checksum_file=$(create_secure_temp "dirmonitor" "$DEFAULT_TEMP_FILE_PERMS")
    if [[ $? -ne 0 || -z "$checksum_file" ]]; then
        error_exit "Failed to create temporary file for directory monitoring"
        return 1
    }

    # Initialize state
    find "$dir" -type f -name "$pattern" -exec sha256sum {} \; 2>/dev/null | sort > "$checksum_file"

    debug "Starting directory monitoring for: $dir (pattern: $pattern)"
    start_time=$(date +%s)

    # Monitor loop
    while true; do
        # Check runtime
        current_time=$(date +%s)
        if ((current_time - start_time >= max_runtime)); then
            debug "Maximum monitoring time reached ($max_runtime seconds)"
            secure_remove_file "$checksum_file"
            return 0
        fi

        # Sleep first to give time for potential immediate changes
        sleep $interval

        # Create new checksum
        local new_checksum_file
        new_checksum_file=$(create_secure_temp "dirmonitor" "$DEFAULT_TEMP_FILE_PERMS")
        if [[ $? -ne 0 || -z "$new_checksum_file" ]]; then
            warn "Failed to create temporary file for checksums"
            continue
        }

        find "$dir" -type f -name "$pattern" -exec sha256sum {} \; 2>/dev/null | sort > "$new_checksum_file"

        # Check for changes
        if ! cmp -s "$checksum_file" "$new_checksum_file"; then
            debug "Changes detected in directory: $dir"

            # Execute command
            if bash -c "$command" > /dev/null 2>&1; then
                debug "Change handler command executed successfully"
            else
                warn "Change handler command failed with exit code $?"
            fi

            # Update checksum file
            mv "$new_checksum_file" "$checksum_file"
        else
            secure_remove_file "$new_checksum_file"
        fi
    done
}

# Export file operations functions and constants
export -f acquire_lock
export -f release_lock
export -f backup_file
export -f ensure_directory
export -f safe_write_file
export -f file_age
export -f is_file_older_than
export -f secure_copy_file
export -f create_secure_temp
export -f secure_remove_file
export -f get_file_hash
export -f verify_file_integrity
export -f find_files
export -f authenticate_file_access
export -f monitor_directory_changes
export -f get_file_operations_utils_version

export DEFAULT_BACKUP_FILE_PERMS
export DEFAULT_TEMP_FILE_PERMS
export DEFAULT_LOCK_FILE_TIMEOUT
export FILE_OPERATIONS_UTILS_VERSION
export FILE_OPERATIONS_UTILS_DATE
