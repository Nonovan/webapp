#!/bin/bash
# filepath: scripts/utils/common/common_file_operations_functions.sh
#######################################
# FILE OPERATIONS FUNCTIONS
#######################################

# Define secure permission constants for file operations
DEFAULT_BACKUP_FILE_PERMS="600"  # Restrictive permissions for backup files
DEFAULT_TEMP_FILE_PERMS="600"    # Restrictive permissions for temporary files

# Create a backup of a file with secure permissions
# Arguments:
#   $1 - File to backup
#   $2 - Backup directory (optional - defaults to DEFAULT_BACKUP_DIR)
#   $3 - Custom permissions (optional - defaults to DEFAULT_BACKUP_FILE_PERMS)
# Returns:
#   Path to backup file on stdout on success, exits with 1 on failure
backup_file() {
    local file="$1"
    local backup_dir="${2:-$DEFAULT_BACKUP_DIR}"
    local perms="${3:-$DEFAULT_BACKUP_FILE_PERMS}"
    local filename=$(basename "$file")
    local backup_file="${backup_dir}/${filename}.${TIMESTAMP}.bak"

    # Ensure backup directory exists with proper permissions
    ensure_directory "$backup_dir" "$DEFAULT_DIR_PERMS" || {
        error_exit "Failed to create backup directory: $backup_dir"
        return 1
    }

    # Check if source file exists
    if [[ ! -f "$file" ]]; then
        error_exit "Cannot backup file, source does not exist: $file"
        return 1
    }

    # Create backup
    cp -p "$file" "$backup_file" 2>/dev/null || {
        error_exit "Failed to create backup of $file to $backup_file"
        return 1
    }

    # Set secure permissions for backup file
    chmod "$perms" "$backup_file" 2>/dev/null || {
        warn "Failed to set permissions $perms on backup file: $backup_file (continuing anyway)"
    }

    debug "Created backup of $file at $backup_file with permissions $perms"
    echo "$backup_file"
    return 0
}

# Create directory if it doesn't exist with proper permissions
# Arguments:
#   $1 - Directory path
#   $2 - Permissions (optional - defaults to DEFAULT_DIR_PERMS)
#   $3 - Owner:Group (optional - format "user:group")
# Returns:
#   0 if created or exists with proper permissions, 1 on failure
ensure_directory() {
    local dir="$1"
    local perms="${2:-$DEFAULT_DIR_PERMS}"
    local owner="${3:-}"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" 2>/dev/null || {
            error_exit "Failed to create directory: $dir"
            return 1
        }

        # Set owner if specified and running as root
        if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
            chown "$owner" "$dir" 2>/dev/null || {
                warn "Failed to set owner $owner for directory: $dir (continuing anyway)"
            }
        }

        # Set permissions
        chmod "$perms" "$dir" 2>/dev/null || {
            error_exit "Failed to set permissions $perms on directory: $dir"
            return 1
        }

        debug "Created directory: $dir with permissions $perms"
    else
        # Directory exists, check if we need to update permissions
        local current_perms
        if command_exists stat; then
            if [[ "$(uname)" == "Darwin" ]]; then
                # macOS version
                current_perms=$(stat -f '%A' "$dir" 2>/dev/null)
            else
                # Linux version
                current_perms=$(stat -c '%a' "$dir" 2>/dev/null)
            fi

            # Check if current permissions match expected
            if [[ "$current_perms" != "$perms" ]]; then
                # Only try to change permissions if we have write access to parent
                if [[ -w "$(dirname "$dir")" ]]; then
                    chmod "$perms" "$dir" 2>/dev/null || {
                        warn "Failed to update permissions on existing directory: $dir (continuing anyway)"
                    }
                    debug "Updated permissions for directory: $dir from $current_perms to $perms"
                }
            }
        }

        # Set owner if specified and running as root
        if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
            if command_exists stat; then
                current_owner=$(stat -c '%U:%G' "$dir" 2>/dev/null || echo "unknown:unknown")
                if [[ "$current_owner" != "$owner" ]]; then
                    chown "$owner" "$dir" 2>/dev/null || {
                        warn "Failed to update owner for directory: $dir (continuing anyway)"
                    }
                    debug "Updated owner for directory: $dir from $current_owner to $owner"
                }
            fi
        }
    fi

    # Check if directory is writable regardless of creation
    if [[ ! -w "$dir" ]]; then
        error_exit "Directory is not writable: $dir"
        return 1
    fi

    return 0
}

# Safely write content to a file with error handling and proper permissions
# Arguments:
#   $1 - Content to write
#   $2 - Output file
#   $3 - Create backup (true/false, defaults to true)
#   $4 - File permissions (optional, defaults to DEFAULT_FILE_PERMS)
#   $5 - Owner:Group (optional - format "user:group")
# Returns: 0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local output_file="$2"
    local create_backup="${3:-true}"
    local perms="${4:-$DEFAULT_FILE_PERMS}"
    local owner="${5:-}"
    local temp_file

    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$output_file")" || {
        error_exit "Failed to ensure parent directory exists for: $output_file"
        return 1
    }

    # Backup existing file if requested
    if [[ "$create_backup" == "true" && -f "$output_file" ]]; then
        backup_file "$output_file" >/dev/null || {
            warn "Failed to back up existing file: $output_file (continuing anyway)"
        }
    }

    # Write to temporary file first to prevent partial writes
    temp_file=$(mktemp) || {
        error_exit "Failed to create temporary file"
        return 1
    }

    # Ensure temp file has restrictive permissions from creation
    chmod "$DEFAULT_TEMP_FILE_PERMS" "$temp_file" 2>/dev/null || {
        warn "Failed to set initial permissions on temporary file"
        # Continue despite warning
    }

    echo "$content" > "$temp_file" || {
        error_exit "Failed to write content to temporary file"
        rm -f "$temp_file"
        return 1
    }

    # Set final permissions on temporary file before moving
    chmod "$perms" "$temp_file" || {
        warn "Failed to set permissions $perms on temporary file (continuing anyway)"
    }

    # Set owner if specified and running as root
    if [[ -n "$owner" && "$(id -u)" -eq 0 ]]; then
        chown "$owner" "$temp_file" 2>/dev/null || {
            warn "Failed to set owner $owner for file (continuing anyway)"
        }
    }

    # Move temporary file to destination (preserves permissions)
    mv "$temp_file" "$output_file" || {
        error_exit "Failed to write to final destination: $output_file"
        rm -f "$temp_file"
        return 1
    }

    debug "Successfully wrote content to $output_file with permissions $perms"
    return 0
}

# Get file age in seconds
# Arguments:
#   $1 - File path
# Returns: File age in seconds on stdout or -1 if file not found/error
file_age() {
    local file="$1"
    local file_time
    local current_time

    if [[ ! -f "$file" ]]; then
        warn "Cannot get age of non-existent file: $file"
        echo "-1"
        return 1
    }

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
        file_time=$(ls -l --time-style=+%s "$file" 2>/dev/null | awk '{print $6}')
    fi

    if [[ -z "$file_time" || ! "$file_time" =~ ^[0-9]+$ ]]; then
        error_exit "Failed to get file modification time: $file"
        echo "-1"
        return 1
    fi

    current_time=$(date +%s)
    echo $((current_time - file_time))
    return 0
}

# Check if file is older than specified time period
# Arguments:
#   $1 - File path
#   $2 - Max age in seconds
# Returns: 0 if file is older than max age or doesn't exist, 1 if file is newer
is_file_older_than() {
    local file="$1"
    local max_age="$2"

    # Validate input
    if [[ -z "$max_age" || ! "$max_age" =~ ^[0-9]+$ ]]; then
        error_exit "Invalid max_age parameter: $max_age (must be a positive number)"
        return 1
    fi

    if [[ ! -f "$file" ]]; then
        # File doesn't exist, consider it "older"
        return 0
    fi

    local age
    age=$(file_age "$file")
    local status=$?

    if [[ $status -ne 0 || "$age" == "-1" ]]; then
        # Error getting age, assume file is too new
        return 1
    fi

    if (( age > max_age )); then
        # File is older than max_age
        return 0
    else
        # File is newer than max_age
        return 1
    fi
}

# Copy a file with proper permissions
# Arguments:
#   $1 - Source file
#   $2 - Destination file
#   $3 - Permissions (optional, defaults to source file permissions or DEFAULT_FILE_PERMS)
#   $4 - Owner:Group (optional - format "user:group")
# Returns: 0 on success, 1 on failure
secure_copy_file() {
    local source="$1"
    local dest="$2"
    local perms="${3:-}"
    local owner="${4:-}"

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
        perms="${perms:-$DEFAULT_FILE_PERMS}"
    fi

    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$dest")" || {
        error_exit "Failed to ensure parent directory exists for: $dest"
        return 1
    }

    # Copy the file
    cp -f "$source" "$dest" || {
        error_exit "Failed to copy file from $source to $dest"
        return 1
    }

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
    return 0
}

# Create a temporary file with secure permissions
# Arguments:
#   $1 - Prefix for temp file name (optional)
#   $2 - Permissions (optional, defaults to DEFAULT_TEMP_FILE_PERMS)
# Returns: Path to temporary file on stdout, or 1 on failure
create_secure_temp() {
    local prefix="${1:-temp}"
    local perms="${2:-$DEFAULT_TEMP_FILE_PERMS}"
    local temp_file
    local temp_dir="/tmp"

    # Ensure temp directory exists and is writable
    if [[ ! -d "$temp_dir" || ! -w "$temp_dir" ]]; then
        temp_dir="."
    fi

    # Create temporary file
    temp_file=$(mktemp "${temp_dir}/${prefix}.XXXXXXXX") || {
        error_exit "Failed to create temporary file with prefix: $prefix"
        return 1
    }

    # Set restrictive permissions
    chmod "$perms" "$temp_file" 2>/dev/null || {
        warn "Failed to set permissions on temporary file: $temp_file (continuing anyway)"
    }

    echo "$temp_file"
    return 0
}

# Securely remove a file (overwrite then delete)
# Arguments:
#   $1 - File to remove
#   $2 - Secure overwrite passes (optional, defaults to 1)
# Returns: 0 on success, 1 on failure
secure_remove_file() {
    local file="$1"
    local passes="${2:-1}"

    if [[ ! -f "$file" ]]; then
        # File doesn't exist, consider it success
        return 0
    fi

    # Validate passes parameter
    if [[ ! "$passes" =~ ^[0-9]+$ ]]; then
        warn "Invalid passes parameter: $passes (must be a non-negative number)"
        passes=1
    fi

    # Check if shred command exists for secure deletion
    if command_exists shred; then
        shred -f -z -u -n "$passes" "$file" 2>/dev/null || {
            warn "Failed to securely shred file: $file, falling back to basic removal"
            rm -f "$file"
        }
    else
        # Fallback if shred is not available
        if [[ "$passes" -gt 0 ]]; then
            # Basic secure deletion: overwrite with random data
            for ((i=1; i<=passes; i++)); do
                if command_exists dd && [[ -r "/dev/urandom" ]]; then
                    dd if=/dev/urandom of="$file" bs=4k conv=notrunc 2>/dev/null || break
                else
                    # Even more basic fallback: overwrite with zeros
                    truncate -s 0 "$file" 2>/dev/null || break
                fi
            done
        fi

        # Remove the file
        rm -f "$file" || {
            error_exit "Failed to remove file: $file"
            return 1
        }
    fi

    debug "Securely removed file: $file"
    return 0
}

# Export file operations functions and constants
export -f backup_file
export -f ensure_directory
export -f safe_write_file
export -f file_age
export -f is_file_older_than
export -f secure_copy_file
export -f create_secure_temp
export -f secure_remove_file
export DEFAULT_BACKUP_FILE_PERMS
export DEFAULT_TEMP_FILE_PERMS
