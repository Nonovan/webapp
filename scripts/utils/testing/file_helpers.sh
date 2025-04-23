#!/bin/bash
# File operation helpers for testing utilities

# Version tracking
readonly FILE_HELPERS_VERSION="1.0.0"

#######################################
# TEMP FILE MANAGEMENT
#######################################

# Create a secure temporary file
# Arguments:
#   $1 - Prefix for temporary file (optional)
#   $2 - Permissions (optional, default: 600)
# Returns:
#   Path to the temporary file
create_secure_temp() {
  local prefix="${1:-temp}"
  local perms="${2:-600}"
  local temp_file

  # Sanitize prefix to prevent command injection
  prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_.-')

  # Check if temp directory exists and is writable
  local temp_dir="/tmp"
  if [[ ! -d "$temp_dir" || ! -w "$temp_dir" ]]; then
    temp_dir="."
  fi

  # Try to use mktemp with advanced options (works on macOS and most Linux)
  if temp_file=$(mktemp -t "${prefix}.XXXXXX" 2>/dev/null); then
    chmod "$perms" "$temp_file" 2>/dev/null
    echo "$temp_file"
    return 0
  fi

  # Standard mktemp fallback (works on most Linux)
  if temp_file=$(mktemp "${temp_dir}/${prefix}.XXXXXX" 2>/dev/null); then
    chmod "$perms" "$temp_file" 2>/dev/null
    echo "$temp_file"
    return 0
  fi

  # Last resort manual creation with improved entropy
  local random_suffix="$$.$RANDOM.$(date +%N 2>/dev/null || echo $RANDOM)"
  temp_file="${temp_dir}/${prefix}.${random_suffix}"

  { touch "$temp_file" && chmod "$perms" "$temp_file"; } 2>/dev/null

  if [[ -f "$temp_file" ]]; then
    echo "$temp_file"
    return 0
  fi

  # Truly last resort - try current directory if not already tried
  if [[ "$temp_dir" != "." ]]; then
    temp_file="./${prefix}.${random_suffix}"
    { touch "$temp_file" && chmod "$perms" "$temp_file"; } 2>/dev/null

    if [[ -f "$temp_file" ]]; then
      echo "$temp_file"
      return 0
    fi
  fi

  # Return empty string if all attempts failed
  echo ""
  return 1
}

# Create temporary directory with proper permissions
# Arguments:
#   $1 - Prefix for temporary directory
#   $2 - Permissions (optional, default: 700)
# Returns:
#   Path to the temporary directory
create_temp_dir() {
  local prefix="${1:-test}"
  local perms="${2:-700}"
  local temp_dir

  # Sanitize prefix
  prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_.-')

  # Check if temp directory exists and is writable
  local base_dir="/tmp"
  if [[ ! -d "$base_dir" || ! -w "$base_dir" ]]; then
    base_dir="."
  fi

  # Try to use mktemp with advanced options (works on macOS and most Linux)
  if temp_dir=$(mktemp -d -t "${prefix}.XXXXXX" 2>/dev/null); then
    chmod "$perms" "$temp_dir" 2>/dev/null
    echo "$temp_dir"
    return 0
  fi

  # Standard mktemp fallback (works on most Linux)
  if temp_dir=$(mktemp -d "${base_dir}/${prefix}.XXXXXX" 2>/dev/null); then
    chmod "$perms" "$temp_dir" 2>/dev/null
    echo "$temp_dir"
    return 0
  fi

  # Manual creation as fallback with improved entropy
  local random_suffix="$$.$RANDOM.$(date +%N 2>/dev/null || echo $RANDOM)"
  temp_dir="${base_dir}/${prefix}.${random_suffix}"

  if mkdir -p "$temp_dir" 2>/dev/null; then
    chmod "$perms" "$temp_dir" 2>/dev/null
    if [[ -d "$temp_dir" && -w "$temp_dir" ]]; then
      echo "$temp_dir"
      return 0
    fi
  fi

  # Last resort - try current directory if not already tried
  if [[ "$base_dir" != "." ]]; then
    temp_dir="./${prefix}.${random_suffix}"
    if mkdir -p "$temp_dir" 2>/dev/null; then
      chmod "$perms" "$temp_dir" 2>/dev/null
      if [[ -d "$temp_dir" && -w "$temp_dir" ]]; then
        echo "$temp_dir"
        return 0
      fi
    fi
  fi

  # Return empty string if all attempts failed
  echo ""
  return 1
}

# Delete a file or directory securely
# Arguments:
#   $1 - Path to file/directory
#   $2 - Number of overwrite passes (optional, default: 1)
# Returns:
#   0 on success, 1 on failure
secure_delete() {
  local path="$1"
  local passes="${2:-1}"

  # Validate inputs
  if [[ -z "$path" ]]; then
    return 1
  fi

  # Safety check to prevent deleting critical directories
  if [[ "$path" == "/" || "$path" == "/bin" || "$path" == "/boot" ||
        "$path" == "/dev" || "$path" == "/etc" || "$path" == "/home" ||
        "$path" == "/lib" || "$path" == "/lib64" || "$path" == "/opt" ||
        "$path" == "/proc" || "$path" == "/root" || "$path" == "/sbin" ||
        "$path" == "/sys" || "$path" == "/tmp" || "$path" == "/usr" ||
        "$path" == "/var" ]]; then
    return 1
  fi

  # Resolve to absolute path if possible
  local resolved_path
  if command -v realpath >/dev/null 2>&1; then
    resolved_path=$(realpath -s "$path" 2>/dev/null || echo "$path")
  else
    resolved_path="$path"
  fi

  # Different handling for files vs directories
  if [[ -d "$resolved_path" ]]; then
    # Find all files and securely overwrite them
    if command -v find >/dev/null 2>&1; then
      find "$resolved_path" -type f -print0 2>/dev/null | while IFS= read -r -d '' file; do
        _secure_delete_file "$file" "$passes"
      done
    fi
    # Remove directory
    rm -rf "$resolved_path" 2>/dev/null
  elif [[ -f "$resolved_path" ]]; then
    _secure_delete_file "$resolved_path" "$passes"
  fi

  # Verify deletion
  [[ ! -e "$resolved_path" ]]
}

# Helper function to securely delete a file
# Arguments:
#   $1 - File path
#   $2 - Number of passes
# Returns:
#   0 on success, 1 on failure
_secure_delete_file() {
  local file="$1"
  local passes="${2:-1}"

  # Ensure file exists and is writable
  if [[ ! -f "$file" ]]; then
    return 1
  fi

  if [[ ! -w "$file" ]]; then
    chmod u+w "$file" 2>/dev/null || return 1
  fi

  # Try to use shred
  if command -v shred >/dev/null 2>&1; then
    shred -u -n "$passes" "$file" 2>/dev/null
    return $?
  fi

  # Manual overwrite fallback
  local filesize
  filesize=$(stat -c %s "$file" 2>/dev/null ||
             stat -f %z "$file" 2>/dev/null ||
             wc -c < "$file" 2>/dev/null ||
             echo 0)

  if [[ $filesize -gt 0 ]]; then
    for ((i=0; i<passes; i++)); do
      # Overwrite with random data
      dd if=/dev/urandom of="$file" bs=8k count=$((filesize / 8192 + 1)) conv=notrunc >/dev/null 2>&1 || true
      # Overwrite with zeros
      dd if=/dev/zero of="$file" bs=8k count=$((filesize / 8192 + 1)) conv=notrunc >/dev/null 2>&1 || true
      sync 2>/dev/null || true
    done
  fi

  # Finally remove the file
  rm -f "$file" 2>/dev/null
  return $?
}

# Write content to a file safely
# Arguments:
#   $1 - Content to write
#   $2 - File path
#   $3 - Permissions (optional, default: 644)
# Returns:
#   0 on success, 1 on failure
safe_write() {
  local content="$1"
  local file_path="$2"
  local perms="${3:-644}"

  # Validate inputs
  if [[ -z "$file_path" ]]; then
    return 1
  fi

  # Create directory if it doesn't exist
  local dir_path
  dir_path=$(dirname "$file_path")
  if [[ ! -d "$dir_path" ]]; then
    mkdir -p "$dir_path" 2>/dev/null || return 1
  fi

  # Use atomic write pattern with temp file
  local temp_file
  temp_file=$(create_secure_temp "$(basename "$file_path")")

  if [[ -z "$temp_file" ]]; then
    return 1
  fi

  # Write content to temp file
  if ! printf "%s\n" "$content" > "$temp_file"; then
    secure_delete "$temp_file"
    return 1
  fi

  # Set permissions before moving
  chmod "$perms" "$temp_file" 2>/dev/null

  # Move temp file to final destination
  if ! mv "$temp_file" "$file_path"; then
    secure_delete "$temp_file"
    return 1
  fi

  return 0
}

# Read file content safely
# Arguments:
#   $1 - File path
# Returns:
#   File content on stdout, 1 on failure
safe_read() {
  local file_path="$1"

  # Validate file exists and is readable
  if [[ ! -f "$file_path" || ! -r "$file_path" ]]; then
    return 1
  fi

  # Use cat for most cases
  if command -v cat >/dev/null 2>&1; then
    cat "$file_path" 2>/dev/null
    return $?
  fi

  # Fallback to while loop reading
  while IFS= read -r line; do
    echo "$line"
  done < "$file_path"
}

# Check if a file exists and matches a specific pattern
# Arguments:
#   $1 - File path
#   $2 - Pattern to search for (grep pattern)
# Returns:
#   0 if found, 1 if not found or error
file_contains() {
  local file_path="$1"
  local pattern="$2"

  # Validate file exists and is readable
  if [[ ! -f "$file_path" || ! -r "$file_path" ]]; then
    return 1
  fi

  if command -v grep >/dev/null 2>&1; then
    grep -q "$pattern" "$file_path" 2>/dev/null
    return $?
  fi

  # Fallback if grep is not available
  while IFS= read -r line; do
    if [[ "$line" == *"$pattern"* ]]; then
      return 0
    fi
  done < "$file_path"

  return 1
}

# Self-test function - tests the helper functions when script is executed directly
# Returns:
#   0 on success, 1 on failure
self_test() {
  echo "Testing file_helpers.sh functions..."

  # Test create_secure_temp
  local temp_file
  temp_file=$(create_secure_temp "test_file")
  if [[ -z "$temp_file" || ! -f "$temp_file" ]]; then
    echo "FAIL: create_secure_temp did not create a valid file"
    return 1
  fi
  echo "PASS: create_secure_temp created: $temp_file"

  # Test safe_write
  if ! safe_write "Hello, world!" "$temp_file"; then
    echo "FAIL: safe_write failed"
    secure_delete "$temp_file"
    return 1
  fi
  echo "PASS: safe_write successfully wrote to file"

  # Test safe_read
  local content
  content=$(safe_read "$temp_file")
  if [[ "$content" != "Hello, world!" ]]; then
    echo "FAIL: safe_read returned incorrect content: $content"
    secure_delete "$temp_file"
    return 1
  fi
  echo "PASS: safe_read read content correctly"

  # Test file_contains
  if ! file_contains "$temp_file" "Hello"; then
    echo "FAIL: file_contains did not find 'Hello' in file"
    secure_delete "$temp_file"
    return 1
  fi
  echo "PASS: file_contains found expected pattern"

  # Test create_temp_dir
  local temp_dir
  temp_dir=$(create_temp_dir "test_dir")
  if [[ -z "$temp_dir" || ! -d "$temp_dir" ]]; then
    echo "FAIL: create_temp_dir did not create a valid directory"
    secure_delete "$temp_file"
    return 1
  fi
  echo "PASS: create_temp_dir created: $temp_dir"

  # Test secure_delete on file
  if ! secure_delete "$temp_file"; then
    echo "FAIL: secure_delete did not delete the file"
    rm -f "$temp_file" 2>/dev/null
    secure_delete "$temp_dir"
    return 1
  fi
  if [[ -e "$temp_file" ]]; then
    echo "FAIL: File still exists after secure_delete"
    rm -f "$temp_file" 2>/dev/null
    secure_delete "$temp_dir"
    return 1
  fi
  echo "PASS: secure_delete successfully deleted file"

  # Test secure_delete on directory
  if ! secure_delete "$temp_dir"; then
    echo "FAIL: secure_delete did not delete the directory"
    rm -rf "$temp_dir" 2>/dev/null
    return 1
  fi
  if [[ -e "$temp_dir" ]]; then
    echo "FAIL: Directory still exists after secure_delete"
    rm -rf "$temp_dir" 2>/dev/null
    return 1
  fi
  echo "PASS: secure_delete successfully deleted directory"

  echo "All file_helpers.sh tests passed!"
  return 0
}

# Export file operation functions
export -f create_secure_temp
export -f create_temp_dir
export -f secure_delete
export -f safe_write
export -f safe_read
export -f file_contains

# Run self-test when script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  self_test
  exit $?
fi
