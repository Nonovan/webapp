#!/bin/bash
# Array manipulation utilities for testing

# Version tracking
readonly ARRAY_UTILS_VERSION="1.1.0"
readonly ARRAY_UTILS_DATE="2023-09-20"

#######################################
# ARRAY MANIPULATION FUNCTIONS
#######################################

# Join array elements with a delimiter
# Arguments:
#   $1 - Delimiter
#   $@ - Array elements
# Returns: Joined string
join_array() {
  local delimiter="$1"
  shift

  # Handle empty array case more efficiently
  if [[ $# -eq 0 ]]; then
    return 0
  fi

  # Use first element directly without conditionals
  local result="$1"
  shift

  # Join remaining elements
  for item in "$@"; do
    result="${result}${delimiter}${item}"
  done

  echo "$result"
}

# Convert a string to an array
# Arguments:
#   $1 - String to convert
#   $2 - Delimiter (optional, default: space)
# Sets: RETURN_ARRAY variable
string_to_array() {
  local input="$1"
  local delimiter="${2:- }"

  # Initialize return array
  RETURN_ARRAY=()

  # Check for empty input
  if [[ -z "$input" ]]; then
    return 0
  fi

  # Special processing for different delimiters
  if [[ "$delimiter" == " " ]]; then
    # Simple space-separated words
    read -ra RETURN_ARRAY <<< "$input"
  else
    # For custom delimiters, use a more robust approach
    local IFS="$delimiter"
    read -ra RETURN_ARRAY <<< "$input"
  fi
}

# Filter array for items matching a pattern
# Arguments:
#   $1 - Search pattern
#   $2 - (Optional) Case sensitivity (true/false, default: true)
#   $@ - Array to search in
# Sets: RETURN_ARRAY with matching items
filter_array() {
  local pattern="$1"
  local case_sensitive="true"

  # Check if second param is a case sensitivity flag
  if [[ "$2" == "true" || "$2" == "false" ]]; then
    case_sensitive="$2"
    shift 2
  else
    shift 1
  fi

  RETURN_ARRAY=()

  for item in "$@"; do
    local match=false

    if [[ "$case_sensitive" == "true" ]]; then
      # Case-sensitive matching
      if [[ "$item" == *"$pattern"* ]]; then
        match=true
      fi
    else
      # Case-insensitive matching
      if [[ "${item,,}" == *"${pattern,,}"* ]]; then
        match=true
      fi
    fi

    if [[ "$match" == "true" ]]; then
      RETURN_ARRAY+=("$item")
    fi
  done
}

# Find index of an item in array
# Arguments:
#   $1 - Item to find
#   $2 - (Optional) Case sensitivity (true/false, default: true)
#   $@ - Array to search in
# Returns: Index if found, -1 if not found
array_index_of() {
  local item="$1"
  local case_sensitive="true"

  # Check if second param is a case sensitivity flag
  if [[ "$2" == "true" || "$2" == "false" ]]; then
    case_sensitive="$2"
    shift 2
  else
    shift 1
  fi

  local i=0
  for element in "$@"; do
    local match=false

    if [[ "$case_sensitive" == "true" ]]; then
      # Case-sensitive comparison
      if [[ "$element" == "$item" ]]; then
        match=true
      fi
    else
      # Case-insensitive comparison
      if [[ "${element,,}" == "${item,,}" ]]; then
        match=true
      fi
    fi

    if [[ "$match" == "true" ]]; then
      echo "$i"
      return 0
    fi
    ((i++))
  done

  echo "-1"
}

# Sort an array
# Arguments:
#   $1 - (Optional) Sort options (e.g., -n for numeric sort)
#   $@ - Array to sort
# Sets: RETURN_ARRAY with sorted items
sort_array() {
  RETURN_ARRAY=()
  local sort_opts=""

  # Check if first arg is sort options
  if [[ "$1" == -* && "$1" != "-"* ]]; then
    sort_opts="$1"
    shift
  fi

  # Use process substitution and readarray for sorting
  if [[ $# -gt 0 ]]; then
    # Check if sort command exists and supports the options
    if command -v sort >/dev/null 2>&1; then
      if [[ -z "$sort_opts" ]]; then
        readarray -t RETURN_ARRAY < <(printf '%s\n' "$@" | sort)
      else
        readarray -t RETURN_ARRAY < <(printf '%s\n' "$@" | sort $sort_opts 2>/dev/null || sort)
      fi
    else
      # Fallback to simple bubble sort for numeric arrays
      RETURN_ARRAY=("$@")
      local n=${#RETURN_ARRAY[@]}
      local swapped=true

      while [[ "$swapped" == "true" ]]; do
        swapped=false
        for ((i=1; i<n; i++)); do
          if [[ "${RETURN_ARRAY[$i-1]}" > "${RETURN_ARRAY[$i]}" ]]; then
            local temp="${RETURN_ARRAY[$i-1]}"
            RETURN_ARRAY[$i-1]="${RETURN_ARRAY[$i]}"
            RETURN_ARRAY[$i]="$temp"
            swapped=true
          fi
        done
        ((n--))
      done
    fi
  fi
}

# Remove duplicates from an array
# Arguments:
#   $@ - Input array
# Sets: RETURN_ARRAY with unique items
unique_array() {
  RETURN_ARRAY=()
  local seen=()

  for item in "$@"; do
    local duplicate=false

    for existing in "${seen[@]}"; do
      if [[ "$existing" == "$item" ]]; then
        duplicate=true
        break
      fi
    done

    if [[ "$duplicate" == "false" ]]; then
      RETURN_ARRAY+=("$item")
      seen+=("$item")
    fi
  done
}

# Get array length
# Arguments:
#   $@ - Array to measure
# Returns: Number of elements in array
array_length() {
  echo "$#"
}

# Check if array contains a value
# Arguments:
#   $1 - Item to find
#   $2 - (Optional) Case sensitivity (true/false, default: true)
#   $@ - Array to search in
# Returns: 0 if found, 1 if not found
array_contains() {
  local item="$1"
  local case_sensitive="true"

  # Check if second param is a case sensitivity flag
  if [[ "$2" == "true" || "$2" == "false" ]]; then
    case_sensitive="$2"
    shift 2
  else
    shift 1
  fi

  for element in "$@"; do
    if [[ "$case_sensitive" == "true" ]]; then
      # Case-sensitive comparison
      if [[ "$element" == "$item" ]]; then
        return 0
      fi
    else
      # Case-insensitive comparison
      if [[ "${element,,}" == "${item,,}" ]]; then
        return 0
      fi
    fi
  done

  return 1
}

# Build a command array with proper escaping
# Arguments:
#   $@ - Command and arguments
# Sets: RETURN_CMD array
build_command() {
  RETURN_CMD=("$@")
}

# Add argument to command array conditionally
# Arguments:
#   $1 - Condition (true/false)
#   $@ - Arguments to add if condition is true
# Modifies: RETURN_CMD array
add_conditional_arg() {
  local condition="$1"
  shift

  if [[ "$condition" == "true" ]]; then
    RETURN_CMD+=("$@")
  fi
}

# Add key-value argument to command array conditionally
# Arguments:
#   $1 - Condition (true/false)
#   $2 - Argument name (e.g., --output)
#   $3 - Argument value
# Modifies: RETURN_CMD array
add_conditional_key_value() {
  local condition="$1"
  local key="$2"
  local value="$3"

  if [[ "$condition" == "true" && -n "$value" ]]; then
    RETURN_CMD+=("$key" "$value")
  fi
}

# Execute a command from array
# Arguments:
#   $@ - Command array
# Returns: Command's exit code
execute_array_command() {
  "$@"
}

# Get a subarray (slice) from an array
# Arguments:
#   $1 - Start index (0-based)
#   $2 - Length (optional, default: to end of array)
#   $@ - Source array
# Sets: RETURN_ARRAY with the slice
array_slice() {
  local start="$1"
  local length="$2"
  shift 2

  RETURN_ARRAY=()

  # Validate start index
  if [[ ! "$start" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  # Handle negative start index
  if [[ $start -lt 0 ]]; then
    start=$((${#@} + start))
    if [[ $start -lt 0 ]]; then
      start=0
    fi
  fi

  # If start is past the end of the array, return empty
  if [[ $start -ge $# ]]; then
    return 0
  fi

  # Skip elements before start index
  for ((i=0; i<start; i++)); do
    shift
  done

  # If length is specified and valid
  if [[ -n "$length" && "$length" =~ ^[0-9]+$ ]]; then
    # Take only 'length' elements
    for ((i=0; i<length && $# -gt 0; i++)); do
      RETURN_ARRAY+=("$1")
      shift
    done
  else
    # Take all remaining elements
    RETURN_ARRAY=("$@")
  fi
}

# Self-test function
# Tests the functionality of each array utility function
# Returns: 0 if all tests pass, 1 otherwise
self_test() {
  echo "Testing array utilities..."
  local failures=0

  # Test join_array
  local joined=$(join_array "," "apple" "banana" "cherry")
  if [[ "$joined" == "apple,banana,cherry" ]]; then
    echo "PASS: join_array"
  else
    echo "FAIL: join_array returned: $joined"
    ((failures++))
  fi

  # Test empty join_array
  local empty_joined=$(join_array "," "")
  if [[ "$empty_joined" == "" ]]; then
    echo "PASS: join_array with empty string"
  else
    echo "FAIL: join_array with empty string returned: $empty_joined"
    ((failures++))
  fi

  # Test string_to_array
  string_to_array "one two three"
  if [[ ${#RETURN_ARRAY[@]} -eq 3 && "${RETURN_ARRAY[0]}" == "one" ]]; then
    echo "PASS: string_to_array with spaces"
  else
    echo "FAIL: string_to_array with spaces returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test string_to_array with custom delimiter
  string_to_array "red,green,blue" ","
  if [[ ${#RETURN_ARRAY[@]} -eq 3 && "${RETURN_ARRAY[1]}" == "green" ]]; then
    echo "PASS: string_to_array with comma"
  else
    echo "FAIL: string_to_array with comma returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test filter_array
  filter_array "app" "apple" "banana" "application" "cherry"
  if [[ ${#RETURN_ARRAY[@]} -eq 2 && "${RETURN_ARRAY[0]}" == "apple" && "${RETURN_ARRAY[1]}" == "application" ]]; then
    echo "PASS: filter_array"
  else
    echo "FAIL: filter_array returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test case-insensitive filter_array
  filter_array "APP" "false" "apple" "banana" "APPle" "cherry"
  if [[ ${#RETURN_ARRAY[@]} -eq 2 && "${RETURN_ARRAY[0]}" == "apple" && "${RETURN_ARRAY[1]}" == "APPle" ]]; then
    echo "PASS: case-insensitive filter_array"
  else
    echo "FAIL: case-insensitive filter_array returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test array_index_of
  local index=$(array_index_of "banana" "apple" "banana" "cherry")
  if [[ "$index" == "1" ]]; then
    echo "PASS: array_index_of"
  else
    echo "FAIL: array_index_of returned: $index"
    ((failures++))
  fi

  # Test array_index_of not found
  local not_found=$(array_index_of "orange" "apple" "banana" "cherry")
  if [[ "$not_found" == "-1" ]]; then
    echo "PASS: array_index_of not found"
  else
    echo "FAIL: array_index_of not found returned: $not_found"
    ((failures++))
  fi

  # Test sort_array
  sort_array "cherry" "banana" "apple"
  if [[ ${#RETURN_ARRAY[@]} -eq 3 && "${RETURN_ARRAY[0]}" == "apple" && "${RETURN_ARRAY[2]}" == "cherry" ]]; then
    echo "PASS: sort_array"
  else
    echo "FAIL: sort_array returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test sort_array with options
  sort_array "-n" "10" "2" "1"
  if [[ ${#RETURN_ARRAY[@]} -eq 3 && "${RETURN_ARRAY[0]}" == "1" && "${RETURN_ARRAY[2]}" == "10" ]]; then
    echo "PASS: sort_array with numeric option"
  else
    echo "FAIL: sort_array with numeric option returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test unique_array
  unique_array "apple" "banana" "apple" "cherry" "banana"
  if [[ ${#RETURN_ARRAY[@]} -eq 3 && "${RETURN_ARRAY[0]}" == "apple" && "${RETURN_ARRAY[1]}" == "banana" && "${RETURN_ARRAY[2]}" == "cherry" ]]; then
    echo "PASS: unique_array"
  else
    echo "FAIL: unique_array returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test array_length
  local length=$(array_length "apple" "banana" "cherry")
  if [[ "$length" == "3" ]]; then
    echo "PASS: array_length"
  else
    echo "FAIL: array_length returned: $length"
    ((failures++))
  fi

  # Test array_contains
  if array_contains "banana" "apple" "banana" "cherry"; then
    echo "PASS: array_contains found element"
  else
    echo "FAIL: array_contains did not find element"
    ((failures++))
  fi

  # Test array_contains not found
  if ! array_contains "orange" "apple" "banana" "cherry"; then
    echo "PASS: array_contains correctly did not find element"
  else
    echo "FAIL: array_contains found element that should not exist"
    ((failures++))
  fi

  # Test array_slice
  array_slice 1 2 "apple" "banana" "cherry" "date"
  if [[ ${#RETURN_ARRAY[@]} -eq 2 && "${RETURN_ARRAY[0]}" == "banana" && "${RETURN_ARRAY[1]}" == "cherry" ]]; then
    echo "PASS: array_slice with start and length"
  else
    echo "FAIL: array_slice returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test array_slice to end
  array_slice 2 "" "apple" "banana" "cherry" "date"
  if [[ ${#RETURN_ARRAY[@]} -eq 2 && "${RETURN_ARRAY[0]}" == "cherry" && "${RETURN_ARRAY[1]}" == "date" ]]; then
    echo "PASS: array_slice to end"
  else
    echo "FAIL: array_slice to end returned: ${RETURN_ARRAY[*]}"
    ((failures++))
  fi

  # Test build_command and add_conditional_arg
  build_command "echo" "hello"
  add_conditional_arg "true" "world"
  add_conditional_arg "false" "skipped"
  if [[ ${#RETURN_CMD[@]} -eq 3 && "${RETURN_CMD[0]}" == "echo" && "${RETURN_CMD[2]}" == "world" ]]; then
    echo "PASS: build_command and add_conditional_arg"
  else
    echo "FAIL: build_command and add_conditional_arg returned: ${RETURN_CMD[*]}"
    ((failures++))
  fi

  # Test add_conditional_key_value
  build_command "curl"
  add_conditional_key_value "true" "--output" "file.txt"
  add_conditional_key_value "false" "--silent" "true"
  if [[ ${#RETURN_CMD[@]} -eq 3 && "${RETURN_CMD[1]}" == "--output" && "${RETURN_CMD[2]}" == "file.txt" ]]; then
    echo "PASS: add_conditional_key_value"
  else
    echo "FAIL: add_conditional_key_value returned: ${RETURN_CMD[*]}"
    ((failures++))
  fi

  if [[ $failures -eq 0 ]]; then
    echo "All array_utils.sh tests passed!"
    return 0
  else
    echo "$failures test(s) failed!"
    return 1
  fi
}

# Export array utility functions
export -f join_array
export -f string_to_array
export -f filter_array
export -f array_index_of
export -f sort_array
export -f unique_array
export -f array_length
export -f array_contains
export -f build_command
export -f add_conditional_arg
export -f add_conditional_key_value
export -f execute_array_command
export -f array_slice

# When executed directly, run self-test
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  self_test
  exit $?
fi
