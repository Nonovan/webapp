#!/bin/bash
# String manipulation utilities for testing

# Version tracking
readonly STRING_UTILS_VERSION="1.0.0"
readonly STRING_UTILS_DATE="2023-09-15"

#######################################
# STRING MANIPULATION FUNCTIONS
#######################################

# Escape a string for a specific format
# Arguments:
#   $1 - String to escape
#   $2 - Format (json, xml, csv, regex, shell, sql, url)
# Returns: Escaped string
escape_string() {
  local string="$1"
  local format="${2:-shell}"

  # Handle empty strings gracefully
  if [[ -z "$string" ]]; then
    echo ""
    return 0
  fi

  case "$format" in
    json)
      # JSON escaping
      string="${string//\\/\\\\}"  # Backslash
      string="${string//\"/\\\"}"  # Double quote
      string="${string//	/\\t}"   # Tab
      string="${string//
/\\n}"    # Newline
      string="${string//
/\\r}"    # Carriage return
      string="${string///\\\//}"   # Forward slash
      string="${string//\b/\\b}"   # Backspace
      string="${string//\f/\\f}"   # Form feed
      ;;
    xml)
      # XML escaping
      string="${string//&/&amp;}"  # Ampersand - must be first!
      string="${string//</&lt;}"   # Less than
      string="${string//>/&gt;}"   # Greater than
      string="${string//\"/&quot;}" # Double quote
      string="${string//'/&#39;}"  # Single quote
      ;;
    csv)
      # CSV escaping
      if [[ "$string" == *","* || "$string" == *"\""* || "$string" == *$'\n'* ]]; then
        string="\"${string//\"/\"\"}\""  # Escape quotes by doubling
      fi
      ;;
    regex)
      # Regex escape special characters
      string="${string//\\/\\\\}"
      string="${string//\./\\.}"
      string="${string//\*/\\*}"
      string="${string//\+/\\+}"
      string="${string//\?/\\?}"
      string="${string//\[/\\[}"
      string="${string//\]/\\]}"
      string="${string//\(/\\(}"
      string="${string//\)/\\)}"
      string="${string//\^/\\^}"
      string="${string//\$/\\$}"
      string="${string//\|/\\|}"
      string="${string//\{/\\{}"
      string="${string//\}/\\}}"
      ;;
    shell)
      # Shell command escaping
      string="${string//\\/\\\\}"
      string="${string//\"/\\\"}"
      string="${string//\$/\\\$}"
      string="${string//\`/\\\`}"
      string="${string//!/\\!}"
      string="${string//&/\\&}"
      string="${string//|/\\|}"
      string="${string//;/\\;}"
      string="${string//(/\\(}"
      string="${string//)/\\)}"
      string="${string//</\\<}"
      string="${string//>/\\>}"
      string="${string//*/\\*}"
      string="${string//~/\\~}"
      ;;
    sql)
      # SQL escaping (for use in queries)
      string="${string//\'/\'\'}"  # Escape single quotes by doubling
      ;;
    url)
      # URL encoding
      local encoded=""
      local length=${#string}
      local pos
      for (( pos=0; pos<length; pos++ )); do
        local c="${string:$pos:1}"
        case "$c" in
          [a-zA-Z0-9.~_-])
            encoded+="$c"
            ;;
          *)
            printf -v encoded "%s%%%02X" "$encoded" "'$c"
            ;;
        esac
      done
      string="$encoded"
      ;;
    *)
      # Unknown format, return as-is with warning to stderr if not default
      if [[ "$format" != "shell" ]]; then
        echo "Warning: Unknown escape format '$format', using no escaping" >&2
      fi
      ;;
  esac

  echo -n "$string"
}

# Truncate a string with ellipsis if needed
# Arguments:
#   $1 - String to truncate
#   $2 - Maximum length (optional, default: 80)
#   $3 - Ellipsis character(s) (optional, default: ...)
#   $4 - Truncation position (start|middle|end, optional, default: end)
# Returns: Truncated string
truncate_string() {
  local string="$1"
  local max_length="${2:-80}"
  local ellipsis="${3:-...}"
  local position="${4:-end}"

  # Handle empty strings and invalid max_length
  if [[ -z "$string" || $max_length -le 0 ]]; then
    echo "$string"
    return 0
  fi

  local str_length=${#string}

  # If string is already shorter, return it unchanged
  if [[ $str_length -le $max_length ]]; then
    echo "$string"
    return 0
  fi

  local ellipsis_length=${#ellipsis}

  case "$position" in
    start)
      # Truncate from the start
      echo "${ellipsis}${string:$((str_length - max_length + ellipsis_length))}"
      ;;
    middle)
      # Truncate from the middle
      local first_part_length=$(( (max_length - ellipsis_length) / 2 ))
      local second_part_length=$(( max_length - ellipsis_length - first_part_length ))
      local first_part="${string:0:$first_part_length}"
      local second_part="${string:$((str_length - second_part_length))}"
      echo "${first_part}${ellipsis}${second_part}"
      ;;
    *)
      # Default: truncate from the end
      local truncate_length=$((max_length - ellipsis_length))
      echo "${string:0:$truncate_length}${ellipsis}"
      ;;
  esac
}

# Get a substring
# Arguments:
#   $1 - String
#   $2 - Start position
#   $3 - Length (optional, to end if not specified)
# Returns: Extracted substring
substring() {
  local string="$1"
  local start="$2"
  local length="${3:-}"

  # Handle empty strings
  if [[ -z "$string" ]]; then
    echo ""
    return 0
  fi

  # Handle negative start index
  if [[ $start -lt 0 ]]; then
    # Convert negative index to positive
    local str_length=${#string}
    start=$((str_length + start))

    # If still negative, start from 0
    if [[ $start -lt 0 ]]; then
      start=0
    fi
  fi

  if [[ -z "$length" ]]; then
    echo "${string:$start}"
  else
    # Handle negative length
    if [[ $length -lt 0 ]]; then
      local str_length=${#string}
      local end=$((str_length + length))
      length=$((end - start))

      # If length is negative, return empty string
      if [[ $length -le 0 ]]; then
        echo ""
        return 0
      fi
    fi
    echo "${string:$start:$length}"
  fi
}

# Pad a string to a specific length
# Arguments:
#   $1 - String to pad
#   $2 - Target length
#   $3 - Padding character (optional, default: space)
#   $4 - Direction (left|right|center, optional, default: right)
# Returns: Padded string
pad_string() {
  local string="$1"
  local length="$2"
  local pad="${3:- }"
  local direction="${4:-right}"

  # Validate inputs
  if [[ -z "$length" || ! "$length" =~ ^[0-9]+$ ]]; then
    echo "$string"
    return 1
  fi

  # Use only first character if multiple are provided for padding
  if [[ ${#pad} -gt 1 ]]; then
    pad="${pad:0:1}"
  fi

  local current_length=${#string}

  # If string is already longer, return it unchanged or truncate based on preference
  if [[ $current_length -ge $length ]]; then
    echo "$string"
    return 0
  fi

  local pad_length=$((length - current_length))
  local padding=""

  # Create padding string using printf for better performance
  printf -v padding "%*s" $pad_length ""
  padding="${padding// /$pad}"

  # Apply padding based on direction
  case "$direction" in
    left)
      echo "$padding$string"
      ;;
    center)
      local left_pad=$((pad_length / 2))
      local right_pad=$((pad_length - left_pad))
      local left_padding="${padding:0:$left_pad}"
      local right_padding="${padding:0:$right_pad}"
      echo "$left_padding$string$right_padding"
      ;;
    *)  # right is default
      echo "$string$padding"
      ;;
  esac
}

# Join array elements with a delimiter
# Arguments:
#   $1 - Delimiter
#   $@ - Array elements
# Returns: Joined string
join_array() {
  local delimiter="$1"
  shift

  if [[ $# -eq 0 ]]; then
    return 0
  fi

  local result="$1"
  shift

  for item in "$@"; do
    result="${result}${delimiter}${item}"
  done

  echo "$result"
}

# Create a formatted table row
# Arguments:
#   $1 - Format (text|markdown|html|csv|json)
#   $@ - Cell values
# Returns: Formatted row
format_table_row() {
  local format="$1"
  shift

  # Handle empty row
  if [[ $# -eq 0 ]]; then
    case "$format" in
      html) echo "<tr></tr>" ;;
      json) echo "[]" ;;
      *) echo "" ;;
    esac
    return 0
  fi

  case "$format" in
    markdown)
      join_array " | " "$@"
      ;;
    html)
      local cells=""
      for cell in "$@"; do
        cells+="<td>$(escape_string "$cell" "xml")</td>"
      done
      echo "<tr>$cells</tr>"
      ;;
    csv)
      local csv_cells=()
      for cell in "$@"; do
        csv_cells+=("$(escape_string "$cell" "csv")")
      done
      join_array "," "${csv_cells[@]}"
      ;;
    json)
      local json_items=()
      for cell in "$@"; do
        json_items+=("\"$(escape_string "$cell" "json")\"")
      done
      echo "[$(join_array "," "${json_items[@]}")]"
      ;;
    *)  # text is default
      join_array "  " "$@"
      ;;
  esac
}

# Convert a string to lowercase
# Arguments:
#   $1 - Input string
# Returns: Lowercase string
to_lowercase() {
  local string="$1"
  echo "${string,,}"
}

# Convert a string to uppercase
# Arguments:
#   $1 - Input string
# Returns: Uppercase string
to_uppercase() {
  local string="$1"
  echo "${string^^}"
}

# Trim whitespace from the beginning and end of a string
# Arguments:
#   $1 - Input string
# Returns: Trimmed string
trim_string() {
  local var="$1"
  # Remove leading whitespace characters
  var="${var#"${var%%[![:space:]]*}"}"
  # Remove trailing whitespace characters
  var="${var%"${var##*[![:space:]]}"}"
  echo "$var"
}

# Check if a string contains a substring
# Arguments:
#   $1 - String to search in
#   $2 - Substring to search for
#   $3 - Case sensitivity (optional, true/false, default: true)
# Returns: 0 if contains, 1 if not
string_contains() {
  local string="$1"
  local substring="$2"
  local case_sensitive="${3:-true}"

  if [[ -z "$string" || -z "$substring" ]]; then
    return 1
  fi

  if [[ "$case_sensitive" != "true" ]]; then
    string="${string,,}"
    substring="${substring,,}"
  fi

  if [[ "$string" == *"$substring"* ]]; then
    return 0
  else
    return 1
  fi
}

# Replace all occurrences of a substring with a replacement
# Arguments:
#   $1 - Input string
#   $2 - Substring to replace
#   $3 - Replacement string
#   $4 - Case sensitivity (optional, true/false, default: true)
# Returns: String with replacements
string_replace() {
  local string="$1"
  local search="$2"
  local replace="$3"
  local case_sensitive="${4:-true}"

  if [[ -z "$string" || -z "$search" ]]; then
    echo "$string"
    return 0
  fi

  if [[ "$case_sensitive" != "true" ]]; then
    # Case insensitive replacement is more complex in bash
    # This is a simple implementation that works for basic cases
    local result=""
    local remaining="$string"
    local lower_search="${search,,}"
    local search_len=${#search}

    while [[ -n "$remaining" ]]; do
      local lower_remaining="${remaining,,}"
      local pos="${lower_remaining%%$lower_search*}"

      # If search string not found, append remaining and exit
      if [[ "$pos" == "$lower_remaining" ]]; then
        result+="$remaining"
        break
      fi

      # Append part before match and the replacement
      result+="${remaining:0:${#pos}}$replace"

      # Continue with remaining part
      remaining="${remaining:${#pos}+$search_len}"
    done

    echo "$result"
  else
    # Simple case sensitive replacement
    echo "${string//$search/$replace}"
  fi
}

# Count occurrences of a substring in a string
# Arguments:
#   $1 - String to search in
#   $2 - Substring to count
#   $3 - Case sensitivity (optional, true/false, default: true)
# Returns: Number of occurrences
count_occurrences() {
  local string="$1"
  local substring="$2"
  local case_sensitive="${3:-true}"

  if [[ -z "$string" || -z "$substring" ]]; then
    echo "0"
    return 0
  fi

  if [[ "$case_sensitive" != "true" ]]; then
    string="${string,,}"
    substring="${substring,,}"
  fi

  # Remove all non-matching parts and count remaining length
  local stripped="${string//$substring/}"
  local count=$(( (${#string} - ${#stripped}) / ${#substring} ))
  echo "$count"
}

# Self-test function
self_test() {
  echo "Testing string utility functions..."
  local failed=0

  # Test escape_string
  local result=$(escape_string '<test>&"'"'" "xml")
  if [[ "$result" != "&lt;test&gt;&amp;&quot;&#39;" ]]; then
    echo "FAIL: escape_string XML escaping didn't work correctly"
    echo "Expected: &lt;test&gt;&amp;&quot;&#39;"
    echo "Got: $result"
    ((failed++))
  else
    echo "PASS: escape_string XML"
  fi

  # Test truncate_string
  result=$(truncate_string "This is a very long string to test truncation" 20)
  if [[ "$result" != "This is a very lo..." ]]; then
    echo "FAIL: truncate_string didn't work correctly"
    echo "Expected: This is a very lo..."
    echo "Got: $result"
    ((failed++))
  else
    echo "PASS: truncate_string"
  fi

  # Test substring
  result=$(substring "Testing substring function" 8 9)
  if [[ "$result" != "substring" ]]; then
    echo "FAIL: substring didn't work correctly"
    echo "Expected: substring"
    echo "Got: $result"
    ((failed++))
  else
    echo "PASS: substring"
  fi

  # Test pad_string
  result=$(pad_string "Padding" 10 "-" "left")
  if [[ "$result" != "---Padding" ]]; then
    echo "FAIL: pad_string didn't work correctly"
    echo "Expected: ---Padding"
    echo "Got: $result"
    ((failed++))
  else
    echo "PASS: pad_string"
  fi

  # Test format_table_row
  result=$(format_table_row "markdown" "Column 1" "Column 2" "Column 3")
  if [[ "$result" != "Column 1 | Column 2 | Column 3" ]]; then
    echo "FAIL: format_table_row markdown didn't work correctly"
    echo "Expected: Column 1 | Column 2 | Column 3"
    echo "Got: $result"
    ((failed++))
  else
    echo "PASS: format_table_row markdown"
  fi

  # Test new functions
  result=$(to_uppercase "convert to uppercase")
  if [[ "$result" != "CONVERT TO UPPERCASE" ]]; then
    echo "FAIL: to_uppercase didn't work correctly"
    ((failed++))
  else
    echo "PASS: to_uppercase"
  fi

  result=$(trim_string "  trim spaces  ")
  if [[ "$result" != "trim spaces" ]]; then
    echo "FAIL: trim_string didn't work correctly"
    ((failed++))
  else
    echo "PASS: trim_string"
  fi

  string_contains "Find substring" "substring"
  if [[ $? -ne 0 ]]; then
    echo "FAIL: string_contains didn't work correctly"
    ((failed++))
  else
    echo "PASS: string_contains"
  fi

  result=$(count_occurrences "count multiple count occurrences count" "count")
  if [[ "$result" != "3" ]]; then
    echo "FAIL: count_occurrences didn't work correctly"
    echo "Expected: 3"
    echo "Got: $result"
    ((failed++))
  else
    echo "PASS: count_occurrences"
  fi

  if [[ $failed -eq 0 ]]; then
    echo "All string utility tests passed!"
    return 0
  else
    echo "$failed tests failed!"
    return 1
  fi
}

# Export string utility functions
export -f escape_string
export -f truncate_string
export -f substring
export -f pad_string
export -f join_array
export -f format_table_row
export -f to_lowercase
export -f to_uppercase
export -f trim_string
export -f string_contains
export -f string_replace
export -f count_occurrences

# Run self-test when script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  self_test
  exit $?
fi
