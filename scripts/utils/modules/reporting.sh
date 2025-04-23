#!/bin/bash
# filepath: scripts/utils/modules/reporting.sh
#
# Reporting module for test utilities
#
# This module provides simplified report generation functionality in various formats
# including text, JSON, and JUnit XML. It uses a data-driven approach to reduce code
# duplication and make the reporting system more maintainable.
#
# Part of: Cloud Infrastructure Platform - Testing Framework
#
# Usage: source "$(dirname "$0")/reporting.sh"
#
# Version: 1.0.0
# Date: 2023-12-20

# Set strict error handling
set -o pipefail
set -o nounset

# Script version for tracking changes
readonly REPORTING_MODULE_VERSION="1.0.0"
readonly REPORTING_MODULE_DATE="2023-12-20"

# Script locations with robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"

# Load core module if available
CORE_MODULE="${MODULES_DIR}/core.sh"
if [[ -f "$CORE_MODULE" ]]; then
  # shellcheck source=./core.sh
  source "$CORE_MODULE"
fi

# Basic logging if core module not available
if ! command -v log &> /dev/null; then
  log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >&2
  }

  # Compatibility with different log function signatures
  log_info() { log "INFO" "$1"; }
  log_error() { log "ERROR" "$1"; }
  log_debug() { log "DEBUG" "$1"; }
  log_warn() { log "WARN" "$1"; }
fi

# Color constants if available
if [[ -z "${GREEN:-}" ]]; then
  readonly RED='\033[0;31m'
  readonly GREEN='\033[0;32m'
  readonly YELLOW='\033[0;33m'
  readonly BLUE='\033[0;34m'
  readonly NC='\033[0m' # No Color
fi

#######################################
# DATA STRUCTURES
#######################################

# Variables that will be set from the main test_utils.sh
TEST_RESULTS=("${TEST_RESULTS[@]:-}")
TEST_GROUPS=("${TEST_GROUPS[@]:-}")
COVERAGE_DATA=("${COVERAGE_DATA[@]:-}")
TESTS_TOTAL=${TESTS_TOTAL:-0}
TESTS_PASSED=${TESTS_PASSED:-0}
TESTS_FAILED=${TESTS_FAILED:-0}
TESTS_SKIPPED=${TESTS_SKIPPED:-0}
TEST_TOTAL_TIME=${TEST_TOTAL_TIME:-0}

# Default configuration values
DEFAULT_REPORT_FORMAT="text"
DEFAULT_REPORT_DIR="${REPORT_DIR:-./reports}"
DEFAULT_REPORT_FILE_PERMS="644"

#######################################
# HELPER FUNCTIONS
#######################################

# Create a temporary directory with proper error handling
# Returns: Path to the temporary directory
create_report_temp_dir() {
  local temp_dir
  temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'test_report_temp')

  if [[ ! -d "$temp_dir" ]]; then
    log_error "Failed to create temporary directory for report"
    return 1
  fi

  # Set secure permissions
  chmod 700 "$temp_dir" 2>/dev/null

  echo "$temp_dir"
}

# Safely write to a file, ensuring parent directory exists
# Arguments:
#   $1 - Path to write to
#   $2 - Content to write (optional, reads from stdin if not provided)
#   $3 - Permissions (optional, default: 644)
# Returns: 0 on success, 1 on failure
safe_write() {
  local target_file="$1"
  local content="${2:-}"
  local perms="${3:-$DEFAULT_REPORT_FILE_PERMS}"

  # Create directory if it doesn't exist
  local dir_path
  dir_path=$(dirname "$target_file")

  if [[ ! -d "$dir_path" ]]; then
    mkdir -p "$dir_path" || {
      log_error "Failed to create directory: $dir_path"
      return 1
    }
  fi

  # Write content to file
  if [[ -n "$content" ]]; then
    printf "%s\n" "$content" > "$target_file" || {
      log_error "Failed to write to file: $target_file"
      return 1
    }
  else
    cat > "$target_file" || {
      log_error "Failed to write to file: $target_file"
      return 1
    }
  fi

  # Set permissions on the file
  chmod "$perms" "$target_file" 2>/dev/null || {
    log_warn "Failed to set permissions $perms on file: $target_file"
    # Continue anyway
  }

  return 0
}

# Process test results and group them by test group
# Arguments:
#   None (uses global TEST_RESULTS array)
# Returns: Writes grouped results to stdout
get_grouped_results() {
  local -A grouped_results=()
  local -a groups=()

  # Handle empty TEST_RESULTS gracefully
  if [[ ${#TEST_RESULTS[@]:-0} -eq 0 ]]; then
    log_debug "No test results to process"
    # Return empty group list
    echo ""
    return 0
  fi

  # First pass: identify all groups
  for result in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r name _ _ _ <<< "$result"

    # Skip empty results
    [[ -z "$name" ]] && continue

    local group="ungrouped"
    if [[ "$name" == *": "* ]]; then
      group="${name%%: *}"
    fi

    # Add to known groups if new
    if [[ -z "${grouped_results[$group]:-}" ]]; then
      grouped_results["$group"]=""
      groups+=("$group")
    fi

    # Append this result to the group
    grouped_results["$group"]+="$result"$'\n'
  done

  # Return both the groups and their contents
  echo "${groups[*]}"
  for group in "${groups[@]}"; do
    echo "$group:::${grouped_results[$group]}"
  done
}

# Get unique files from coverage data
# Arguments:
#   None (uses global COVERAGE_DATA array)
# Returns: Writes unique file paths to stdout
get_unique_coverage_files() {
  local -A unique_files=()
  local -a files=()

  # Handle empty COVERAGE_DATA gracefully
  if [[ ${#COVERAGE_DATA[@]:-0} -eq 0 ]]; then
    log_debug "No coverage data to process"
    return 0
  fi

  for file in "${COVERAGE_DATA[@]}"; do
    if [[ -n "$file" && -z "${unique_files[$file]:-}" ]]; then
      unique_files["$file"]=1
      files+=("$file")
    fi
  done

  # Return array of unique files
  for file in "${files[@]}"; do
    echo "$file"
  done
}

# Escape special characters for XML
# Arguments:
#   $1 - String to escape
# Returns: Escaped string
xml_escape() {
  local string="${1:-}"
  string="${string//&/&amp;}"
  string="${string//</&lt;}"
  string="${string//>/&gt;}"
  string="${string//\"/&quot;}"
  string="${string//\'/&apos;}"
  echo "$string"
}

# Escape special characters for JSON
# Arguments:
#   $1 - String to escape
# Returns: Escaped string
json_escape() {
  local string="${1:-}"
  string="${string//\\/\\\\}"
  string="${string//\"/\\\"}"
  string="${string//	/\\t}"
  string="${string//$'\n'/\\n}"
  string="${string//$'\r'/\\r}"
  echo "$string"
}

# Clean up temporary files
# Arguments:
#   $1 - File or directory to remove
# Returns: 0 on success
cleanup_temp_files() {
  local path="${1:-}"

  if [[ -z "$path" ]]; then
    return 0
  fi

  if [[ -e "$path" ]]; then
    if [[ -f "$path" ]]; then
      rm -f "$path" 2>/dev/null || log_warn "Failed to remove temporary file: $path"
    elif [[ -d "$path" ]]; then
      # Security check - only remove directories that appear to be temporary
      if [[ "$path" == */tmp/* || "$path" == */temp/* || "$path" == *test_report_temp* ]]; then
        rm -rf "$path" 2>/dev/null || log_warn "Failed to remove temporary directory: $path"
      else
        log_warn "Refusing to remove directory that doesn't look temporary: $path"
      fi
    fi
  fi

  return 0
}

#######################################
# REPORT GENERATION - COMMON INTERFACE
#######################################

# Generate a test report
# Arguments:
#   $1 - Output format (text, json, junit)
#   $2 - Output file path (optional)
# Returns: 0 on success, 1 on failure
generate_report() {
  local format="${1:-$DEFAULT_REPORT_FORMAT}"
  local output_file="${2:-}"
  local result=0

  log_debug "Generating ${format} report${output_file:+ to $output_file}"

  # Validate format
  case "$format" in
    text|json|junit|xml)
      # Valid format
      ;;
    *)
      log_warn "Unknown report format: $format, defaulting to text"
      format="text"
      ;;
  esac

  # Ensure output directory exists if output file is specified
  if [[ -n "$output_file" ]]; then
    local output_dir
    output_dir=$(dirname "$output_file")
    if [[ ! -d "$output_dir" ]]; then
      mkdir -p "$output_dir" || {
        log_error "Failed to create output directory: $output_dir"
        return 1
      }
    fi
  fi

  # Prepare report data (common for all formats)
  local report_data
  report_data=$(prepare_report_data)
  result=$?

  if [[ $result -ne 0 || -z "$report_data" ]]; then
    log_error "Failed to prepare report data"
    return 1
  fi

  # Generate report based on format
  case "$format" in
    json)
      generate_json_from_data "$report_data" "$output_file"
      result=$?
      ;;
    junit|xml)
      generate_junit_from_data "$report_data" "$output_file"
      result=$?
      ;;
    *)
      generate_text_from_data "$report_data" "$output_file"
      result=$?
      ;;
  esac

  # Clean up the data file
  cleanup_temp_files "$(dirname "$report_data")"

  return $result
}

# Prepare report data in a common format that all generators can use
# Arguments:
#   None (uses global test variables)
# Returns: Path to the file containing prepared data
prepare_report_data() {
  local temp_dir
  temp_dir=$(create_report_temp_dir) || return 1

  local data_file="${temp_dir}/report_data.txt"

  # Write summary data
  {
    echo "SUMMARY:BEGIN"
    echo "timestamp:$(date -u "+%Y-%m-%dT%H:%M:%SZ")"
    echo "total:$TESTS_TOTAL"
    echo "passed:$TESTS_PASSED"
    echo "failed:$TESTS_FAILED"
    echo "skipped:$TESTS_SKIPPED"
    echo "time:$TEST_TOTAL_TIME"
    echo "SUMMARY:END"

    # Write test results grouped by test group
    echo "GROUPS:BEGIN"
    get_grouped_results
    echo "GROUPS:END"

    # Write coverage data
    echo "COVERAGE:BEGIN"
    get_unique_coverage_files
    echo "COVERAGE:END"

  } > "$data_file" || {
    log_error "Failed to write to data file: $data_file"
    cleanup_temp_files "$temp_dir"
    return 1
  }

  echo "$data_file"
}

# Parse the common report data into variables
# Arguments:
#   $1 - Path to data file
#   $2... - Names of variables to receive parsed data
# Returns: 0 on success, sets variables in parent scope
parse_report_data() {
  local data_file="$1"
  local -n _total="$2"
  local -n _passed="$3"
  local -n _failed="$4"
  local -n _skipped="$5"
  local -n _time="$6"
  local -n _timestamp="$7"
  local -n _group_results="$8"
  local -n _coverage_files="$9"

  local in_section=""

  if [[ ! -f "$data_file" ]]; then
    log_error "Data file not found: $data_file"
    return 1
  fi

  # Reset arrays
  _group_results=()
  _coverage_files=()

  # Parse the file
  while IFS= read -r line; do
    # Track which section we're in
    if [[ "$line" == "SUMMARY:BEGIN" ]]; then
      in_section="summary"
      continue
    elif [[ "$line" == "SUMMARY:END" ]]; then
      in_section=""
      continue
    elif [[ "$line" == "GROUPS:BEGIN" ]]; then
      in_section="groups"
      continue
    elif [[ "$line" == "GROUPS:END" ]]; then
      in_section=""
      continue
    elif [[ "$line" == "COVERAGE:BEGIN" ]]; then
      in_section="coverage"
      continue
    elif [[ "$line" == "COVERAGE:END" ]]; then
      in_section=""
      continue
    fi

    # Process each section
    if [[ "$in_section" == "summary" && -n "$line" ]]; then
      IFS=':' read -r key value <<< "$line"
      case "$key" in
        total) _total="$value" ;;
        passed) _passed="$value" ;;
        failed) _failed="$value" ;;
        skipped) _skipped="$value" ;;
        time) _time="$value" ;;
        timestamp) _timestamp="$value" ;;
      esac
    elif [[ "$in_section" == "groups" && "$line" == *":::"* ]]; then
      _group_results+=("$line")
    elif [[ "$in_section" == "coverage" && -n "$line" ]]; then
      _coverage_files+=("$line")
    fi
  done < "$data_file"

  return 0
}

#######################################
# TEXT REPORT GENERATION
#######################################

# Generate a text report from prepared data
# Arguments:
#   $1 - Path to data file
#   $2 - Output file path (optional, stdout if not provided)
# Returns: 0 on success, 1 on failure
generate_text_from_data() {
  local data_file="$1"
  local output_file="${2:-}"
  local temp_output

  # Parse the data
  local total=0 passed=0 failed=0 skipped=0 time=0 timestamp=""
  local group_results=() coverage_files=()

  parse_report_data "$data_file" total passed failed skipped time timestamp group_results coverage_files || return 1

  # Use temp file if output file is specified
  if [[ -n "$output_file" ]]; then
    temp_output=$(mktemp)
  else
    temp_output="/dev/stdout"
  fi

  log_debug "Generating text report from data"

  # Generate the text report
  {
    echo "========================================"
    echo "TEST RESULTS"
    echo "========================================"
    echo "Total Tests: $total"
    echo "Passed: $passed"
    echo "Failed: $failed"
    echo "Skipped: $skipped"
    echo "Time: ${time}s"
    echo "========================================"

    # Display results by group
    for group_data in "${group_results[@]}"; do
      local group="${group_data%%:::*}"
      local results="${group_data#*:::}"

      # Only output if we have results
      [[ -z "$results" ]] && continue

      echo
      echo "Group: $group"
      echo "----------------------------------------"

      while IFS= read -r result_line; do
        [[ -z "$result_line" ]] && continue

        IFS='|' read -r name status duration message <<< "$result_line"

        # Extract test name without group prefix
        local test_name="$name"
        if [[ "$name" == *": "* ]]; then
          test_name="${name#*: }"
        fi

        # Format the status with color if output is a terminal
        local status_text
        if [[ "$temp_output" == "/dev/stdout" && -t 1 ]]; then
          case "$status" in
            "PASS") status_text="${GREEN}[PASS]${NC}  " ;;
            "FAIL") status_text="${RED}[FAIL]${NC}  " ;;
            "SKIP") status_text="${YELLOW}[SKIP]${NC}  " ;;
            *) status_text="[?????]  " ;;
          esac
        else
          case "$status" in
            "PASS") status_text="[PASS]  " ;;
            "FAIL") status_text="[FAIL]  " ;;
            "SKIP") status_text="[SKIP]  " ;;
            *) status_text="[?????]  " ;;
          esac
        fi

        # Output the test result
        echo "$status_text $test_name (${duration}s)"
        if [[ -n "$message" && "$status" != "PASS" ]]; then
          echo "         $message"
        fi
      done <<< "$results"
    done

    # Display coverage info if we have any
    if [[ ${#coverage_files[@]} -gt 0 ]]; then
      echo
      echo "========================================"
      echo "COVERAGE INFO"
      echo "========================================"
      echo "Files covered: ${#coverage_files[@]}"

      for file in "${coverage_files[@]}"; do
        echo "- $file"
      done
    fi

    echo
    echo "Generated: $(date)"

  } > "$temp_output" || {
    log_error "Failed to write text report"
    [[ -f "$temp_output" && "$temp_output" != "/dev/stdout" ]] && rm -f "$temp_output"
    return 1
  }

  # Move to final output location if specified
  if [[ -n "$output_file" ]]; then
    safe_write "$output_file" < "$temp_output" || {
      [[ -f "$temp_output" ]] && rm -f "$temp_output"
      return 1
    }
    [[ -f "$temp_output" ]] && rm -f "$temp_output"
    log_info "Text report written to $output_file"
  fi

  return 0
}

#######################################
# JSON REPORT GENERATION
#######################################

# Generate a JSON report from prepared data
# Arguments:
#   $1 - Path to data file
#   $2 - Output file path (optional, stdout if not provided)
# Returns: 0 on success, 1 on failure
generate_json_from_data() {
  local data_file="$1"
  local output_file="${2:-}"
  local temp_output

  # Parse the data
  local total=0 passed=0 failed=0 skipped=0 time=0 timestamp=""
  local group_results=() coverage_files=()

  parse_report_data "$data_file" total passed failed skipped time timestamp group_results coverage_files || return 1

  # Use temp file if output file is specified
  if [[ -n "$output_file" ]]; then
    temp_output=$(mktemp)
  else
    temp_output="/dev/stdout"
  fi

  log_debug "Generating JSON report from data"

  # Generate the JSON report
  {
    echo "{"
    echo "  \"summary\": {"
    echo "    \"total\": $total,"
    echo "    \"passed\": $passed,"
    echo "    \"failed\": $failed,"
    echo "    \"skipped\": $skipped,"
    echo "    \"time\": $time,"
    echo "    \"timestamp\": \"$timestamp\","
    echo "    \"version\": \"$REPORTING_MODULE_VERSION\""
    echo "  },"
    echo "  \"tests\": ["

    # Add test results
    local first_test=true
    for group_data in "${group_results[@]}"; do
      local group="${group_data%%:::*}"
      local results="${group_data#*:::}"

      while IFS= read -r result_line; do
        [[ -z "$result_line" ]] && continue

        IFS='|' read -r name status duration message <<< "$result_line"

        # Get test name without group prefix
        local test_name="$name"
        if [[ "$name" == *": "* ]]; then
          test_name="${name#*: }"
        fi

        # Add comma between test entries
        if [[ "$first_test" == "true" ]]; then
          first_test=false
        else
          echo ","
        fi

        # Escape message for JSON
        local escaped_message
        escaped_message=$(json_escape "$message")

        echo -n "    {"
        echo -n "\"group\": \"$group\", "
        echo -n "\"name\": \"$test_name\", "
        echo -n "\"status\": \"$status\", "
        echo -n "\"duration\": $duration, "
        echo -n "\"message\": \"$escaped_message\""
        echo -n "}"
      done <<< "$results"
    done

    echo
    echo "  ],"

    # Add coverage data
    echo "  \"coverage\": ["

    local first_file=true
    for file in "${coverage_files[@]}"; do
      if [[ "$first_file" == "true" ]]; then
        first_file=false
      else
        echo ","
      fi

      local escaped_file
      escaped_file=$(json_escape "$file")
      echo -n "    \"$escaped_file\""
    done

    echo
    echo "  ],"

    # Add metadata
    echo "  \"metadata\": {"
    echo "    \"generator\": \"Cloud Infrastructure Platform Testing Framework\","
    echo "    \"generatorVersion\": \"$REPORTING_MODULE_VERSION\","
    echo "    \"generatedAt\": \"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\""
    echo "  }"
    echo "}"

  } > "$temp_output" || {
    log_error "Failed to write JSON report"
    [[ -f "$temp_output" && "$temp_output" != "/dev/stdout" ]] && rm -f "$temp_output"
    return 1
  }

  # Move to final output location if specified
  if [[ -n "$output_file" ]]; then
    safe_write "$output_file" < "$temp_output" || {
      [[ -f "$temp_output" ]] && rm -f "$temp_output"
      return 1
    }
    [[ -f "$temp_output" ]] && rm -f "$temp_output"
    log_info "JSON report written to $output_file"
  fi

  return 0
}

#######################################
# JUNIT XML REPORT GENERATION
#######################################

# Generate a JUnit XML report from prepared data
# Arguments:
#   $1 - Path to data file
#   $2 - Output file path (optional, stdout if not provided)
# Returns: 0 on success, 1 on failure
generate_junit_from_data() {
  local data_file="$1"
  local output_file="${2:-}"
  local temp_output

  # Parse the data
  local total=0 passed=0 failed=0 skipped=0 time=0 timestamp=""
  local group_results=() coverage_files=()

  parse_report_data "$data_file" total passed failed skipped time timestamp group_results coverage_files || return 1

  # Use temp file if output file is specified
  if [[ -n "$output_file" ]]; then
    temp_output=$(mktemp)
  else
    temp_output="/dev/stdout"
  fi

  log_debug "Generating JUnit XML report from data"

  # Generate the JUnit XML report
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo "<testsuites name=\"Cloud Infrastructure Platform Tests\" time=\"$time\" tests=\"$total\" failures=\"$failed\" skipped=\"$skipped\" timestamp=\"$timestamp\">"

    # Process each test group
    for group_data in "${group_results[@]}"; do
      local group="${group_data%%:::*}"
      local results="${group_data#*:::}"

      # Skip empty groups
      [[ -z "$results" ]] && continue

      # Calculate group metrics
      local group_total=0
      local group_failures=0
      local group_skipped=0
      local group_time=0

      # First pass to get group metrics
      while IFS= read -r result_line; do
        [[ -z "$result_line" ]] && continue

        IFS='|' read -r _ status duration _ <<< "$result_line"
        ((group_total++))

        # Use bc if available, otherwise do simple math (less precision)
        if command -v bc &>/dev/null; then
          group_time=$(echo "$group_time + $duration" | bc 2>/dev/null || echo "$group_time")
        else
          group_time=$(( group_time + duration ))
        fi

        case "$status" in
          "FAIL") ((group_failures++)) ;;
          "SKIP") ((group_skipped++)) ;;
        esac
      done <<< "$results"

      # Escape group name for XML
      local escaped_group
      escaped_group=$(xml_escape "$group")

      # Output testsuite element
      echo "  <testsuite name=\"$escaped_group\" tests=\"$group_total\" failures=\"$group_failures\" skipped=\"$group_skipped\" time=\"$group_time\">"

      # Second pass to output test cases
      while IFS= read -r result_line; do
        [[ -z "$result_line" ]] && continue

        IFS='|' read -r name status duration message <<< "$result_line"

        # Extract test name without group prefix
        local test_name="$name"
        if [[ "$name" == *": "* ]]; then
          test_name="${name#*: }"
        fi

        # XML escape name and message
        local escaped_test_name escaped_message
        escaped_test_name=$(xml_escape "$test_name")
        escaped_message=$(xml_escape "$message")

        echo "    <testcase name=\"$escaped_test_name\" classname=\"$escaped_group\" time=\"$duration\">"

        case "$status" in
          "FAIL")
            echo "      <failure message=\"$escaped_message\" type=\"failure\"></failure>"
            ;;
          "SKIP")
            echo "      <skipped message=\"$escaped_message\"></skipped>"
            ;;
        esac

        echo "    </testcase>"
      done <<< "$results"

      echo "  </testsuite>"
    done

    # Add properties with metadata
    echo "  <properties>"
    echo "    <property name=\"generator\" value=\"Cloud Infrastructure Platform Testing Framework\"/>"
    echo "    <property name=\"generatorVersion\" value=\"$REPORTING_MODULE_VERSION\"/>"
    echo "    <property name=\"generatedAt\" value=\"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\"/>"
    echo "  </properties>"

    echo "</testsuites>"

  } > "$temp_output" || {
    log_error "Failed to write XML report"
    [[ -f "$temp_output" && "$temp_output" != "/dev/stdout" ]] && rm -f "$temp_output"
    return 1
  }

  # Move to final output location if specified
  if [[ -n "$output_file" ]]; then
    safe_write "$output_file" < "$temp_output" || {
      [[ -f "$temp_output" ]] && rm -f "$temp_output"
      return 1
    }
    [[ -f "$temp_output" ]] && rm -f "$temp_output"
    log_info "JUnit XML report written to $output_file"
  fi

  return 0
}

#######################################
# PUBLIC API
#######################################

# Main entry point for report generation
# Arguments:
#   $1 - Output format (text, json, junit)
#   $2 - Output file (optional)
# Returns: 0 on success, 1 on failure
generate_test_report() {
  local format="${1:-text}"
  local output_file="${2:-}"

  # Pass arguments to the generate_report function
  generate_report "$format" "$output_file"
  return $?
}

# Self-test function for report module
# Arguments:
#   None
# Returns: 0 on success, 1 on failure
reporting_self_test() {
  log_info "Running reporting module self-test"

  # Create test data
  local original_test_results=("${TEST_RESULTS[@]:-}")
  local original_test_groups=("${TEST_GROUPS[@]:-}")
  local original_coverage_data=("${COVERAGE_DATA[@]:-}")
  local original_tests_total=$TESTS_TOTAL
  local original_tests_passed=$TESTS_PASSED
  local original_tests_failed=$TESTS_FAILED
  local original_tests_skipped=$TESTS_SKIPPED
  local original_test_total_time=$TEST_TOTAL_TIME

  # Set test data
  TEST_RESULTS=(
    "Test Group 1: Test 1|PASS|0.01|Passed successfully"
    "Test Group 1: Test 2|FAIL|0.02|Expected 5 but got 4"
    "Test Group 2: Test 1|PASS|0.03|"
    "Test Group 2: Test 2|SKIP|0.00|Not implemented yet"
  )

  TEST_GROUPS=("Test Group 1" "Test Group 2")
  COVERAGE_DATA=("scripts/utils/modules/reporting.sh" "scripts/utils/modules/core.sh")
  TESTS_TOTAL=4
  TESTS_PASSED=2
  TESTS_FAILED=1
  TESTS_SKIPPED=1
  TEST_TOTAL_TIME=0.06

  local temp_dir
  temp_dir=$(create_report_temp_dir)
  local result=0

  if [[ -z "$temp_dir" ]]; then
    log_error "Failed to create temporary directory for self-test"
    return 1
  fi

  # Generate reports in each format
  local text_report="$temp_dir/report.txt"
  local json_report="$temp_dir/report.json"
  local xml_report="$temp_dir/report.xml"

  generate_report "text" "$text_report" &&
  generate_report "json" "$json_report" &&
  generate_report "junit" "$xml_report"

  result=$?

  # Verify reports exist
  [[ -f "$text_report" ]] || { log_error "Text report not generated"; result=1; }
  [[ -f "$json_report" ]] || { log_error "JSON report not generated"; result=1; }
  [[ -f "$xml_report" ]] || { log_error "XML report not generated"; result=1; }

  if [[ $result -eq 0 ]]; then
    log_info "Self-test passed! Reports generated:"
    log_info "- Text: $text_report"
    log_info "- JSON: $json_report"
    log_info "- XML: $xml_report"
  else
    log_error "Self-test failed with code $result"
  fi

  # Clean up test data
  cleanup_temp_files "$temp_dir"

  # Restore original values
  TEST_RESULTS=("${original_test_results[@]:-}")
  TEST_GROUPS=("${original_test_groups[@]:-}")
  COVERAGE_DATA=("${original_coverage_data[@]:-}")
  TESTS_TOTAL=$original_tests_total
  TESTS_PASSED=$original_tests_passed
  TESTS_FAILED=$original_tests_failed
  TESTS_SKIPPED=$original_tests_skipped
  TEST_TOTAL_TIME=$original_test_total_time

  return $result
}

#######################################
# EXPORT PUBLIC API
#######################################

# Export functions for external use
export -f generate_test_report
export -f reporting_self_test

# Export constants and version information
export REPORTING_MODULE_VERSION
export REPORTING_MODULE_DATE

# When executed directly, run self-test
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  reporting_self_test
  exit $?
fi
