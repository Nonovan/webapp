#!/bin/bash
# Time measurement utilities for testing

# Version tracking
readonly TIMING_UTILS_VERSION="1.0.0"
readonly TIMING_UTILS_DATE="2024-08-01"

#######################################
# TIME MEASUREMENT FUNCTIONS
#######################################

# Get high precision time if available
# Returns: Current time with highest precision available
get_high_precision_time() {
  # First try to use date with nanosecond precision
  if [[ -x /usr/bin/date && "$(/usr/bin/date +%N 2>/dev/null)" != "N" ]]; then
    /usr/bin/date +%s.%N
    return 0
  fi

  # Next try GNU date which may support nanoseconds
  if command -v gdate >/dev/null 2>&1 && "$(gdate +%N 2>/dev/null)" != "N"; then
    gdate +%s.%N
    return 0
  fi

  # Fallback to second precision
  date +%s
  return 0
}

# Calculate duration between two timestamps
# Arguments:
#   $1 - Start time
#   $2 - End time
#   $3 - Decimal precision (optional, default: 3)
# Returns: Duration in seconds with specified precision
calculate_duration() {
  local start_time="$1"
  local end_time="$2"
  local precision="${3:-3}"

  # Validate inputs
  if [[ -z "$start_time" || -z "$end_time" ]]; then
    echo "0"
    return 1
  fi

  # Check if inputs are valid numbers
  if ! [[ "$start_time" =~ ^[0-9]+(\.[0-9]+)?$ || "$end_time" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "0"
    return 1
  fi

  # Use bc for floating point calculation if available
  if command -v bc >/dev/null 2>&1; then
    echo "scale=$precision; $end_time - $start_time" | bc 2>/dev/null || echo "$((end_time - start_time))"
    return 0
  fi

  # Python as a secondary option for floating point
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "print(round($end_time - $start_time, $precision))" 2>/dev/null || python3 -c "print($end_time - $start_time)" 2>/dev/null
    return $?
  fi

  if command -v python >/dev/null 2>&1; then
    python -c "print(round($end_time - $start_time, $precision))" 2>/dev/null || python -c "print($end_time - $start_time)" 2>/dev/null
    return $?
  fi

  # Integer subtraction as final fallback
  echo "$((${end_time%.*} - ${start_time%.*}))"
  return 0
}

# Format a duration for display
# Arguments:
#   $1 - Duration in seconds
#   $2 - Output format (optional: 'human', 'seconds', 'compact', default: 'seconds')
#   $3 - Decimal precision (optional, default: 2)
# Returns: Formatted duration string
format_duration() {
  local duration="$1"
  local format="${2:-seconds}"
  local precision="${3:-2}"

  # Validate input
  if [[ -z "$duration" || ! "$duration" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "0"
    return 1
  fi

  case "$format" in
    human)
      # Convert to human-readable format (e.g., 1h 2m 3.45s)
      if command -v bc >/dev/null 2>&1; then
        local hours minutes seconds
        hours=$(echo "$duration / 3600" | bc)
        minutes=$(echo "($duration / 60) % 60" | bc)
        seconds=$(echo "scale=$precision; $duration % 60" | bc)

        local result=""
        [[ $hours -gt 0 ]] && result="${hours}h "
        [[ $hours -gt 0 || $minutes -gt 0 ]] && result="${result}${minutes}m "
        result="${result}${seconds}s"
        echo "$result"
      else
        # Fallback to basic seconds if bc isn't available
        echo "${duration}s"
      fi
      ;;
    compact)
      # Compact format (e.g., 1h2m3s)
      if command -v bc >/dev/null 2>&1; then
        local hours minutes seconds
        hours=$(echo "$duration / 3600" | bc)
        minutes=$(echo "($duration / 60) % 60" | bc)
        seconds=$(echo "scale=$precision; $duration % 60" | bc)

        local result=""
        [[ $hours -gt 0 ]] && result="${hours}h"
        [[ $hours -gt 0 || $minutes -gt 0 ]] && result="${result}${minutes}m"
        result="${result}${seconds}s"
        echo "$result"
      else
        # Fallback to seconds only
        echo "${duration}s"
      fi
      ;;
    seconds|*)
      # Default: just format with specified precision
      if command -v bc >/dev/null 2>&1; then
        echo "scale=$precision; $duration" | bc 2>/dev/null || echo "$duration"
      else
        echo "$duration"
      fi
      ;;
  esac

  return 0
}

# Sleep with millisecond precision if available
# Arguments:
#   $1 - Sleep time in seconds (can be fractional)
#   $2 - Fallback behavior (optional: 'floor', 'ceiling', default: 'ceiling')
# Returns:
#   0 on success, 1 on failure
precision_sleep() {
  local sleep_time="$1"
  local fallback="${2:-ceiling}"

  # Validate input
  if [[ -z "$sleep_time" || ! "$sleep_time" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    return 1
  fi

  # Try perl first as it has best cross-platform compatibility for subsecond sleep
  if command -v perl >/dev/null 2>&1; then
    perl -e "select(undef, undef, undef, $sleep_time);" 2>/dev/null
    return $?
  fi

  # Try Python as an alternative for subsecond sleep
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import time; time.sleep($sleep_time)" 2>/dev/null
    return $?
  fi

  if command -v python >/dev/null 2>&1; then
    python -c "import time; time.sleep($sleep_time)" 2>/dev/null
    return $?
  fi

  # Fallback to regular sleep with appropriate rounding
  local int_sleep
  case "$fallback" in
    floor)
      # Round down to nearest second
      int_sleep=${sleep_time%.*}
      ;;
    *)
      # Default: round up to nearest second
      int_sleep=$((${sleep_time%.*} + 1))
      ;;
  esac

  sleep "$int_sleep" 2>/dev/null
  return $?
}

# Execute with timeout and precision timing
# Arguments:
#   $1 - Timeout in seconds
#   $2 - Optional flags:
#        --quiet: Suppress timing output
#        --no-kill: Don't kill process on timeout (just return status)
#        --output=FILE: Write command output to FILE
#   $@ - Command and arguments to execute
# Returns:
#   Command's exit code or timeout error (124)
execute_timed() {
  local timeout="$1"
  shift
  local quiet=false
  local no_kill=false
  local output_file=""
  local start_time end_time duration
  local exit_code=0
  local temp_output

  # Process optional flags
  while [[ "$1" == --* ]]; do
    case "$1" in
      --quiet)
        quiet=true
        shift
        ;;
      --no-kill)
        no_kill=true
        shift
        ;;
      --output=*)
        output_file="${1#*=}"
        shift
        ;;
      *)
        break
        ;;
    esac
  done

  # Validate timeout value
  if [[ -z "$timeout" || ! "$timeout" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Error: Invalid timeout value" >&2
    return 1
  fi

  # Create temporary file for output capture if needed
  if [[ -z "$output_file" ]]; then
    if command -v mktemp >/dev/null 2>&1; then
      temp_output=$(mktemp)
    else
      temp_output="/tmp/timed_exec_$$.tmp"
      touch "$temp_output"
    fi
    output_file="$temp_output"
  fi

  # Start timing
  start_time=$(get_high_precision_time)

  # Execute with timeout if available
  if command -v timeout >/dev/null 2>&1; then
    timeout --foreground "$timeout" "$@" > "$output_file" 2>&1
    exit_code=$?
  else
    # Simple timeout implementation
    "$@" > "$output_file" 2>&1 &
    local pid=$!

    # Wait for completion or timeout
    while kill -0 $pid 2>/dev/null; do
      # Calculate elapsed time
      local current_time
      current_time=$(get_high_precision_time)

      # Use bc if available for floating point comparison
      local timed_out=false
      if command -v bc >/dev/null 2>&1; then
        if (( $(echo "$current_time - $start_time >= $timeout" | bc -l) )); then
          timed_out=true
        fi
      else
        # Integer comparison as fallback
        if (( current_time - ${start_time%.*} >= ${timeout%.*} )); then
          timed_out=true
        fi
      fi

      # Handle timeout if occurred
      if [[ "$timed_out" == "true" ]]; then
        if [[ "$no_kill" == "true" ]]; then
          exit_code=124
          break
        else
          kill -TERM $pid 2>/dev/null
          # Wait a bit and then send SIGKILL if process is still running
          precision_sleep 0.5
          kill -0 $pid 2>/dev/null && kill -KILL $pid 2>/dev/null
          wait $pid 2>/dev/null || true
          exit_code=124
          break
        fi
      fi

      precision_sleep 0.1
    done

    # If we exited the loop without timeout, get exit status
    if [[ "$exit_code" != "124" ]]; then
      wait $pid
      exit_code=$?
    fi
  fi

  # Calculate and log duration
  end_time=$(get_high_precision_time)
  duration=$(calculate_duration "$start_time" "$end_time")

  if [[ "$quiet" != "true" ]]; then
    if [[ "$exit_code" == "124" ]]; then
      echo "Command timed out after ${duration}s" >&2
    else
      echo "Command completed in ${duration}s with exit code $exit_code" >&2
    fi
  fi

  # Output results if using a temporary file
  if [[ -n "$temp_output" ]]; then
    cat "$temp_output"
    rm -f "$temp_output"
  fi

  return $exit_code
}

# Time a command execution without enforcing timeout
# Arguments:
#   $@ - Command and arguments to execute
# Returns:
#   Formatted timing string and command exit code
time_command() {
  local start_time end_time duration exit_code

  # Start timing
  start_time=$(get_high_precision_time)

  # Execute command
  "$@"
  exit_code=$?

  # Calculate duration
  end_time=$(get_high_precision_time)
  duration=$(calculate_duration "$start_time" "$end_time")

  # Output timing information
  echo "Time: ${duration}s"

  return $exit_code
}

# Wait until a condition is true or timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2 - Condition command to evaluate
#   $3 - Optional interval between checks (default: 0.5)
# Returns:
#   0 if condition became true, 1 if timeout occurred
wait_for_condition() {
  local timeout="$1"
  local condition="$2"
  local interval="${3:-0.5}"
  local start_time exit_code

  # Validate inputs
  if [[ -z "$timeout" || -z "$condition" ]]; then
    return 1
  fi

  # Start timing
  start_time=$(get_high_precision_time)

  while true; do
    # Evaluate condition
    eval "$condition"
    exit_code=$?

    # If condition is true, we're done
    if [[ $exit_code -eq 0 ]]; then
      return 0
    fi

    # Check if we've exceeded the timeout
    local current_time=$(get_high_precision_time)
    local elapsed
    elapsed=$(calculate_duration "$start_time" "$current_time")

    if command -v bc >/dev/null 2>&1; then
      if (( $(echo "$elapsed >= $timeout" | bc -l) )); then
        return 1
      fi
    else
      if (( ${elapsed%.*} >= ${timeout%.*} )); then
        return 1
      fi
    fi

    # Wait before checking again
    precision_sleep "$interval"
  done
}

# Self-test function - validates core functionality
# Returns:
#   0 on success, 1 on failure
self_test() {
  local failures=0

  echo "Testing timing_utils.sh functions..."

  # Test get_high_precision_time
  local time1
  time1=$(get_high_precision_time)
  if [[ -n "$time1" && "$time1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "PASS: get_high_precision_time returns valid timestamp: $time1"
  else
    echo "FAIL: get_high_precision_time returned invalid value: $time1"
    ((failures++))
  fi

  # Test calculate_duration
  precision_sleep 1
  local time2 duration
  time2=$(get_high_precision_time)
  duration=$(calculate_duration "$time1" "$time2")
  if [[ "$duration" =~ ^[0-9]+(\.[0-9]+)?$ && $(echo "$duration > 0.9" | bc -l) -eq 1 ]]; then
    echo "PASS: calculate_duration returned reasonable value: $duration"
  else
    echo "FAIL: calculate_duration returned unexpected value: $duration"
    ((failures++))
  fi

  # Test format_duration
  local formatted
  formatted=$(format_duration "123.456" "human")
  if [[ "$formatted" == *"m"* && "$formatted" == *"s"* ]]; then
    echo "PASS: format_duration (human) works correctly: $formatted"
  else
    echo "FAIL: format_duration (human) returned unexpected value: $formatted"
    ((failures++))
  fi

  # Test precision_sleep
  local sleep_start sleep_end sleep_duration
  sleep_start=$(get_high_precision_time)
  precision_sleep 0.5
  sleep_end=$(get_high_precision_time)
  sleep_duration=$(calculate_duration "$sleep_start" "$sleep_end")

  if [[ $(echo "$sleep_duration >= 0.4" | bc -l) -eq 1 && $(echo "$sleep_duration <= 1.0" | bc -l) -eq 1 ]]; then
    echo "PASS: precision_sleep works correctly (slept for $sleep_duration seconds)"
  else
    echo "FAIL: precision_sleep duration outside expected range: $sleep_duration"
    ((failures++))
  fi

  # Test execute_timed
  if execute_timed 1 --quiet echo "test" >/dev/null; then
    echo "PASS: execute_timed successfully executed command"
  else
    echo "FAIL: execute_timed failed to execute command"
    ((failures++))
  fi

  # Test execute_timed timeout
  if ! execute_timed 0.5 --quiet sleep 2; then
    echo "PASS: execute_timed correctly timed out"
  else
    echo "FAIL: execute_timed did not timeout as expected"
    ((failures++))
  fi

  if [[ $failures -eq 0 ]]; then
    echo "All timing_utils.sh tests passed!"
    return 0
  else
    echo "$failures test(s) failed!"
    return 1
  fi
}

# Export timing functions
export -f get_high_precision_time
export -f calculate_duration
export -f format_duration
export -f precision_sleep
export -f execute_timed
export -f time_command
export -f wait_for_condition

# Run self-test when script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  self_test
  exit $?
fi
