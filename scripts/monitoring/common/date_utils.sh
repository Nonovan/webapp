#!/bin/bash
# -----------------------------------------------------------------------------
# date_utils.sh - Standard date and time manipulation functions
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# This script provides standardized date and time manipulation functions
# for use across all monitoring scripts. It offers cross-platform compatible
# utilities for date formatting, conversion, validation and calculations.
#
# Usage: source "$(dirname "$0")/../common/date_utils.sh"
# -----------------------------------------------------------------------------

# Set strict error handling
set -o pipefail

# Script version for tracking changes and compatibility
readonly DATE_UTILS_VERSION="1.2.0"

# Detect operating system for platform-specific date handling
OS_TYPE=$(uname -s)

# -----------------------------------------------------------------------------
# BASIC DATE FORMATTING FUNCTIONS
# -----------------------------------------------------------------------------

# Format current date according to specified format
# Arguments:
#   $1 - Format (optional, defaults to "%Y-%m-%d")
# Returns: Formatted date string
format_date() {
    local format="${1:-%Y-%m-%d}"

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS date formatting
        date -j -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux date formatting
        date +"$format"
    fi
}

# Format current time according to specified format
# Arguments:
#   $1 - Format (optional, defaults to "%H:%M:%S")
# Returns: Formatted time string
format_time() {
    local format="${1:-%H:%M:%S}"

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS time formatting
        date -j -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux time formatting
        date +"$format"
    fi
}

# Format current datetime according to specified format
# Arguments:
#   $1 - Format (optional, defaults to "%Y-%m-%d %H:%M:%S")
# Returns: Formatted datetime string
format_datetime() {
    local format="${1:-%Y-%m-%d %H:%M:%S}"

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS datetime formatting
        date -j -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux datetime formatting
        date +"$format"
    fi
}

# Format timestamp for ISO 8601 format (UTC)
# Returns: ISO 8601 timestamp
iso8601_timestamp() {
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        date -j -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" -u "+%Y-%m-%dT%H:%M:%SZ"
    else
        date -u "+%Y-%m-%dT%H:%M:%SZ"
    fi
}

# Get current Unix timestamp (seconds since epoch)
# Returns: Unix timestamp
unix_timestamp() {
    date +%s
}

# Format timestamp for log filenames (without special characters)
# Returns: Filename-friendly timestamp
filename_timestamp() {
    date "+%Y%m%d_%H%M%S"
}

# -----------------------------------------------------------------------------
# DATE CALCULATION FUNCTIONS
# -----------------------------------------------------------------------------

# Get date N days ago
# Arguments:
#   $1 - Number of days ago (default: 1)
#   $2 - Output format (default: %Y-%m-%d)
# Returns: Formatted date string
days_ago() {
    local days="${1:-1}"
    local format="${2:-%Y-%m-%d}"

    if [[ ! "$days" =~ ^[0-9]+$ ]]; then
        echo "Error: Days parameter must be a positive integer"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS calculation
        date -j -v "-${days}d" -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux calculation
        date -d "$days days ago" +"$format"
    fi
}

# Get date N days in the future
# Arguments:
#   $1 - Number of days in the future (default: 1)
#   $2 - Output format (default: %Y-%m-%d)
# Returns: Formatted date string
days_hence() {
    local days="${1:-1}"
    local format="${2:-%Y-%m-%d}"

    if [[ ! "$days" =~ ^[0-9]+$ ]]; then
        echo "Error: Days parameter must be a positive integer"
        return 1
    }

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS calculation
        date -j -v "+${days}d" -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux calculation
        date -d "$days days" +"$format"
    fi
}

# Get date N months ago
# Arguments:
#   $1 - Number of months ago (default: 1)
#   $2 - Output format (default: %Y-%m-%d)
# Returns: Formatted date string
months_ago() {
    local months="${1:-1}"
    local format="${2:-%Y-%m-%d}"

    if [[ ! "$months" =~ ^[0-9]+$ ]]; then
        echo "Error: Months parameter must be a positive integer"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS calculation
        date -j -v "-${months}m" -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux calculation
        date -d "$months months ago" +"$format"
    fi
}

# Get date N months in the future
# Arguments:
#   $1 - Number of months in the future (default: 1)
#   $2 - Output format (default: %Y-%m-%d)
# Returns: Formatted date string
months_hence() {
    local months="${1:-1}"
    local format="${2:-%Y-%m-%d}"

    if [[ ! "$months" =~ ^[0-9]+$ ]]; then
        echo "Error: Months parameter must be a positive integer"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS calculation
        date -j -v "+${months}m" -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"$format"
    else
        # Linux calculation
        date -d "$months months" +"$format"
    fi
}

# Get first day of current month
# Arguments:
#   $1 - Output format (default: %Y-%m-%d)
#   $2 - Reference date (optional, default: current date)
# Returns: Formatted date string
first_day_of_month() {
    local format="${1:-%Y-%m-%d}"
    local ref_date="${2:-$(date +"%Y-%m-%d")}"

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # Extract year and month from reference date
        local year_month
        if [[ -n "$2" ]]; then
            # If reference date provided, use it
            year_month=$(date -j -f "%Y-%m-%d" "$ref_date" +"%Y-%m")
        else
            # Otherwise use current date
            year_month=$(date -j -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" +"%Y-%m")
        fi

        date -j -f "%Y-%m-%d" "${year_month}-01" +"$format"
    else
        # Linux calculation
        if [[ -n "$2" ]]; then
            # If reference date provided, use it
            date -d "$(date -d "$ref_date" +%Y-%m)-01" +"$format"
        else
            # Otherwise use current date
            date -d "$(date +%Y-%m)-01" +"$format"
        fi
    fi
}

# Get last day of current month
# Arguments:
#   $1 - Output format (default: %Y-%m-%d)
#   $2 - Reference date (optional, default: current date)
# Returns: Formatted date string
last_day_of_month() {
    local format="${1:-%Y-%m-%d}"
    local ref_date="${2:-$(date +"%Y-%m-%d")}"

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        local next_month
        local first_of_next

        if [[ -n "$2" ]]; then
            # If reference date provided, extract year-month and add 1 month
            local year_month=$(date -j -f "%Y-%m-%d" "$ref_date" +"%Y-%m")
            local year=${year_month%%-*}
            local month=${year_month##*-}
            month=$((10#$month + 1))

            if [[ $month -gt 12 ]]; then
                month=1
                year=$((year + 1))
            fi

            # Format month with leading zeros
            month=$(printf "%02d" $month)
            next_month="${year}-${month}"
        else
            # Otherwise use current date and add 1 month
            next_month=$(date -j -f "%Y-%m-%d %H:%M:%S" "$(date +"%Y-%m-%d %H:%M:%S")" -v "+1m" +"%Y-%m")
        fi

        # Get first day of next month
        first_of_next=$(date -j -f "%Y-%m-%d" "${next_month}-01" +"%Y-%m-%d")
        # Subtract 1 day to get last day of current month
        date -j -f "%Y-%m-%d" "$first_of_next" -v "-1d" +"$format"
    else
        # Linux calculation
        if [[ -n "$2" ]]; then
            # If reference date provided, use it
            date -d "$(date -d "$ref_date" +%Y-%m-01) + 1 month - 1 day" +"$format"
        else
            # Otherwise use current date
            date -d "$(date -d "$(date +%Y-%m-01) + 1 month - 1 day" +%Y-%m-%d)" +"$format"
        fi
    fi
}

# Get beginning of day (00:00:00)
# Arguments:
#   $1 - Date to use (default: today)
#   $2 - Output format (default: %Y-%m-%d %H:%M:%S)
# Returns: Formatted date string
start_of_day() {
    local input_date="${1:-$(date +"%Y-%m-%d")}"
    local format="${2:-%Y-%m-%d %H:%M:%S}"

    # Validate date format
    if ! is_valid_date "$input_date" "%Y-%m-%d"; then
        echo "Error: Invalid date format. Expected YYYY-MM-DD"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS calculation
        date -j -f "%Y-%m-%d" "$input_date" +"$format"
    else
        # Linux calculation
        date -d "$input_date 00:00:00" +"$format"
    fi
}

# Get end of day (23:59:59)
# Arguments:
#   $1 - Date to use (default: today)
#   $2 - Output format (default: %Y-%m-%d %H:%M:%S)
# Returns: Formatted date string
end_of_day() {
    local input_date="${1:-$(date +"%Y-%m-%d")}"
    local format="${2:-%Y-%m-%d %H:%M:%S}"

    # Validate date format
    if ! is_valid_date "$input_date" "%Y-%m-%d"; then
        echo "Error: Invalid date format. Expected YYYY-MM-DD"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS calculation
        date -j -f "%Y-%m-%d %H:%M:%S" "$input_date 23:59:59" +"$format"
    else
        # Linux calculation
        date -d "$input_date 23:59:59" +"$format"
    fi
}

# -----------------------------------------------------------------------------
# DATE CONVERSION FUNCTIONS
# -----------------------------------------------------------------------------

# Convert date format
# Arguments:
#   $1 - Input date string
#   $2 - Input format (default: %Y-%m-%d)
#   $3 - Output format (default: %d/%m/%Y)
# Returns: Reformatted date string
convert_date_format() {
    local input_date="$1"
    local input_format="${2:-%Y-%m-%d}"
    local output_format="${3:-%d/%m/%Y}"

    if [[ -z "$input_date" ]]; then
        echo "Error: Input date is required"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS conversion
        local result
        result=$(date -j -f "$input_format" "$input_date" +"$output_format" 2>/dev/null) || {
            echo "Error: Invalid date '$input_date' or format '$input_format'"
            return 1
        }
        echo "$result"
    else
        # Linux conversion
        local result
        # Try to handle the input format by creating a date command
        # This is a simplified approach - Linux date doesn't directly support format conversion
        result=$(date -d "$input_date" +"$output_format" 2>/dev/null) || {
            echo "Error: Invalid date '$input_date'"
            return 1
        }
        echo "$result"
    fi
}

# Convert Unix timestamp to formatted date
# Arguments:
#   $1 - Unix timestamp (seconds since epoch)
#   $2 - Output format (default: %Y-%m-%d %H:%M:%S)
# Returns: Formatted date string
timestamp_to_date() {
    local timestamp="$1"
    local format="${2:-%Y-%m-%d %H:%M:%S}"

    if [[ -z "$timestamp" ]]; then
        echo "Error: Timestamp is required"
        return 1
    fi

    if [[ ! "$timestamp" =~ ^[0-9]+$ ]]; then
        echo "Error: Invalid timestamp - must be a positive integer"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS conversion
        date -r "$timestamp" +"$format"
    else
        # Linux conversion
        date -d "@$timestamp" +"$format"
    fi
}

# Convert formatted date to Unix timestamp
# Arguments:
#   $1 - Date string
#   $2 - Input format (default: %Y-%m-%d %H:%M:%S)
# Returns: Unix timestamp (seconds since epoch)
date_to_timestamp() {
    local input_date="$1"
    local input_format="${2:-%Y-%m-%d %H:%M:%S}"

    if [[ -z "$input_date" ]]; then
        echo "Error: Input date is required"
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS conversion
        local result
        result=$(date -j -f "$input_format" "$input_date" +%s 2>/dev/null) || {
            echo "Error: Invalid date '$input_date' or format '$input_format'"
            return 1
        }
        echo "$result"
    else
        # Linux conversion
        local result
        result=$(date -d "$input_date" +%s 2>/dev/null) || {
            echo "Error: Invalid date '$input_date'"
            return 1
        }
        echo "$result"
    fi
}

# -----------------------------------------------------------------------------
# DATE COMPARISON FUNCTIONS
# -----------------------------------------------------------------------------

# Calculate difference between two dates in days
# Arguments:
#   $1 - First date (YYYY-MM-DD)
#   $2 - Second date (YYYY-MM-DD)
# Returns: Number of days between dates (positive if second date is later)
date_diff_days() {
    local date1="$1"
    local date2="$2"

    if [[ -z "$date1" || -z "$date2" ]]; then
        echo "Error: Both dates are required"
        return 1
    fi

    # Validate date formats
    if ! is_valid_date "$date1" "%Y-%m-%d" || ! is_valid_date "$date2" "%Y-%m-%d"; then
        echo "Error: Invalid date format. Expected YYYY-MM-DD"
        return 1
    }

    # Convert dates to timestamps
    local timestamp1
    local timestamp2

    timestamp1=$(date_to_timestamp "$date1" "%Y-%m-%d")
    timestamp2=$(date_to_timestamp "$date2" "%Y-%m-%d")

    if [[ ! "$timestamp1" =~ ^[0-9]+$ || ! "$timestamp2" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to convert dates to timestamps"
        return 1
    fi

    # Calculate difference and convert to days
    echo $(( (timestamp2 - timestamp1) / 86400 ))
}

# Check if date is in the past
# Arguments:
#   $1 - Date to check (YYYY-MM-DD)
# Returns: 0 if date is in the past, 1 otherwise
is_date_past() {
    local check_date="$1"
    local today

    if [[ -z "$check_date" ]]; then
        echo "Error: Date is required"
        return 2
    fi

    # Validate date format
    if ! is_valid_date "$check_date" "%Y-%m-%d"; then
        echo "Error: Invalid date format. Expected YYYY-MM-DD"
        return 2
    }

    today=$(date +"%Y-%m-%d")

    # Convert dates to timestamps for comparison
    local check_timestamp
    local today_timestamp

    check_timestamp=$(date_to_timestamp "$check_date" "%Y-%m-%d")
    today_timestamp=$(date_to_timestamp "$today" "%Y-%m-%d")

    if [[ ! "$check_timestamp" =~ ^[0-9]+$ || ! "$today_timestamp" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to convert dates to timestamps"
        return 2
    fi

    if (( check_timestamp < today_timestamp )); then
        return 0  # True, date is in the past
    else
        return 1  # False, date is not in the past
    fi
}

# Check if date is in the future
# Arguments:
#   $1 - Date to check (YYYY-MM-DD)
# Returns: 0 if date is in the future, 1 otherwise
is_date_future() {
    local check_date="$1"
    local today

    if [[ -z "$check_date" ]]; then
        echo "Error: Date is required"
        return 2
    fi

    # Validate date format
    if ! is_valid_date "$check_date" "%Y-%m-%d"; then
        echo "Error: Invalid date format. Expected YYYY-MM-DD"
        return 2
    }

    today=$(date +"%Y-%m-%d")

    # Convert dates to timestamps for comparison
    local check_timestamp
    local today_timestamp

    check_timestamp=$(date_to_timestamp "$check_date" "%Y-%m-%d")
    today_timestamp=$(date_to_timestamp "$today" "%Y-%m-%d")

    if [[ ! "$check_timestamp" =~ ^[0-9]+$ || ! "$today_timestamp" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to convert dates to timestamps"
        return 2
    fi

    if (( check_timestamp > today_timestamp )); then
        return 0  # True, date is in the future
    else
        return 1  # False, date is not in the future
    fi
}

# Check if a date falls within a given range
# Arguments:
#   $1 - Date to check (YYYY-MM-DD)
#   $2 - Start date of range (YYYY-MM-DD)
#   $3 - End date of range (YYYY-MM-DD)
# Returns: 0 if date is in range, 1 otherwise
is_date_in_range() {
    local check_date="$1"
    local start_date="$2"
    local end_date="$3"

    if [[ -z "$check_date" || -z "$start_date" || -z "$end_date" ]]; then
        echo "Error: All three dates are required"
        return 2
    fi

    # Validate date formats
    if ! is_valid_date "$check_date" "%Y-%m-%d" ||
       ! is_valid_date "$start_date" "%Y-%m-%d" ||
       ! is_valid_date "$end_date" "%Y-%m-%d"; then
        echo "Error: Invalid date format. Expected YYYY-MM-DD"
        return 2
    }

    # Convert dates to timestamps for comparison
    local check_timestamp
    local start_timestamp
    local end_timestamp

    check_timestamp=$(date_to_timestamp "$check_date" "%Y-%m-%d")
    start_timestamp=$(date_to_timestamp "$start_date" "%Y-%m-%d")
    end_timestamp=$(date_to_timestamp "$end_date" "%Y-%m-%d")

    if [[ ! "$check_timestamp" =~ ^[0-9]+$ ||
          ! "$start_timestamp" =~ ^[0-9]+$ ||
          ! "$end_timestamp" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to convert dates to timestamps"
        return 2
    fi

    if (( check_timestamp >= start_timestamp && check_timestamp <= end_timestamp )); then
        return 0  # True, date is in range
    else
        return 1  # False, date is not in range
    fi
}

# -----------------------------------------------------------------------------
# TIME FUNCTIONS
# -----------------------------------------------------------------------------

# Format seconds into human readable time format
# Arguments:
#   $1 - Time in seconds
# Returns: Human readable time (e.g. "2h 30m 45s")
format_seconds_human() {
    local seconds="$1"

    if [[ -z "$seconds" ]]; then
        echo "Error: Time value is required"
        return 1
    fi

    if [[ ! "$seconds" =~ ^[0-9]+$ ]]; then
        echo "Error: Invalid time value - must be a positive integer"
        return 1
    fi

    local days=$((seconds / 86400))
    local hours=$(( (seconds % 86400) / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))
    local result=""

    if (( days > 0 )); then
        result="${days}d "
    fi
    if (( hours > 0 || days > 0 )); then
        result="${result}${hours}h "
    fi
    if (( minutes > 0 || hours > 0 || days > 0 )); then
        result="${result}${minutes}m "
    fi
    result="${result}${secs}s"

    echo "$result"
}

# Calculate time elapsed since a given timestamp
# Arguments:
#   $1 - Start timestamp (Unix time in seconds)
# Returns: Elapsed seconds
elapsed_time() {
    local start_time="$1"
    local current_time

    if [[ -z "$start_time" ]]; then
        echo "Error: Start time is required"
        return 1
    fi

    if [[ ! "$start_time" =~ ^[0-9]+$ ]]; then
        echo "Error: Invalid start time - must be a positive integer"
        return 1
    fi

    current_time=$(date +%s)
    echo $((current_time - start_time))
}

# Format time elapsed since a given timestamp in human-readable format
# Arguments:
#   $1 - Start timestamp (Unix time in seconds)
# Returns: Human-readable elapsed time
elapsed_time_human() {
    local start_time="$1"

    if [[ -z "$start_time" ]]; then
        echo "Error: Start time is required"
        return 1
    fi

    local elapsed
    elapsed=$(elapsed_time "$start_time") || return 1
    format_seconds_human "$elapsed"
}

# -----------------------------------------------------------------------------
# TIMEZONE FUNCTIONS
# -----------------------------------------------------------------------------

# Get current timezone
# Returns: Current timezone
get_timezone() {
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS timezone
        local tz
        tz=$(systemsetup -gettimezone 2>/dev/null | awk '{print $3}')
        if [[ -z "$tz" ]]; then
            date +%Z
        else
            echo "$tz"
        fi
    else
        # Linux timezone
        if [[ -f /etc/timezone ]]; then
            cat /etc/timezone
        elif [[ -L /etc/localtime ]]; then
            # For systemd-based systems where /etc/localtime is a symlink
            readlink /etc/localtime | sed 's#^.*/zoneinfo/##'
        else
            date +%Z
        fi
    fi
}

# Convert date between timezones
# Arguments:
#   $1 - Date string
#   $2 - Source timezone (e.g., "UTC" or "America/New_York")
#   $3 - Target timezone (e.g., "UTC" or "America/Los_Angeles")
#   $4 - Format (default: "%Y-%m-%d %H:%M:%S")
# Returns: Converted date string
convert_timezone() {
    local date_str="$1"
    local source_tz="$2"
    local target_tz="$3"
    local format="${4:-%Y-%m-%d %H:%M:%S}"

    if [[ -z "$date_str" || -z "$source_tz" || -z "$target_tz" ]]; then
        echo "Error: Date string and both timezones are required"
        return 1
    fi

    # This function requires TZ environment variable support
    if command -v perl &>/dev/null && perl -e 'use POSIX qw(strftime);' &>/dev/null; then
        # Use perl for timezone conversion (more reliable)
        TZ="$source_tz" perl -e '
            use POSIX qw(strftime mktime);
            my ($y, $m, $d, $H, $M, $S) =
                $ARGV[0] =~ /(\d{4})-(\d{2})-(\d{2})(?:\s+(\d{2}):(\d{2}):(\d{2}))?/;
            if (!defined $y) {
                print "Error: Invalid date format\n";
                exit 1;
            }
            $m -= 1;  # Month is 0-based in mktime
            $H ||= 0; $M ||= 0; $S ||= 0;
            my $time = mktime($S, $M, $H, $d, $m, $y - 1900);
            if ($time == -1) {
                print "Error: Invalid date values\n";
                exit 1;
            }
            $ENV{TZ} = $ARGV[1];
            print strftime($ARGV[2], localtime($time));
        ' "$date_str" "$target_tz" "$format" || {
            echo "Error: Failed to convert timezone"
            return 1
        }
    else
        # Fallback using date command (less reliable across systems)
        if [[ "$OS_TYPE" == "Darwin" ]]; then
            # macOS doesn't support TZ environment variable well with date
            echo "Error: Timezone conversion requires Perl on macOS"
            return 1
        else
            # Linux with TZ environment variable
            TZ="$source_tz" date -d "$date_str" "+%s" 2>/dev/null | {
                read -r timestamp
                TZ="$target_tz" date -d "@$timestamp" "+$format" 2>/dev/null || {
                    echo "Error: Failed to convert timezone"
                    return 1
                }
            } || {
                echo "Error: Failed to convert date to timestamp"
                return 1
            }
        fi
    fi
}

# Get current UTC time
# Arguments:
#   $1 - Format (default: "%Y-%m-%d %H:%M:%S")
# Returns: Current UTC time
utc_time() {
    local format="${1:-%Y-%m-%d %H:%M:%S}"
    date -u +"$format"
}

# -----------------------------------------------------------------------------
# DATE VALIDATION FUNCTIONS
# -----------------------------------------------------------------------------

# Check if date string is valid
# Arguments:
#   $1 - Date string
#   $2 - Format (default: "%Y-%m-%d")
# Returns: 0 if valid, 1 if not
is_valid_date() {
    local date_str="$1"
    local format="${2:-%Y-%m-%d}"

    if [[ -z "$date_str" ]]; then
        return 1
    fi

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS date validation
        if date -j -f "$format" "$date_str" > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    else
        # Linux date validation
        if date -d "$date_str" > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    fi
}

# Validate date with custom error message
# Arguments:
#   $1 - Date string
#   $2 - Format (default: "%Y-%m-%d")
# Returns: 0 if valid, 1 if not (and prints error)
validate_date() {
    local date_str="$1"
    local format="${2:-%Y-%m-%d}"

    if [[ -z "$date_str" ]]; then
        echo "Error: Empty date string provided"
        return 1
    fi

    if ! is_valid_date "$date_str" "$format"; then
        echo "Error: Invalid date format '$date_str'. Expected format: $format"
        return 1
    fi

    return 0
}

# Check if a year is a leap year
# Arguments:
#   $1 - Year to check
# Returns: 0 if leap year, 1 if not
is_leap_year() {
    local year="$1"

    if [[ ! "$year" =~ ^[0-9]{4}$ ]]; then
        echo "Error: Invalid year format - must be 4 digits"
        return 2
    fi

    # Leap year rule: divisible by 4, but not by 100 unless also divisible by 400
    if (( year % 4 == 0 )) && (( year % 100 != 0 || year % 400 == 0 )); then
        return 0  # True, it's a leap year
    else
        return 1  # False, it's not a leap year
    fi
}

# Get number of days in a month
# Arguments:
#   $1 - Month (1-12)
#   $2 - Year (4-digit)
# Returns: Number of days in month
days_in_month() {
    local month="$1"
    local year="$2"

    if [[ -z "$month" || -z "$year" ]]; then
        echo "Error: Both month and year are required"
        return 1
    fi

    if [[ ! "$month" =~ ^[1-9]|1[0-2]$ ]]; then
        echo "Error: Invalid month - must be between 1 and 12"
        return 1
    fi

    if [[ ! "$year" =~ ^[0-9]{4}$ ]]; then
        echo "Error: Invalid year format - must be 4 digits"
        return 1
    fi

    case "$month" in
        1|3|5|7|8|10|12) echo "31" ;;
        4|6|9|11) echo "30" ;;
        2)
            if is_leap_year "$year" >/dev/null 2>&1; then
                echo "29"
            else
                echo "28"
            fi
            ;;
        *)
            echo "Error: Invalid month"
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# ADDITIONAL UTILITY FUNCTIONS
# -----------------------------------------------------------------------------

# Get current quarter number (1-4)
# Arguments: None
# Returns: Current quarter (1-4)
current_quarter() {
    local month
    month=$(date +%m)
    # Convert to number and calculate quarter
    month=$((10#$month))  # Force base-10 interpretation
    echo $(( (month - 1) / 3 + 1 ))
}

# Get quarter start date
# Arguments:
#   $1 - Quarter number (1-4, optional, defaults to current quarter)
#   $2 - Year (optional, defaults to current year)
#   $3 - Output format (default: %Y-%m-%d)
# Returns: Start date of the specified quarter
quarter_start() {
    local quarter="${1:-$(current_quarter)}"
    local year="${2:-$(date +%Y)}"
    local format="${3:-%Y-%m-%d}"

    if [[ ! "$quarter" =~ ^[1-4]$ ]]; then
        echo "Error: Invalid quarter - must be between 1 and 4"
        return 1
    fi

    if [[ ! "$year" =~ ^[0-9]{4}$ ]]; then
        echo "Error: Invalid year format - must be 4 digits"
        return 1
    fi

    # Calculate quarter start month
    local month=$(( (quarter - 1) * 3 + 1 ))
    # Format month with leading zero
    month=$(printf "%02d" $month)

    # Create date string for first day of the quarter
    local quarter_date="${year}-${month}-01"

    # Format the date
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        date -j -f "%Y-%m-%d" "$quarter_date" +"$format"
    else
        date -d "$quarter_date" +"$format"
    fi
}

# Get quarter end date
# Arguments:
#   $1 - Quarter number (1-4, optional, defaults to current quarter)
#   $2 - Year (optional, defaults to current year)
#   $3 - Output format (default: %Y-%m-%d)
# Returns: End date of the specified quarter
quarter_end() {
    local quarter="${1:-$(current_quarter)}"
    local year="${2:-$(date +%Y)}"
    local format="${3:-%Y-%m-%d}"

    if [[ ! "$quarter" =~ ^[1-4]$ ]]; then
        echo "Error: Invalid quarter - must be between 1 and 4"
        return 1
    fi

    if [[ ! "$year" =~ ^[0-9]{4}$ ]]; then
        echo "Error: Invalid year format - must be 4 digits"
        return 1
    fi

    # Calculate quarter end month
    local month=$(( quarter * 3 ))
    # Format month with leading zero
    month=$(printf "%02d" $month)

    # Create date string for last day of the quarter
    local quarter_date="${year}-${month}-01"

    # Get last day of the month
    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # For macOS, use last_day_of_month function
        last_day_of_month "$format" "$quarter_date"
    else
        # For Linux, get last day of the month directly
        date -d "$quarter_date +1 month -1 day" +"$format"
    fi
}

# Get age of file in seconds
# Arguments:
#   $1 - File path
# Returns: Age in seconds
file_age_seconds() {
    local file_path="$1"

    if [[ ! -f "$file_path" ]]; then
        echo "Error: File not found: $file_path"
        return 1
    fi

    local file_time
    local current_time

    if [[ "$OS_TYPE" == "Darwin" ]]; then
        # macOS - stat format is different
        file_time=$(stat -f %m "$file_path")
    else
        # Linux
        file_time=$(stat -c %Y "$file_path")
    fi

    current_time=$(date +%s)
    echo $((current_time - file_time))
}

# Get age of file in human-readable format
# Arguments:
#   $1 - File path
# Returns: Age in human-readable format (e.g., "2d 5h 30m 15s")
file_age_human() {
    local file_path="$1"
    local age_seconds

    age_seconds=$(file_age_seconds "$file_path") || return 1

    format_seconds_human "$age_seconds"
}

# Export functions for use in other scripts
export -f format_date
export -f format_time
export -f format_datetime
export -f iso8601_timestamp
export -f unix_timestamp
export -f filename_timestamp
export -f days_ago
export -f days_hence
export -f months_ago
export -f months_hence
export -f first_day_of_month
export -f last_day_of_month
export -f start_of_day
export -f end_of_day
export -f convert_date_format
export -f timestamp_to_date
export -f date_to_timestamp
export -f date_diff_days
export -f is_date_past
export -f is_date_future
export -f is_date_in_range
export -f format_seconds_human
export -f elapsed_time
export -f elapsed_time_human
export -f get_timezone
export -f convert_timezone
export -f utc_time
export -f is_valid_date
export -f validate_date
export -f is_leap_year
export -f days_in_month
export -f current_quarter
export -f quarter_start
export -f quarter_end
export -f file_age_seconds
export -f file_age_human

# Basic self-test function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Date Utils v${DATE_UTILS_VERSION} - Self Test"
    echo "==================================="
    echo "Current Date: $(format_date)"
    echo "Current Time: $(format_time)"
    echo "Current Datetime: $(format_datetime)"
    echo "ISO8601: $(iso8601_timestamp)"
    echo "Unix Timestamp: $(unix_timestamp)"
    echo "Filename timestamp: $(filename_timestamp)"
    echo "Yesterday: $(days_ago)"
    echo "Tomorrow: $(days_hence)"
    echo "Last month: $(months_ago)"
    echo "Next month: $(months_hence)"
    echo "First day of month: $(first_day_of_month)"
    echo "Last day of month: $(last_day_of_month)"
    echo "Start of day: $(start_of_day)"
    echo "End of day: $(end_of_day)"

    echo
    echo "Date Conversions:"
    echo "YYYY-MM-DD to DD/MM/YYYY: $(convert_date_format "2023-12-31" "%Y-%m-%d" "%d/%m/%Y")"

    test_timestamp=$(unix_timestamp)
    echo "Current timestamp: $test_timestamp"
    echo "Timestamp to date: $(timestamp_to_date "$test_timestamp")"

    echo
    echo "Date Comparison:"
    echo "Days between 2023-01-01 and 2023-12-31: $(date_diff_days "2023-01-01" "2023-12-31")"

    test_past="2022-01-01"
    if is_date_past "$test_past"; then
        echo "$test_past is in the past"
    else
        echo "$test_past is not in the past"
    fi

    test_future="2099-01-01"
    if is_date_future "$test_future"; then
        echo "$test_future is in the future"
    else
        echo "$test_future is not in the future"
    fi

    echo
    echo "Time Functions:"
    echo "5000 seconds formatted: $(format_seconds_human 5000)"
    echo "Current quarter: $(current_quarter)"
    echo "Quarter start: $(quarter_start)"
    echo "Quarter end: $(quarter_end)"

    echo
    echo "Timezone Functions:"
    echo "Current timezone: $(get_timezone)"
    echo "Current UTC time: $(utc_time)"

    echo
    echo "Date Validation:"
    echo "Is 2023-02-29 valid? $(is_valid_date "2023-02-29" && echo "Yes" || echo "No")"
    echo "Is 2024-02-29 valid? $(is_valid_date "2024-02-29" && echo "Yes" || echo "No")"
    echo "Is 2024 a leap year? $(is_leap_year "2024" && echo "Yes" || echo "No")"
    echo "Is 2023 a leap year? $(is_leap_year "2023" && echo "Yes" || echo "No")"
    echo "Days in February 2024: $(days_in_month 2 2024)"
    echo "Days in February 2023: $(days_in_month 2 2023)"

    # Test file age if this script file exists
    if [[ -f "${BASH_SOURCE[0]}" ]]; then
        echo
        echo "File Age:"
        echo "This script's age: $(file_age_human "${BASH_SOURCE[0]}")"
    fi
fi
