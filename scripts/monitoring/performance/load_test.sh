#!/bin/bash
# -----------------------------------------------------------------------------
# load_test.sh - HTTP Load Testing Tool
#
# Part of Cloud Infrastructure Platform
#
# This script performs comprehensive HTTP load testing against specified endpoints.
# Features include customizable concurrency, multiple test types, detailed reporting,
# performance metrics, and authentication support.
#
# Usage: ./load_test.sh [options] [URL]
# -----------------------------------------------------------------------------

set -o pipefail

# Script version for tracking changes and compatibility
readonly SCRIPT_VERSION="1.0.0"

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"
TARGET_URL="http://localhost:8080"
CONCURRENT_REQUESTS=10
TOTAL_REQUESTS=100
REQUEST_INTERVAL=0
TIMEOUT=10
METHOD="GET"
DATA=""
HEADERS=()
AUTH_KEY=""
AUTH_USER=""
AUTH_PASS=""
VERBOSE=false
SHOW_PROGRESS=true
OUTPUT_FORMAT="text" # options: text, json, csv
OUTPUT_FILE=""
ENDPOINTS=()
TEST_DURATION=0  # 0 means unlimited, otherwise in seconds
TEST_TYPE="requests" # options: requests, duration
REQUEST_RATE=0  # requests per second (0 means unlimited)
EXIT_ON_ERROR=false
DEBUG=false

# Import logging utilities if available
if [[ -f "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh"
else
    # Minimal logging
    log_info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
    log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; }
    log_debug() { [[ "$DEBUG" == "true" || "$VERBOSE" == "true" ]] && echo -e "\033[0;37m[DEBUG]\033[0m $1"; }
    log_warning() { echo -e "\033[0;33m[WARNING]\033[0m $1" >&2; }
    log_success() { echo -e "\033[0;32m[SUCCESS]\033[0m $1"; }
fi

# Function to display script usage
usage() {
    cat <<EOF
HTTP Load Testing Tool v${SCRIPT_VERSION}

Usage: $(basename "$0") [options] [URL]

Options:
  -n, --requests NUMBER       Total number of requests to perform (default: ${TOTAL_REQUESTS})
  -c, --concurrency NUMBER    Number of concurrent requests (default: ${CONCURRENT_REQUESTS})
  -t, --timeout SECONDS       Request timeout in seconds (default: ${TIMEOUT})
  -m, --method METHOD         HTTP method to use (default: ${METHOD})
  -H, --header HEADER         Add custom header (can be used multiple times)
  -d, --data DATA             Data to send with request (for POST, PUT, etc.)
  --duration SECONDS          Run test for specified duration instead of request count
  --rate NUMBER               Limit requests per second (0 = unlimited)
  --interval MS               Delay between requests in milliseconds (default: ${REQUEST_INTERVAL})
  -e, --endpoints FILE        File with list of endpoints to test (one per line)
  --auth-key TOKEN            Authorization token/key
  --auth-user USER            Username for basic auth
  --auth-pass PASSWORD        Password for basic auth
  --output-format FORMAT      Output format: text, json, csv (default: ${OUTPUT_FORMAT})
  --output-file FILE          Write results to file instead of stdout
  -q, --quiet                 Suppress progress display
  --exit-on-error             Stop testing when an error occurs
  -v, --verbose               Enable verbose output
  --debug                     Enable debug mode
  -h, --help                  Show this help message

Examples:
  $(basename "$0") https://api.example.com/status      # Simple test with defaults
  $(basename "$0") -n 1000 -c 20 https://api.example.com/status   # 1000 requests, 20 concurrent
  $(basename "$0") --duration 60 -c 50 https://api.example.com/status   # Test for 60 seconds
  $(basename "$0") --auth-key "xyz123" -H "Content-Type: application/json" https://api.example.com/data

This tool supports multiple request methods, custom headers, authentication, and various
output formats for analyzing results. By default it tracks response time and status codes.
EOF
    exit 1
}

# Function to validate input parameters
validate_parameters() {
    # Validate URL if provided
    if [[ -n "$TARGET_URL" && "$TARGET_URL" != http* ]]; then
        log_warning "URL doesn't start with http:// or https:// - adding http://"
        TARGET_URL="http://$TARGET_URL"
    fi

    # Validate numeric parameters
    if ! [[ "$CONCURRENT_REQUESTS" =~ ^[1-9][0-9]*$ ]]; then
        log_error "Concurrency must be a positive integer"
        exit 1
    fi

    if ! [[ "$TOTAL_REQUESTS" =~ ^[1-9][0-9]*$ ]]; then
        log_error "Total requests must be a positive integer"
        exit 1
    fi

    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
        log_error "Timeout must be a non-negative integer"
        exit 1
    fi

    if ! [[ "$REQUEST_INTERVAL" =~ ^[0-9]+$ ]]; then
        log_error "Interval must be a non-negative integer"
        exit 1
    fi

    if ! [[ "$TEST_DURATION" =~ ^[0-9]+$ ]]; then
        log_error "Duration must be a non-negative integer"
        exit 1
    fi

    if ! [[ "$REQUEST_RATE" =~ ^[0-9]+$ ]]; then
        log_error "Rate must be a non-negative integer"
        exit 1
    fi

    # Validate HTTP method
    case "${METHOD^^}" in
        GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)
            # Valid method
            ;;
        *)
            log_error "Unsupported HTTP method: $METHOD"
            exit 1
            ;;
    esac

    # Set test type based on parameters
    if [[ "$TEST_DURATION" -gt 0 ]]; then
        TEST_TYPE="duration"
    else
        TEST_TYPE="requests"
    fi

    # Validate endpoints file if provided
    if [[ -n "$ENDPOINTS_FILE" ]]; then
        if [[ ! -f "$ENDPOINTS_FILE" ]]; then
            log_error "Endpoints file not found: $ENDPOINTS_FILE"
            exit 1
        fi

        # Read endpoints from file
        readarray -t ENDPOINTS < "$ENDPOINTS_FILE"
        log_debug "Loaded ${#ENDPOINTS[@]} endpoints from $ENDPOINTS_FILE"
    fi

    # If we still don't have any endpoints, use the TARGET_URL
    if [[ ${#ENDPOINTS[@]} -eq 0 && -n "$TARGET_URL" ]]; then
        ENDPOINTS=("$TARGET_URL")
    fi

    # Validate that we have at least one endpoint
    if [[ ${#ENDPOINTS[@]} -eq 0 ]]; then
        log_error "No target URLs specified. Use positional parameter or --endpoints"
        exit 1
    fi
}

# Function to perform a single HTTP request and report metrics
perform_request() {
    local url="$1"
    local method="${2:-GET}"
    local result_file="$3"
    local id="$4"
    local start_time
    local status_code
    local response_time
    local curl_args=()

    # Build curl command
    curl_args+=(
        -s                           # Silent mode
        -o /dev/null                 # Don't output response body
        -w "%{http_code},%{time_total},%{size_download},%{time_connect},%{time_starttransfer}" # Output format
        -X "$method"                 # HTTP method
        -m "$TIMEOUT"                # Request timeout
    )

    # Add headers if specified
    for header in "${HEADERS[@]}"; do
        curl_args+=(-H "$header")
    done

    # Add authentication if specified
    if [[ -n "$AUTH_KEY" ]]; then
        curl_args+=(-H "Authorization: Bearer $AUTH_KEY")
    elif [[ -n "$AUTH_USER" && -n "$AUTH_PASS" ]]; then
        curl_args+=(-u "$AUTH_USER:$AUTH_PASS")
    fi

    # Add data if specified
    if [[ -n "$DATA" ]]; then
        curl_args+=(--data "$DATA")
    fi

    # Record start timestamp with nanosecond precision if available
    if [[ -x /usr/bin/date && "$(/usr/bin/date +%N)" != "N" ]]; then
        start_time=$(/usr/bin/date +%s.%N)
    else
        start_time=$(date +%s)
    fi

    # Perform the request
    local result
    result=$(curl "${curl_args[@]}" "$url")
    local exit_code=$?

    # Record end time
    local end_time
    if [[ -x /usr/bin/date && "$(/usr/bin/date +%N)" != "N" ]]; then
        end_time=$(/usr/bin/date +%s.%N)
    else
        end_time=$(date +%s)
    fi

    if [[ $exit_code -eq 0 ]]; then
        # Parse the result (format: status_code,time_total,size_download,time_connect,time_starttransfer)
        IFS=',' read -r status_code response_time size_download time_connect time_starttransfer <<< "$result"

        # Calculate total elapsed time with higher precision if available
        local elapsed
        if [[ "$start_time" == *.* && "$end_time" == *.* ]]; then
            # Use bc for floating point calculation if available
            if command -v bc > /dev/null; then
                elapsed=$(echo "$end_time - $start_time" | bc)
            else
                # Fallback to response_time from curl
                elapsed=$response_time
            fi
        else
            # Integer subtraction as fallback
            elapsed=$((end_time - start_time))
        fi

        # Log the result
        if [[ "$VERBOSE" == "true" ]]; then
            log_debug "Request $id: $url - Status: $status_code, Time: ${response_time}s"
        fi

        # Write to result file (id,url,method,status_code,response_time,size,connect_time,ttfb,timestamp)
        echo "$id,$url,$method,$status_code,$response_time,$size_download,$time_connect,$time_starttransfer,$(date +%s)" >> "$result_file"

        # Check if we need to exit on error
        if [[ "$EXIT_ON_ERROR" == "true" && "$status_code" != 2* ]]; then
            log_error "Request failed with status $status_code - exiting"
            # Signal the main process to stop
            touch "${result_file}.error"
            return 1
        fi
    else
        # Handle curl error
        log_debug "Request $id: $url - curl error: $exit_code"
        echo "$id,$url,$method,0,$TIMEOUT,0,0,0,$(date +%s)" >> "$result_file"

        if [[ "$EXIT_ON_ERROR" == "true" ]]; then
            log_error "Request failed with curl error $exit_code - exiting"
            # Signal the main process to stop
            touch "${result_file}.error"
            return 1
        fi
    fi

    return 0
}

# Function to update the progress bar
update_progress() {
    local completed="$1"
    local total="$2"
    local percent=$((completed * 100 / total))
    local bar_length=50
    local filled_length=$((bar_length * completed / total))

    # Don't show progress in quiet mode
    if [[ "$SHOW_PROGRESS" != "true" ]]; then
        return 0
    fi

    # Create the progress bar
    local bar=""
    for ((i=0; i<filled_length; i++)); do
        bar+="="
    done
    for ((i=filled_length; i<bar_length; i++)); do
        bar+=" "
    done

    # Print the progress bar
    printf "\r[%s] %3d%% (%d/%d)" "$bar" "$percent" "$completed" "$total"

    # Print newline when complete
    if [[ $completed -eq $total ]]; then
        echo
    fi
}

# Function to generate statistics from results
generate_statistics() {
    local result_file="$1"
    local output_format="${2:-text}"
    local output_file="${3:-/dev/stdout}"
    local total_requests=0
    local successful_requests=0
    local failed_requests=0
    local total_time=0
    local min_time=99999
    local max_time=0

    # Initialize arrays for status code tracking
    declare -A status_counts

    # Arrays for percentile calculations
    local times=()

    # Read results file
    while IFS=',' read -r id url method status_code response_time size_download time_connect time_starttransfer timestamp; do
        ((total_requests++))

        # Skip header line if present
        [[ "$id" == "id" ]] && continue

        # Track status codes
        if [[ $status_code -gt 0 ]]; then
            status_counts[$status_code]=$((${status_counts[$status_code]:-0} + 1))

            # Track successful requests (2xx)
            if [[ $status_code -ge 200 && $status_code -lt 300 ]]; then
                ((successful_requests++))

                # Add to times array for percentile calculation (only successful requests)
                times+=("$response_time")

                # Update timing stats
                total_time=$(echo "$total_time + $response_time" | bc -l)

                # Update min/max
                if [[ $(echo "$response_time < $min_time" | bc -l) -eq 1 ]]; then
                    min_time=$response_time
                fi
                if [[ $(echo "$response_time > $max_time" | bc -l) -eq 1 ]]; then
                    max_time=$response_time
                fi
            else
                ((failed_requests++))
            fi
        else
            # Count connection failures
            status_counts["connection_error"]=$((${status_counts["connection_error"]:-0} + 1))
            ((failed_requests++))
        fi
    done < "$result_file"

    # Calculate average time if we have successful requests
    local avg_time=0
    if [[ $successful_requests -gt 0 ]]; then
        avg_time=$(echo "scale=3; $total_time / $successful_requests" | bc -l)
    fi

    # Sort times for percentile calculations
    if [[ ${#times[@]} -gt 0 ]]; then
        # Sort numerically
        IFS=$'\n' times=($(sort -n <<<"${times[*]}"))
        unset IFS
    fi

    # Calculate percentiles
    local p50=0
    local p90=0
    local p95=0
    local p99=0

    if [[ ${#times[@]} -gt 0 ]]; then
        p50_idx=$(echo "scale=0; ${#times[@]} * 0.5 / 1" | bc -l)
        p90_idx=$(echo "scale=0; ${#times[@]} * 0.9 / 1" | bc -l)
        p95_idx=$(echo "scale=0; ${#times[@]} * 0.95 / 1" | bc -l)
        p99_idx=$(echo "scale=0; ${#times[@]} * 0.99 / 1" | bc -l)

        p50=${times[$p50_idx]}
        p90=${times[$p90_idx]}
        p95=${times[$p95_idx]}
        p99=${times[$p99_idx]}
    fi

    # Calculate requests per second
    local duration=$(echo "$total_time / $successful_requests" | bc -l)
    local rps=$(echo "scale=2; $successful_requests / $duration" | bc -l)

    # Generate output based on format
    case "$output_format" in
        json)
            echo "{" > "$output_file"
            echo "  \"summary\": {" >> "$output_file"
            echo "    \"total_requests\": $total_requests," >> "$output_file"
            echo "    \"successful_requests\": $successful_requests," >> "$output_file"
            echo "    \"failed_requests\": $failed_requests," >> "$output_file"
            echo "    \"success_rate\": $(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l)," >> "$output_file"
            echo "    \"total_time\": $(echo "scale=2; $total_time" | bc -l)," >> "$output_file"
            echo "    \"requests_per_second\": $rps" >> "$output_file"
            echo "  }," >> "$output_file"

            echo "  \"timing\": {" >> "$output_file"
            echo "    \"min\": $min_time," >> "$output_file"
            echo "    \"max\": $max_time," >> "$output_file"
            echo "    \"avg\": $avg_time," >> "$output_file"
            echo "    \"p50\": $p50," >> "$output_file"
            echo "    \"p90\": $p90," >> "$output_file"
            echo "    \"p95\": $p95," >> "$output_file"
            echo "    \"p99\": $p99" >> "$output_file"
            echo "  }," >> "$output_file"

            echo "  \"status_codes\": {" >> "$output_file"
            local first=true
            for status in "${!status_counts[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo "," >> "$output_file"
                fi
                echo -n "    \"$status\": ${status_counts[$status]}" >> "$output_file"
            done
            echo "" >> "$output_file"
            echo "  }" >> "$output_file"
            echo "}" >> "$output_file"
            ;;

        csv)
            # Write summary
            echo "Metric,Value" > "$output_file"
            echo "Total Requests,$total_requests" >> "$output_file"
            echo "Successful Requests,$successful_requests" >> "$output_file"
            echo "Failed Requests,$failed_requests" >> "$output_file"
            echo "Success Rate,$(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l)%" >> "$output_file"
            echo "Total Time,$(echo "scale=2; $total_time" | bc -l)" >> "$output_file"
            echo "Requests Per Second,$rps" >> "$output_file"
            echo "Minimum Response Time,$min_time" >> "$output_file"
            echo "Maximum Response Time,$max_time" >> "$output_file"
            echo "Average Response Time,$avg_time" >> "$output_file"
            echo "P50 Response Time,$p50" >> "$output_file"
            echo "P90 Response Time,$p90" >> "$output_file"
            echo "P95 Response Time,$p95" >> "$output_file"
            echo "P99 Response Time,$p99" >> "$output_file"
            echo "" >> "$output_file"

            # Write status codes
            echo "Status Code,Count" >> "$output_file"
            for status in "${!status_counts[@]}"; do
                echo "$status,${status_counts[$status]}" >> "$output_file"
            done
            ;;

        *)
            # Default to text output
            echo "=== Load Test Results ===" > "$output_file"
            echo "Target URL(s): ${ENDPOINTS[*]}" >> "$output_file"
            echo "Concurrency: $CONCURRENT_REQUESTS" >> "$output_file"
            echo "Test Type: $TEST_TYPE" >> "$output_file"
            if [[ "$TEST_TYPE" == "requests" ]]; then
                echo "Total Requests: $TOTAL_REQUESTS" >> "$output_file"
            else
                echo "Test Duration: $TEST_DURATION seconds" >> "$output_file"
            fi
            echo "" >> "$output_file"

            echo "=== Summary ===" >> "$output_file"
            echo "Total Requests:      $total_requests" >> "$output_file"
            echo "Successful Requests: $successful_requests" >> "$output_file"
            echo "Failed Requests:     $failed_requests" >> "$output_file"
            echo "Success Rate:        $(echo "scale=2; $successful_requests * 100 / $total_requests" | bc -l)%" >> "$output_file"
            echo "Total Time:          $(echo "scale=2; $total_time" | bc -l) seconds" >> "$output_file"
            echo "Requests Per Second: $rps" >> "$output_file"
            echo "" >> "$output_file"

            echo "=== Response Time Statistics (seconds) ===" >> "$output_file"
            echo "Minimum: $min_time" >> "$output_file"
            echo "Maximum: $max_time" >> "$output_file"
            echo "Average: $avg_time" >> "$output_file"
            echo "P50:     $p50" >> "$output_file"
            echo "P90:     $p90" >> "$output_file"
            echo "P95:     $p95" >> "$output_file"
            echo "P99:     $p99" >> "$output_file"
            echo "" >> "$output_file"

            echo "=== HTTP Status Codes ===" >> "$output_file"
            for status in "${!status_counts[@]}"; do
                if [[ "$status" == "connection_error" ]]; then
                    echo "Connection Errors: ${status_counts[$status]}" >> "$output_file"
                else
                    echo "Status $status: ${status_counts[$status]}" >> "$output_file"
                fi
            done
            ;;
    esac
}

# Function to check if required commands are available
check_dependencies() {
    local missing_deps=()

    # Check for curl
    if ! command -v curl &>/dev/null; then
        missing_deps+=("curl")
    fi

    # Check for bc (used for floating point math)
    if ! command -v bc &>/dev/null; then
        log_warning "bc is not installed. Accurate timing calculations may not be available."
    fi

    # If any dependencies are missing, exit
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install these dependencies and try again."
        exit 1
    fi
}

# Function to run the load test with a fixed number of requests
run_requests_test() {
    local result_file="$1"
    local completed=0
    local start_time
    local end_time

    # Create header row for results file
    echo "id,url,method,status_code,response_time,size,connect_time,ttfb,timestamp" > "$result_file"

    # Start timer
    start_time=$(date +%s)

    log_info "Starting load test with $TOTAL_REQUESTS total requests across ${#ENDPOINTS[@]} endpoints..."
    log_info "Using $CONCURRENT_REQUESTS concurrent connections"

    # Loop through requests
    for ((i=1; i<=TOTAL_REQUESTS; i++)); do
        # Check if we need to stop due to error
        if [[ -f "${result_file}.error" ]]; then
            log_warning "Stopping test due to error"
            break
        fi

        # Select URL (round-robin through endpoints)
        local url_index=$(( (i - 1) % ${#ENDPOINTS[@]} ))
        local url="${ENDPOINTS[$url_index]}"

        # Run request in background to simulate concurrency
        ((j=j%CONCURRENT_REQUESTS)); ((j++==0)) && wait
        perform_request "$url" "$METHOD" "$result_file" "$i" &

        # Update progress bar
        ((completed++))
        update_progress $completed $TOTAL_REQUESTS

        # Sleep for rate limiting if specified
        if [[ "$REQUEST_RATE" -gt 0 ]]; then
            sleep $(echo "scale=3; 1/$REQUEST_RATE" | bc -l)
        elif [[ "$REQUEST_INTERVAL" -gt 0 ]]; then
            # Convert milliseconds to seconds
            sleep $(echo "scale=3; $REQUEST_INTERVAL/1000" | bc -l)
        fi
    done

    # Wait for all background jobs to finish
    wait

    # End timer
    end_time=$(date +%s)

    # Clean up error file if it exists
    [[ -f "${result_file}.error" ]] && rm -f "${result_file}.error"

    # Calculate total duration
    local duration=$((end_time - start_time))
    log_info "Load test completed in $duration seconds"
}

# Function to run the load test for a specified duration
run_duration_test() {
    local result_file="$1"
    local completed=0
    local start_time
    local current_time
    local end_time_target

    # Create header row for results file
    echo "id,url,method,status_code,response_time,size,connect_time,ttfb,timestamp" > "$result_file"

    # Calculate end time
    start_time=$(date +%s)
    end_time_target=$((start_time + TEST_DURATION))

    log_info "Starting load test for $TEST_DURATION seconds across ${#ENDPOINTS[@]} endpoints..."
    log_info "Using $CONCURRENT_REQUESTS concurrent connections"

    # Loop until duration is reached
    while true; do
        # Check current time
        current_time=$(date +%s)
        if [[ $current_time -ge $end_time_target ]]; then
            break
        fi

        # Check if we need to stop due to error
        if [[ -f "${result_file}.error" ]]; then
            log_warning "Stopping test due to error"
            break
        fi

        # Calculate and show progress
        local elapsed=$((current_time - start_time))
        local percent=$((elapsed * 100 / TEST_DURATION))
        if [[ "$SHOW_PROGRESS" == "true" ]]; then
            printf "\rProgress: %d%% (%d/%d seconds)" $percent $elapsed $TEST_DURATION
        fi

        # Select URL (round-robin through endpoints)
        local url_index=$(( (completed % ${#ENDPOINTS[@]}) ))
        local url="${ENDPOINTS[$url_index]}"

        # Run request in background to simulate concurrency
        ((j=j%CONCURRENT_REQUESTS)); ((j++==0)) && wait
        perform_request "$url" "$METHOD" "$result_file" "$((++completed))" &

        # Sleep for rate limiting if specified
        if [[ "$REQUEST_RATE" -gt 0 ]]; then
            sleep $(echo "scale=3; 1/$REQUEST_RATE" | bc -l)
        elif [[ "$REQUEST_INTERVAL" -gt 0 ]]; then
            # Convert milliseconds to seconds
            sleep $(echo "scale=3; $REQUEST_INTERVAL/1000" | bc -l)
        fi
    done

    # Wait for all background jobs to finish
    wait
    echo # New line after progress bar

    # Clean up error file if it exists
    [[ -f "${result_file}.error" ]] && rm -f "${result_file}.error"

    # Calculate total duration
    log_info "Load test completed with $completed requests in $TEST_DURATION seconds"
}

# Parse command line arguments
ENDPOINTS_FILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--requests)
            TOTAL_REQUESTS="$2"
            shift 2
            ;;
        -c|--concurrency)
            CONCURRENT_REQUESTS="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -m|--method)
            METHOD="$2"
            shift 2
            ;;
        -H|--header)
            HEADERS+=("$2")
            shift 2
            ;;
        -d|--data)
            DATA="$2"
            shift 2
            ;;
        --duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --rate)
            REQUEST_RATE="$2"
            shift 2
            ;;
        --interval)
            REQUEST_INTERVAL="$2"
            shift 2
            ;;
        -e|--endpoints)
            ENDPOINTS_FILE="$2"
            shift 2
            ;;
        --auth-key)
            AUTH_KEY="$2"
            shift 2
            ;;
        --auth-user)
            AUTH_USER="$2"
            shift 2
            ;;
        --auth-pass)
            AUTH_PASS="$2"
            shift 2
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --output-file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -q|--quiet)
            SHOW_PROGRESS=false
            shift
            ;;
        --exit-on-error)
            EXIT_ON_ERROR=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        http*|/*|./*|../*|*://*) # URL patterns
            ENDPOINTS+=("$1")
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Main execution flow
check_dependencies
validate_parameters

# Create temporary file for results
TEMP_DIR=$(mktemp -d)
RESULTS_FILE="${TEMP_DIR}/load_test_results_$(date +%Y%m%d_%H%M%S).csv"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Run the appropriate test type
if [[ "$TEST_TYPE" == "requests" ]]; then
    run_requests_test "$RESULTS_FILE"
else
    run_duration_test "$RESULTS_FILE"
fi

# Generate statistics
log_info "Generating statistics..."
if [[ -n "$OUTPUT_FILE" ]]; then
    generate_statistics "$RESULTS_FILE" "$OUTPUT_FORMAT" "$OUTPUT_FILE"
    log_success "Results written to $OUTPUT_FILE"
else
    generate_statistics "$RESULTS_FILE" "$OUTPUT_FORMAT"
fi

log_success "Load test completed successfully."
exit 0
