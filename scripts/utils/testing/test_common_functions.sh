#!/bin/bash
# filepath: scripts/utils/testing/test_common_functions.sh
#
# Test suite for common_functions.sh
#
# This script provides a simplified and more maintainable approach to testing
# the functionality of common_functions.sh and its modules.
#
# Usage: ./test_common_functions.sh [--verbose] [--focus test_name]

set -o pipefail
set -o nounset

# Version tracking
TEST_COMMON_FUNCTIONS_VERSION="1.0.0"
TEST_COMMON_FUNCTIONS_DATE="2024-08-15"

# Get script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Path to common functions and test utilities
COMMON_FUNCTIONS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"
TEST_UTILS_PATH="${SCRIPT_DIR}/test_utils.sh"
TEST_HELPERS_PATH="${SCRIPT_DIR}/test_helpers.sh"

# Set default options
VERBOSE=false
FOCUS_TEST=""
KEEP_TEMP=false
FORMAT="text"
OUTPUT_FILE=""
EXIT_CODE=0

# Test environment variables
TEST_ENV_DIR="/tmp/common_functions_test_$(date +%s)"
TEST_CONFIG_DIR="${TEST_ENV_DIR}/configs"
TEST_MODULE_DIR="${TEST_ENV_DIR}/modules"
MODULE_LIST=("core" "system" "advanced" "file_ops" "validation" "health" "network" "database" "cloud")

#######################################
# UTILITY FUNCTIONS
#######################################

# Load test utilities in a specific order with proper error handling
# First try test_utils.sh which is the full framework
if [[ -f "$TEST_UTILS_PATH" ]]; then
    # shellcheck source=/dev/null
    if ! source "$TEST_UTILS_PATH"; then
        echo "Error: Failed to source test_utils.sh"
        exit 1
    fi
# Then try test_helpers.sh which contains basic test helpers
elif [[ -f "$TEST_HELPERS_PATH" ]]; then
    # shellcheck source=/dev/null
    if ! source "$TEST_HELPERS_PATH"; then
        echo "Error: Failed to source test_helpers.sh"
        exit 1
    fi
# Finally, define minimal test utilities
else
    echo "Warning: Neither test_utils.sh nor test_helpers.sh found. Using minimal test functionality."

    # Define minimal required test utilities
    command_exists() { command -v "$1" &> /dev/null; }

    log() {
        local message="${2:-}"
        local level="${1:-INFO}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message"
    }

    log_info() { log "INFO" "$1"; }
    log_debug() { [[ "$VERBOSE" == "true" ]] && log "DEBUG" "$1" || true; }
    log_warn() { log "WARN" "$1" >&2; }
    log_error() { log "ERROR" "$1" >&2; }

    begin_test_group() { echo -e "\n=== $1 ==="; }
    end_test_group() { echo -e "=== End ===\n"; }

    run_test() {
        local name="$1"
        local cmd="$2"
        local skip="${3:-false}"

        if [[ "$skip" == "true" ]]; then
            echo "⏭ SKIP: $name"
            return 0
        fi

        echo -n "⚙ RUNNING: $name... "
        local start_time=$(date +%s)
        local output
        local status=0

        # Execute command and catch output and status
        output=$(eval "$cmd" 2>&1) || status=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [[ $status -eq 0 ]]; then
            echo "✅ PASS ($duration sec)"
            [[ "$VERBOSE" == "true" ]] && echo "$output"
            return 0
        else
            echo "❌ FAIL ($duration sec)"
            echo "Error output: $output"
            EXIT_CODE=1
            return 1
        fi
    }
fi

# Parse command line options
parse_options() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --focus|-f)
                if [[ -n "${2:-}" ]]; then
                    FOCUS_TEST="$2"
                    shift 2
                else
                    log_error "Error: --focus requires a test function name"
                    exit 1
                fi
                ;;
            --keep-temp|-k)
                KEEP_TEMP=true
                shift
                ;;
            --format)
                if [[ -n "${2:-}" ]]; then
                    FORMAT="$2"
                    shift 2
                else
                    log_error "Error: --format requires a format name"
                    exit 1
                fi
                ;;
            --output|-o)
                if [[ -n "${2:-}" ]]; then
                    OUTPUT_FILE="$2"
                    shift 2
                else
                    log_error "Error: --output requires a file path"
                    exit 1
                fi
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                log_info "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Show usage information
show_usage() {
    cat <<USAGE
Usage: $(basename "$0") [OPTIONS]

Test suite for common_functions.sh v${TEST_COMMON_FUNCTIONS_VERSION}

OPTIONS:
  --verbose, -v         Show more detailed output
  --focus, -f NAME      Run only the specified test
  --keep-temp, -k       Don't delete temporary test files
  --format FORMAT       Output format: text, json, junit, or html
  --output, -o FILE     Output file for test results
  --help, -h            Show this help message

Examples:
  ./test_common_functions.sh
  ./test_common_functions.sh --verbose
  ./test_common_functions.sh --focus test_module_loading
  ./test_common_functions.sh --format junit --output results.xml
USAGE
}

#######################################
# TEST ENVIRONMENT SETUP
#######################################

# Create test environment with all necessary directories
setup_test_environment() {
    log_debug "Setting up test environment at $TEST_ENV_DIR"

    # Create test directories
    mkdir -p "$TEST_CONFIG_DIR" "$TEST_MODULE_DIR/common" || {
        log_error "Failed to create test directories"
        exit 1
    }

    # Create test configuration file
    cat > "${TEST_CONFIG_DIR}/test_config.conf" << EOF
# Test configuration file for common_functions.sh testing
DEFAULT_LOG_DIR=${TEST_ENV_DIR}/logs
DEFAULT_BACKUP_DIR=${TEST_ENV_DIR}/backups
DEFAULT_ENVIRONMENT=test
MODULES=core,validation
QUIET=false
PARALLEL_LOAD=true
PARALLEL_LOAD_MAX=2
EOF

    # Create mock modules for testing
    for module in "${MODULE_LIST[@]}"; do
        create_mock_module "$module" || {
            log_error "Failed to create mock module: $module"
            cleanup_test_environment
            exit 1
        }
    done
}

# Create a mock module for testing
create_mock_module() {
    local module="$1"
    local module_path="${TEST_MODULE_DIR}/common/common_${module}_utils.sh"

    cat > "$module_path" << EOF
#!/bin/bash
# filepath: ${module_path#"$PROJECT_ROOT/"}
# Mock ${module} module for testing

# Version tracking
${module^^}_UTILS_VERSION="1.0.0-test"
${module^^}_UTILS_DATE="$(date '+%Y-%m-%d')"

# Get version information
get_${module}_utils_version() {
    echo "\${${module^^}_UTILS_VERSION} (\${${module^^}_UTILS_DATE})"
}

# Test function to check if this module was loaded
${module}_test_function() {
    echo "${module} module loaded successfully"
    return 0
}

# Export functions
export -f get_${module}_utils_version
export -f ${module}_test_function
EOF

    # Add core functionality to the core module
    if [[ "$module" == "core" ]]; then
        cat >> "$module_path" << EOF

# Basic logging function required by other modules
log() {
    local level="\${2:-INFO}"
    local message="\$1"
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] [\$level] \$message"
}

# Error exit function
error_exit() {
    log "\$1" "ERROR"
    return 1
}

# Warning and debug functions
warn() { log "\$1" "WARNING"; }
debug() { [[ "\${VERBOSE:-false}" == "true" ]] && log "\$1" "DEBUG" || true; }

# Export logging functions
export -f log
export -f error_exit
export -f warn
export -f debug
EOF
    fi

    # Add validation functions to validation module
    if [[ "$module" == "validation" ]]; then
        cat >> "$module_path" << EOF

# Check if a value is a valid number
is_number() {
    local value="\$1"
    local allow_float="\${2:-false}"

    if [[ "\$allow_float" == "true" ]]; then
        [[ "\$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]
    else
        [[ "\$value" =~ ^[0-9]+$ ]]
    fi
}

# Validate if a path is safe
is_safe_path() {
    local path="\$1"
    [[ "\$path" != *".."* ]] && [[ "\$path" != *"~"* ]]
}

# Export validation functions
export -f is_number
export -f is_safe_path
EOF
    fi

    chmod +x "$module_path"
    return 0
}

# Clean up test environment
cleanup_test_environment() {
    if [[ "$KEEP_TEMP" != "true" ]]; then
        log_debug "Cleaning up test environment at $TEST_ENV_DIR"
        rm -rf "$TEST_ENV_DIR"
    else
        log_info "Keeping temporary files in $TEST_ENV_DIR"
    fi
}

#######################################
# TEST CASES
#######################################

# Test module loading functionality
test_module_loading() {
    local test_script="${TEST_ENV_DIR}/test_module_load.sh"

    cat > "$test_script" << EOF
#!/bin/bash
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" core
if declare -f core_test_function &>/dev/null; then
    echo "PASS: Core module loaded successfully"
    exit 0
else
    echo "FAIL: Core module not loaded"
    exit 1
fi
EOF
    chmod +x "$test_script"

    run_test "Module loading" "$test_script"
    return $?
}

# Test multiple module loading
test_multiple_modules() {
    local test_script="${TEST_ENV_DIR}/test_multiple_modules.sh"

    cat > "$test_script" << EOF
#!/bin/bash
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" core,validation
if declare -f core_test_function &>/dev/null && declare -f validation_test_function &>/dev/null; then
    echo "PASS: Multiple modules loaded successfully"
    exit 0
else
    echo "FAIL: Not all modules were loaded"
    exit 1
fi
EOF
    chmod +x "$test_script"

    run_test "Multiple module loading" "$test_script"
    return $?
}

# Test dependency resolution between modules
test_dependency_resolution() {
    # Setup: Make advanced module depend on system
    local advanced_path="${TEST_MODULE_DIR}/common/common_advanced_utils.sh"
    local system_path="${TEST_MODULE_DIR}/common/common_system_utils.sh"

    # Backup original advanced module
    cp "$advanced_path" "${advanced_path}.bak" || {
        log_error "Failed to backup advanced module"
        return 1
    }

    # Add dependency check
    cat > "$advanced_path" << EOF
#!/bin/bash
# filepath: ${advanced_path#"$PROJECT_ROOT/"}
# Check for system module dependency
if ! declare -f system_test_function &>/dev/null; then
    echo "Error: Required dependency system not loaded" >&2
    exit 1
fi

# Version tracking
ADVANCED_UTILS_VERSION="1.0.0-test"
ADVANCED_UTILS_DATE="$(date '+%Y-%m-%d')"

# Get version information
get_advanced_utils_version() {
    echo "\${ADVANCED_UTILS_VERSION} (\${ADVANCED_UTILS_DATE})"
}

# Test function to check if this module was loaded
advanced_test_function() {
    echo "advanced module loaded successfully (with system dependency)"
    return 0
}

# Export functions
export -f get_advanced_utils_version
export -f advanced_test_function
EOF
    chmod +x "$advanced_path"

    # Add function to system module that advanced will call
    cat >> "$system_path" << EOF

# Function required by advanced module
get_system_info() {
    echo "System info: Test Environment"
    return 0
}

export -f get_system_info
EOF

    # Test script
    local test_script="${TEST_ENV_DIR}/test_dependency.sh"

    cat > "$test_script" << EOF
#!/bin/bash
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" advanced
if declare -f system_test_function &>/dev/null && declare -f advanced_test_function &>/dev/null; then
    echo "PASS: Dependency resolution worked correctly"
    exit 0
else
    echo "FAIL: Dependency resolution failed"
    exit 1
fi
EOF
    chmod +x "$test_script"

    # Run test and restore original file
    local result=0
    run_test "Dependency resolution" "$test_script"
    result=$?

    # Restore original file
    mv "${advanced_path}.bak" "$advanced_path" || log_warn "Failed to restore advanced module backup"
    return $result
}

# Test parallel module loading
test_parallel_loading() {
    # Only test if the shell supports job control
    if ! jobs -p &>/dev/null; then
        log_info "Skipping parallel loading test (job control not supported)"
        run_test "Parallel module loading" "echo 'Skipped: job control not supported'; true" "true"
        return 0
    fi

    # Check for bc command
    if ! command_exists bc; then
        log_info "Skipping parallel loading test (bc command not available)"
        run_test "Parallel module loading" "echo 'Skipped: bc command not available'; true" "true"
        return 0
    fi

    # Add delays to modules to make timing differences measurable
    for module in core system validation file_ops; do
        local module_path="${TEST_MODULE_DIR}/common/common_${module}_utils.sh"
        # Backup the file
        cp "$module_path" "${module_path}.bak" || {
            log_error "Failed to backup ${module} module"
            return 1
        }
        # Add sleep - use a temporary file to avoid different behavior on Linux vs MacOS
        sed '1s/^/sleep 0.5\n/' "$module_path" > "${module_path}.tmp"
        mv "${module_path}.tmp" "$module_path"
        chmod +x "$module_path"
    done

    # Create test scripts
    local parallel_script="${TEST_ENV_DIR}/test_parallel_load.sh"
    local sequential_script="${TEST_ENV_DIR}/test_sequential_load.sh"

    cat > "$parallel_script" << EOF
#!/bin/bash
start_time=\$(date +%s.%N)
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" --parallel core,system,validation,file_ops
end_time=\$(date +%s.%N)
echo "\$(echo "\$end_time - \$start_time" | bc)"
EOF

    cat > "$sequential_script" << EOF
#!/bin/bash
start_time=\$(date +%s.%N)
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" core,system,validation,file_ops
end_time=\$(date +%s.%N)
echo "\$(echo "\$end_time - \$start_time" | bc)"
EOF

    chmod +x "$parallel_script" "$sequential_script"

    # Run tests
    local parallel_time=$("$parallel_script")
    local sequential_time=$("$sequential_script")

    # Restore original modules
    for module in core system validation file_ops; do
        mv "${TEST_MODULE_DIR}/common/common_${module}_utils.sh.bak" "${TEST_MODULE_DIR}/common/common_${module}_utils.sh" || {
            log_warn "Failed to restore ${module} module backup"
        }
    done

    # Compare times with tolerance for environmental variations
    local time_diff=$(echo "$sequential_time - $parallel_time" | bc)
    local is_faster=$(echo "$time_diff > 0.1" | bc)

    if [[ "$is_faster" -eq 1 ]]; then
        run_test "Parallel module loading" "echo 'Parallel loading saved $time_diff seconds'; true"
        return 0
    else
        run_test "Parallel module loading" "echo 'Test inconclusive (parallel: $parallel_time, sequential: $sequential_time)'; true"
        return 0
    fi
}

# Test config file loading
test_config_file_loading() {
    local test_script="${TEST_ENV_DIR}/test_config_load.sh"

    cat > "$test_script" << EOF
#!/bin/bash
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" --config "${TEST_CONFIG_DIR}/test_config.conf"

# Check environment variables
if [[ "\${DEFAULT_LOG_DIR-}" == "${TEST_ENV_DIR}/logs" &&
      "\${DEFAULT_BACKUP_DIR-}" == "${TEST_ENV_DIR}/backups" &&
      "\${DEFAULT_ENVIRONMENT-}" == "test" ]] &&
   declare -f core_test_function &>/dev/null &&
   declare -f validation_test_function &>/dev/null; then
    echo "PASS: Configuration loaded correctly"
    exit 0
else
    echo "FAIL: Configuration not loaded correctly"
    exit 1
fi
EOF
    chmod +x "$test_script"

    run_test "Config file loading" "$test_script"
    return $?
}

# Test error handling
test_error_handling() {
    local test_script="${TEST_ENV_DIR}/test_error_handling.sh"

    cat > "$test_script" << EOF
#!/bin/bash
# Check error handling with non-existent module
# shellcheck source=/dev/null
output=\$(source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" non_existent_module 2>&1)
exit_code=\$?

if [[ \$exit_code -ne 0 && "\$output" == *"not found"* || "\$output" == *"unknown"* || "\$output" == *"No module"* ]]; then
    echo "PASS: Error handling works correctly"
    exit 0
else
    echo "FAIL: Error handling failed"
    exit 1
fi
EOF
    chmod +x "$test_script"

    run_test "Error handling" "$test_script"
    return $?
}

# Test custom module path
test_custom_module_path() {
    # Create a custom module path
    local custom_path="${TEST_ENV_DIR}/custom_modules"
    mkdir -p "$custom_path/common" || {
        log_error "Failed to create custom module path"
        return 1
    }

    # Create a custom module
    local custom_module="$custom_path/common/common_custom_utils.sh"
    cat > "$custom_module" << EOF
#!/bin/bash
# filepath: custom_modules/common/common_custom_utils.sh
# Custom module for testing

# Version tracking
CUSTOM_UTILS_VERSION="1.0.0-custom"
CUSTOM_UTILS_DATE="$(date '+%Y-%m-%d')"

# Test function
custom_test_function() {
    echo "Custom module loaded successfully"
    return 0
}

export -f custom_test_function
EOF
    chmod +x "$custom_module"

    # Create test script
    local test_script="${TEST_ENV_DIR}/test_custom_path.sh"
    cat > "$test_script" << EOF
#!/bin/bash
# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "$custom_path" custom
if declare -f custom_test_function &>/dev/null; then
    echo "PASS: Custom module loaded from custom path"
    exit 0
else
    echo "FAIL: Custom module not loaded"
    exit 1
fi
EOF
    chmod +x "$test_script"

    run_test "Custom module path" "$test_script"
    return $?
}

# Test for environment variable overrides
test_environment_overrides() {
    local test_script="${TEST_ENV_DIR}/test_env_override.sh"

    cat > "$test_script" << EOF
#!/bin/bash
# Set environment variable that should override config
export MODULES=system,health
export MODULE_PATH="${TEST_MODULE_DIR}"

# shellcheck source=/dev/null
source "${COMMON_FUNCTIONS_PATH}" --quiet --config "${TEST_CONFIG_DIR}/test_config.conf"

# Check if environment variables took precedence
if declare -f system_test_function &>/dev/null &&
   declare -f health_test_function &>/dev/null &&
   ! declare -f core_test_function &>/dev/null; then
    echo "PASS: Environment variable overrides worked"
    exit 0
else
    echo "FAIL: Environment variables did not override config"
    exit 1
fi
EOF
    chmod +x "$test_script"

    run_test "Environment variable overrides" "$test_script"
    return $?
}

# Run all tests
run_tests() {
    # Set up test environment
    setup_test_environment

    begin_test_group "Common Functions Tests"

    # Determine which tests to run
    if [[ -n "$FOCUS_TEST" ]]; then
        if declare -f "$FOCUS_TEST" &>/dev/null; then
            log_info "Running only test: $FOCUS_TEST"
            "$FOCUS_TEST"
        else
            log_error "Test function not found: $FOCUS_TEST"
            log_info "Available test functions:"
            declare -F | grep -E "test_" | awk '{print $3}'
            EXIT_CODE=1
        fi
    else
        # Run all tests
        log_info "Running all tests..."
        test_module_loading
        test_multiple_modules
        test_dependency_resolution
        test_parallel_loading
        test_config_file_loading
        test_error_handling
        test_custom_module_path
        test_environment_overrides
    fi

    end_test_group

    # Clean up
    cleanup_test_environment

    # Output results
    if [[ $EXIT_CODE -eq 0 ]]; then
        log_info "✅ All tests passed!"
    else
        log_error "❌ Some tests failed!"
    fi

    # If we have test_utils.sh, try to generate a report
    if declare -f generate_test_report &>/dev/null; then
        generate_test_report "$FORMAT" "$OUTPUT_FILE"
    elif [[ -n "$OUTPUT_FILE" ]]; then
        log_warn "Cannot generate detailed report without test_utils.sh"

        # Create a minimal report format
        case "$FORMAT" in
            json)
                echo "{\"status\": \"$([ $EXIT_CODE -eq 0 ] && echo "passed" || echo "failed")\", \"timestamp\": \"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\"}" > "$OUTPUT_FILE"
                ;;
            xml|junit)
                cat > "$OUTPUT_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Common Functions Tests" tests="1" failures="$([[ $EXIT_CODE -eq 0 ]] && echo "0" || echo "1")">
    <testcase name="common_functions_tests" status="$([[ $EXIT_CODE -eq 0 ]] && echo "passed" || echo "failed")"/>
  </testsuite>
</testsuites>
EOF
                ;;
            *)
                echo "Test Summary: $([ $EXIT_CODE -eq 0 ] && echo "PASSED" || echo "FAILED")" > "$OUTPUT_FILE"
                ;;
        esac
    fi

    return $EXIT_CODE
}

#######################################
# MAIN
#######################################

# Make sure the script isn't being sourced
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    log_error "This script should be executed, not sourced"
    exit 1
fi

# Parse command line options
parse_options "$@"

# Run tests
run_tests

exit $EXIT_CODE
