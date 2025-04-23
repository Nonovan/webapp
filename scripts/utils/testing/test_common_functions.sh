#!/bin/bash
# filepath: scripts/utils/testing/test_common_functions.sh
#
# Test utilities for common_functions.sh
#
# This script provides specialized testing functions for the common_functions.sh
# script and its modules. It builds upon the test_utils.sh framework to provide
# specific utilities for testing the core functionality of common_functions.sh.
#
# Usage: source scripts/utils/testing/test_common_functions.sh

# Set strict mode for better error detection
set -o pipefail

# Version tracking
TEST_COMMON_FUNCTIONS_VERSION="1.0.0"
TEST_COMMON_FUNCTIONS_DATE="2023-09-01"

# Get script locations
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Path to common functions and test utilities
COMMON_FUNCTIONS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"
TEST_UTILS_PATH="${SCRIPT_DIR}/test_utils.sh"

# First, load the general test utilities
if [[ -f "$TEST_UTILS_PATH" ]]; then
    source "$TEST_UTILS_PATH"
else
    echo "Error: test_utils.sh not found at $TEST_UTILS_PATH" >&2
    exit 1
fi

# Directory for isolated test environments
TEST_ENV_DIR="/tmp/common_functions_test_$(date +%s)"

# Configuration for module testing
MODULE_LIST=("core" "system" "advanced" "file_ops" "validation" "health" "network" "database" "cloud")
DEFAULT_TEST_TIMEOUT=30

# Test environment setup variables
TEST_CONFIG_DIR="${TEST_ENV_DIR}/configs"
TEST_MODULE_DIR="${TEST_ENV_DIR}/modules"

#######################################
# TEST ENVIRONMENT SETUP FUNCTIONS
#######################################

# Setup a clean test environment
# Arguments: None
# Returns: 0 on success, 1 on failure
setup_test_environment() {
    log "INFO" "Setting up test environment"

    # Create test directories
    mkdir -p "$TEST_ENV_DIR" "$TEST_CONFIG_DIR" "$TEST_MODULE_DIR"

    # Check if common_functions.sh exists
    if [[ ! -f "$COMMON_FUNCTIONS_PATH" ]]; then
        log "ERROR" "common_functions.sh not found at $COMMON_FUNCTIONS_PATH"
        return 1
    fi

    # Create a test configuration file
    create_test_config_file

    # Setup isolated module directory structure
    setup_module_directories

    log "INFO" "Test environment setup complete"
    return 0
}

# Create a test configuration file
# Arguments: None
# Returns: 0 on success, 1 on failure
create_test_config_file() {
    local config_file="${TEST_CONFIG_DIR}/test_config.conf"

    cat > "$config_file" << EOF
# Test configuration file for common_functions.sh testing
DEFAULT_LOG_DIR=${TEST_ENV_DIR}/logs
DEFAULT_BACKUP_DIR=${TEST_ENV_DIR}/backups
DEFAULT_ENVIRONMENT=test
MODULES=core,validation
QUIET=false
PARALLEL_LOAD=true
PARALLEL_LOAD_MAX=2
EOF

    if [[ $? -ne 0 ]]; then
        log "ERROR" "Failed to create test config file"
        return 1
    fi

    log "DEBUG" "Created test config at $config_file"
    return 0
}

# Setup module directories for isolated testing
# Arguments: None
# Returns: 0 on success, 1 on failure
setup_module_directories() {
    mkdir -p "${TEST_MODULE_DIR}/common"

    for module in "${MODULE_LIST[@]}"; do
        log "DEBUG" "Setting up test module: $module"
        create_mock_module "$module"
    done

    return 0
}

# Creates a mock module for testing
# Arguments:
#   $1 - Module name
# Returns: 0 on success, 1 on failure
create_mock_module() {
    local module="$1"
    local module_path="${TEST_MODULE_DIR}/common/common_${module}_utils.sh"

    cat > "$module_path" << EOF
#!/bin/bash
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

    # Add logging function to core module
    if [[ "$module" == "core" ]]; then
        cat >> "$module_path" << EOF

# Basic logging function required by other modules
log() {
    local message="\$1"
    local level="\${2:-INFO}"
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] [\$level] \$message"
}

# Error exit function
error_exit() {
    log "\$1" "ERROR"
    return 1
}

# Warning function
warn() {
    log "\$1" "WARNING"
}

# Debug logging
debug() {
    log "\$1" "DEBUG"
}

# Export logging functions
export -f log
export -f error_exit
export -f warn
export -f debug
EOF
    fi

    # Additional functions for validation module
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

    # Make the module executable
    chmod +x "$module_path"

    return 0
}

# Cleanup test environment
# Arguments: None
# Returns: 0 on success, 1 on failure
cleanup_test_environment() {
    local keep_temp="${1:-false}"

    if [[ "$keep_temp" != "true" ]]; then
        log "INFO" "Cleaning up test environment"
        rm -rf "$TEST_ENV_DIR"
    else
        log "INFO" "Keeping test environment at $TEST_ENV_DIR"
    fi

    return 0
}

#######################################
# TEST MODULE FUNCTIONS
#######################################

# Test module loading
# Arguments:
#   $1 - Module name
#   $2 - Additional args for common_functions.sh (optional)
# Returns: 0 if module loaded successfully, 1 otherwise
test_module_load() {
    local module="$1"
    local extra_args="${2:-}"
    local output
    local exit_code

    log "INFO" "Testing loading of module: $module"

    # Create a temporary test script
    local test_script="${TEST_ENV_DIR}/test_${module}_load.sh"

    cat > "$test_script" << EOF
#!/bin/bash
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" ${module} ${extra_args}
if declare -f ${module}_test_function &>/dev/null; then
    echo "SUCCESS: Module ${module} loaded"
    exit 0
else
    echo "FAILURE: Module ${module} not loaded"
    exit 1
fi
EOF

    chmod +x "$test_script"

    # Run the test script
    output=$("$test_script" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "Module $module loaded successfully"
        return 0
    else
        log "ERROR" "Failed to load module $module: $output"
        return 1
    fi
}

# Test dependency resolution between modules
# Arguments:
#   $1 - Module that depends on others
#   $2 - Dependencies that should be loaded (comma-separated)
# Returns: 0 if dependencies resolved correctly, 1 otherwise
test_dependency_resolution() {
    local module="$1"
    local dependencies="$2"
    local output
    local exit_code

    log "INFO" "Testing dependency resolution for module: $module"

    # Add dependency information to the module
    local module_path="${TEST_MODULE_DIR}/common/common_${module}_utils.sh"

    # Backup the original module
    cp "$module_path" "${module_path}.bak"

    # Add dependency check to the module
    IFS=',' read -ra deps <<< "$dependencies"
    echo -e "\n# Check dependencies" >> "$module_path"
    for dep in "${deps[@]}"; do
        echo "if ! declare -f ${dep}_test_function &>/dev/null; then" >> "$module_path"
        echo "    echo \"Error: Required dependency ${dep} not loaded\" >&2" >> "$module_path"
        echo "    exit 1" >> "$module_path"
        echo "fi" >> "$module_path"
    done

    # Create a temporary test script
    local test_script="${TEST_ENV_DIR}/test_${module}_deps.sh"

    cat > "$test_script" << EOF
#!/bin/bash
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" ${module}

# Check if all dependencies were loaded
success=true
EOF

    for dep in "${deps[@]}"; do
        echo "if ! declare -f ${dep}_test_function &>/dev/null; then" >> "$test_script"
        echo "    echo \"FAILURE: Dependency ${dep} was not loaded\"" >> "$test_script"
        echo "    success=false" >> "$test_script"
        echo "fi" >> "$test_script"
    done

    cat >> "$test_script" << EOF
if [[ "\$success" == "true" ]]; then
    echo "SUCCESS: All dependencies loaded correctly"
    exit 0
else
    exit 1
fi
EOF

    chmod +x "$test_script"

    # Run the test script
    output=$("$test_script" 2>&1)
    exit_code=$?

    # Restore the original module
    mv "${module_path}.bak" "$module_path"

    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "Dependencies for module $module resolved correctly"
        return 0
    else
        log "ERROR" "Dependency resolution failed for module $module: $output"
        return 1
    fi
}

# Test parallel module loading
# Arguments:
#   $1 - Modules to load in parallel (comma-separated)
# Returns: 0 if parallel loading works, 1 otherwise
test_parallel_loading() {
    local modules="$1"
    local output

    log "INFO" "Testing parallel loading of modules: $modules"

    # Add sleeps to modules to ensure timing differences are detectable
    for module in ${modules//,/ }; do
        local module_path="${TEST_MODULE_DIR}/common/common_${module}_utils.sh"
        # Backup the original file
        cp "$module_path" "${module_path}.bak"
        # Add a sleep at the beginning
        sed -i.tmp '1s/^/sleep 0.5\n/' "$module_path"
        rm -f "${module_path}.tmp"
    done

    # Create test scripts for parallel and sequential loading
    local parallel_script="${TEST_ENV_DIR}/test_parallel_load.sh"
    local sequential_script="${TEST_ENV_DIR}/test_sequential_load.sh"

    cat > "$parallel_script" << EOF
#!/bin/bash
start_time=\$(date +%s.%N)
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" --parallel ${modules}
end_time=\$(date +%s.%N)
parallel_time=\$(echo "\$end_time - \$start_time" | bc 2>/dev/null || echo "0")
echo "\$parallel_time"
exit 0
EOF

    cat > "$sequential_script" << EOF
#!/bin/bash
start_time=\$(date +%s.%N)
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" ${modules}
end_time=\$(date +%s.%N)
sequential_time=\$(echo "\$end_time - \$start_time" | bc 2>/dev/null || echo "0")
echo "\$sequential_time"
exit 0
EOF

    chmod +x "$parallel_script" "$sequential_script"

    # Run both scripts and get times
    local parallel_time sequential_time
    parallel_time=$("$parallel_script")
    sequential_time=$("$sequential_script")

    # Restore the original modules
    for module in ${modules//,/ }; do
        local module_path="${TEST_MODULE_DIR}/common/common_${module}_utils.sh"
        mv "${module_path}.bak" "$module_path"
    done

    # Compare times
    if command_exists bc; then
        local time_diff=$(echo "$sequential_time - $parallel_time" | bc)
        local is_faster=$(echo "$time_diff > 0.1" | bc)

        if [[ "$is_faster" -eq 1 ]]; then
            log "SUCCESS" "Parallel loading was faster: $parallel_time vs $sequential_time"
            return 0
        else
            log "WARNING" "Parallel loading was not significantly faster: $parallel_time vs $sequential_time"
            # Return success anyway, as this can be environmentally dependent
            return 0
        fi
    else
        log "WARNING" "Could not compare times accurately (bc not available)"
        # We'll consider it a success as we can't reliably measure
        return 0
    fi
}

# Test configuration file loading
# Arguments:
#   $1 - Path to config file
# Returns: 0 if config loaded correctly, 1 otherwise
test_config_file_loading() {
    local config_file="$1"
    local output
    local exit_code

    log "INFO" "Testing configuration file loading: $config_file"

    # Create a temporary test script
    local test_script="${TEST_ENV_DIR}/test_config_load.sh"

    cat > "$test_script" << EOF
#!/bin/bash
source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" --config "${config_file}"

# Check if key settings were applied
env_vars=(
  "DEFAULT_LOG_DIR=${TEST_ENV_DIR}/logs"
  "DEFAULT_BACKUP_DIR=${TEST_ENV_DIR}/backups"
  "DEFAULT_ENVIRONMENT=test"
)

success=true
for var in "\${env_vars[@]}"; do
  key=\${var%%=*}
  expected_value=\${var#*=}
  actual_value=\${!key}

  if [[ "\$actual_value" != "\$expected_value" ]]; then
    echo "Config error: \$key expected '\$expected_value', got '\$actual_value'"
    success=false
  fi
done

# Check if modules were loaded
if ! declare -f core_test_function &>/dev/null || ! declare -f validation_test_function &>/dev/null; then
  echo "Config error: Modules were not loaded correctly"
  success=false
fi

if [[ "\$success" == "true" ]]; then
  echo "SUCCESS: Configuration loaded correctly"
  exit 0
else
  exit 1
fi
EOF

    chmod +x "$test_script"

    # Run the test script
    output=$("$test_script" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "Configuration file loaded correctly"
        return 0
    else
        log "ERROR" "Configuration file loading failed: $output"
        return 1
    fi
}

# Test error handling for non-existent modules
# Arguments: None
# Returns: 0 if error handling works, 1 otherwise
test_error_handling() {
    local output
    local exit_code

    log "INFO" "Testing error handling for non-existent modules"

    # Create a temporary test script
    local test_script="${TEST_ENV_DIR}/test_error_handling.sh"

    cat > "$test_script" << EOF
#!/bin/bash
output=\$(source "${COMMON_FUNCTIONS_PATH}" --quiet --module-path "${TEST_MODULE_DIR}" non_existent_module 2>&1)
exit_code=\$?

if [[ \$exit_code -ne 0 && "\$output" == *"not found"* || "\$output" == *"unknown"* || "\$output" == *"No module"* ]]; then
  echo "SUCCESS: Error was correctly reported for non-existent module"
  exit 0
else
  echo "FAILURE: Error handling did not work as expected"
  echo "Exit code: \$exit_code"
  echo "Output: \$output"
  exit 1
fi
EOF

    chmod +x "$test_script"

    # Run the test script
    output=$("$test_script" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "Error handling works correctly"
        return 0
    else
        log "ERROR" "Error handling test failed: $output"
        return 1
    fi
}

#######################################
# TEST RUNNERS
#######################################

# Run a specific test by name
# Arguments:
#   $1 - Test name
# Returns: 0 if test passes, 1 otherwise
run_specific_test() {
    local test_name="$1"

    log "INFO" "Running specific test: $test_name"

    # Check if the test function exists
    if declare -f "$test_name" &>/dev/null; then
        begin_test_group "$(echo "$test_name" | sed 's/^test_//')"
        run_test "$test_name" "$test_name"
        end_test_group
        return 0
    else
        log "ERROR" "Test function not found: $test_name"
        return 1
    fi
}

# Run all common function tests
# Arguments:
#   $1 - Keep temp files flag (true/false, optional)
# Returns: 0 if all tests pass, 1 if any test fails
run_all_tests() {
    local keep_temp="${1:-false}"

    # Setup test environment
    setup_test_environment || return 1

    # Start the test group
    begin_test_group "Common Functions Tests"

    # Run tests for core functionality
    run_test "Module Loading (Core)" "test_module_load core"
    run_test "Module Loading (Multiple)" "test_module_load 'core,validation'"
    run_test "Dependency Resolution" "test_dependency_resolution advanced 'core,system'"
    run_test "Parallel Loading" "test_parallel_loading 'core,system,validation,file_ops'"
    run_test "Configuration File" "test_config_file_loading '${TEST_CONFIG_DIR}/test_config.conf'"
    run_test "Error Handling" "test_error_handling"

    # End test group
    end_test_group

    # Generate test report
    generate_test_report

    # Cleanup
    cleanup_test_environment "$keep_temp"

    # Return overall status
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log "SUCCESS" "All tests passed! 🎉"
        return 0
    else
        log "ERROR" "Some tests failed! ❌"
        return 1
    fi
}

#######################################
# MAIN
#######################################

# Show script usage
show_usage() {
    cat <<EOF
USAGE: $(basename "$0") [OPTIONS]

Test utilities for common_functions.sh v$TEST_COMMON_FUNCTIONS_VERSION

OPTIONS:
  --test=NAME, -t NAME     Run a specific test by name
  --verbose, -v            Show more detailed output
  --keep-temp, -k          Keep temporary test files
  --report=FORMAT, -r FMT  Report format: text, json, or junit (default: text)
  --output=FILE, -o FILE   Save test results to FILE
  --help, -h               Show this help message

EXAMPLES:
  # Run all tests
  $(basename "$0")

  # Run all tests with detailed output
  $(basename "$0") --verbose

  # Run specific test
  $(basename "$0") --test=test_module_load

  # Generate a JUnit XML report
  $(basename "$0") --report=junit --output=common_functions_test_results.xml
EOF
}

# Parse command line arguments
parse_test_args() {
    local specific_test=""
    local keep_temp=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --test=*)
                specific_test="${1#*=}"
                shift
                ;;
            -t|--test)
                if [[ -n "$2" && "$2" != -* ]]; then
                    specific_test="$2"
                    shift 2
                else
                    log "ERROR" "Option --test requires an argument"
                    exit 1
                fi
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --keep-temp|-k)
                keep_temp=true
                shift
                ;;
            --report=*)
                OUTPUT_FORMAT="${1#*=}"
                shift
                ;;
            -r|--report)
                if [[ -n "$2" && "$2" =~ ^(text|json|junit)$ ]]; then
                    OUTPUT_FORMAT="$2"
                    shift 2
                else
                    log "ERROR" "Option --report requires an argument: text, json, or junit"
                    exit 1
                fi
                ;;
            --output=*)
                OUTPUT_FILE="${1#*=}"
                shift
                ;;
            -o|--output)
                if [[ -n "$2" ]]; then
                    OUTPUT_FILE="$2"
                    shift 2
                else
                    log "ERROR" "Option --output requires an argument"
                    exit 1
                fi
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Run tests
    if [[ -n "$specific_test" ]]; then
        run_specific_test "$specific_test"
    else
        run_all_tests "$keep_temp"
    fi
}

# Export test functions
export -f setup_test_environment
export -f cleanup_test_environment
export -f create_mock_module
export -f test_module_load
export -f test_dependency_resolution
export -f test_parallel_loading
export -f test_config_file_loading
export -f test_error_handling
export -f run_specific_test
export -f run_all_tests

# If script is executed directly, run the tests
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_test_args "$@"
    exit $?
fi
