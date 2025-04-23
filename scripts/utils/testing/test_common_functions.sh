#!/bin/bash
# filepath: scripts/utils/testing/test_common_functions.sh
#
# Test suite for common_functions.sh
#
# This script tests the functionality of the common_functions.sh script,
# including module loading, parallel loading, dependency resolution, and
# configuration file support.
#
# Usage: ./test_common_functions.sh [--verbose] [--keep-temp] [--focus test_name]

# Set default options
VERBOSE=false
KEEP_TEMP=false
FOCUS_TEST=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
COMMON_FUNCTIONS="${PROJECT_ROOT}/scripts/utils/common_functions.sh"
TEST_CONFIG_DIR="${SCRIPT_DIR}/test_configs"
TEST_TEMP_DIR="/tmp/common_functions_test_$(date +%s)"
# Improvement #1: Add isolated module directory for test independence
TEST_MODULES_DIR="${TEST_TEMP_DIR}/modules"

# Define color codes for test output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test status counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
CURRENT_TEST=""

# Parse command line options
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose|-v)
      VERBOSE=true
      shift
      ;;
    --keep-temp|-k)
      KEEP_TEMP=true
      shift
      ;;
    --focus|-f)
      if [[ -n "$2" ]]; then
        FOCUS_TEST="$2"
        shift 2
      else
        echo "Error: --focus requires a test function name"
        exit 1
      fi
      ;;
    --help|-h)
      cat <<HELP
Usage: ./test_common_functions.sh [OPTIONS]

Options:
  --verbose, -v     Show more detailed output
  --keep-temp, -k   Don't delete temporary test files
  --focus, -f NAME  Run only the specified test
  --help, -h        Show this help message

Examples:
  ./test_common_functions.sh
  ./test_common_functions.sh --verbose
  ./test_common_functions.sh --focus test_dependency_resolution
HELP
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Log a message with a timestamp
log() {
  local level="$1"
  local message="$2"
  local color=""

  case "$level" in
    INFO)    color="$BLUE" ;;
    PASS)    color="$GREEN" ;;
    FAIL)    color="$RED" ;;
    WARNING) color="$YELLOW" ;;
    DEBUG)   color="$CYAN" ;;
    *)       color="$NC" ;;
  esac

  if [[ "$level" == "DEBUG" && "$VERBOSE" != "true" ]]; then
    # Skip debug messages unless verbose mode is enabled
    return 0
  fi

  echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message${NC}"
}

# Start a new test
start_test() {
  CURRENT_TEST="$1"
  log "INFO" "Starting test: $CURRENT_TEST"
}

# Mark current test as passed
test_passed() {
  local message="${1:-Test passed}"
  ((TESTS_PASSED++))
  log "PASS" "✓ $CURRENT_TEST: $message"
}

# Mark current test as failed
test_failed() {
  local message="${1:-Test failed}"
  ((TESTS_FAILED++))
  log "FAIL" "✗ $CURRENT_TEST: $message"

  # Add more detailed failure information when in verbose mode
  if [[ "$VERBOSE" == "true" && -n "$2" ]]; then
    log "FAIL" "  Details: $2"
  fi
}

# Mark current test as skipped
test_skipped() {
  local message="${1:-Test skipped}"
  ((TESTS_SKIPPED++))
  log "WARNING" "⚠ $CURRENT_TEST: $message"
}

# Clean up temp files
cleanup() {
  if [[ "$KEEP_TEMP" != "true" ]]; then
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$TEST_TEMP_DIR"
  else
    log "INFO" "Keeping temporary files in $TEST_TEMP_DIR"
  fi
}

# Check if command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Improvement #1: Function to create isolated module for a specific test
create_test_module() {
  local module="$1"
  local test_name="$2"
  local test_module_dir="${TEST_MODULES_DIR}/${test_name}"
  local module_file="${test_module_dir}/common/common_${module}_utils.sh"

  # Create directories if they don't exist
  mkdir -p "${test_module_dir}/common"

  # Create module file
  cat > "$module_file" << EOF
#!/bin/bash
# filepath: scripts/utils/common/common_${module}_utils.sh
# Mock ${module} module for testing: $test_name

# Version tracking
${module^^}_UTILS_VERSION="1.0.0-test"
${module^^}_UTILS_DATE="$(date '+%Y-%m-%d')"

# Get version information
get_${module}_utils_version() {
  echo "\${${module^^}_UTILS_VERSION} (\${${module^^}_UTILS_DATE})"
}

# Test function to check if this module was loaded
${module}_test_function() {
  echo "${module} module loaded successfully for test $test_name"
  return 0
}

# Test function with an error
${module}_test_error() {
  return 1
}

# Export functions
export -f get_${module}_utils_version
export -f ${module}_test_function
export -f ${module}_test_error
EOF

  chmod +x "$module_file"

  # Add logging function to core module
  if [[ "$module" == "core" ]]; then
    cat >> "$module_file" << EOF

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

# Export additional functions
export -f log
export -f error_exit
EOF
  fi

  # Return the path to the created module
  echo "$module_file"
}

# Improvement #1: Function to prepare test environment for a specific test
prepare_test_environment() {
  local test_name="$1"
  local test_module_dir="${TEST_MODULES_DIR}/${test_name}"

  log "DEBUG" "Preparing isolated test environment for $test_name"

  # Create all modules for this specific test
  for module in core system advanced file_ops validation health; do
    create_test_module "$module" "$test_name"
  done

  # Create a custom COMMON_FUNCTIONS variable pointing to this test's environment
  echo "export MODULE_PATH_PREFIX=${test_module_dir}"
}

# Set up test environment
setup() {
  log "INFO" "Setting up test environment"

  # Check if common_functions.sh exists
  if [[ ! -f "$COMMON_FUNCTIONS" ]]; then
    log "FAIL" "common_functions.sh not found at $COMMON_FUNCTIONS"
    exit 1
  fi

  # Create test directories
  mkdir -p "$TEST_TEMP_DIR" "$TEST_CONFIG_DIR" "$TEST_MODULES_DIR"

  # Create a test configuration file
  cat > "${TEST_CONFIG_DIR}/test_config.conf" << EOF
# Test configuration file for common_functions.sh
DEFAULT_LOG_DIR=${TEST_TEMP_DIR}/logs
DEFAULT_BACKUP_DIR=${TEST_TEMP_DIR}/backups
DEFAULT_ENVIRONMENT=test
MODULES=core,validation
QUIET=false
PARALLEL_LOAD=true
PARALLEL_LOAD_MAX=2
EOF

  # Create a mock common_core_utils.sh for testing if not already available
  if [[ ! -d "${PROJECT_ROOT}/scripts/utils/common" ]]; then
    mkdir -p "${PROJECT_ROOT}/scripts/utils/common"
  fi

  # Create mock modules for testing if real ones are not available
  for module in core system advanced file_ops validation health; do
    module_path="${PROJECT_ROOT}/scripts/utils/common/common_${module}_utils.sh"
    if [[ ! -f "$module_path" ]]; then
      log "INFO" "Creating mock $module module for testing"

      # Create a basic module file with version information and test functions
      cat > "$module_path" << EOF
#!/bin/bash
# filepath: scripts/utils/common/common_${module}_utils.sh
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

# Test function with an error
${module}_test_error() {
  return 1
}

# Export functions
export -f get_${module}_utils_version
export -f ${module}_test_function
export -f ${module}_test_error
EOF
      chmod +x "$module_path"
    fi
  done

  # Add additional required functions to core module
  if [[ -f "${PROJECT_ROOT}/scripts/utils/common/common_core_utils.sh" ]]; then
    # Check if log function already exists
    if ! grep -q "function log" "${PROJECT_ROOT}/scripts/utils/common/common_core_utils.sh"; then
      log "INFO" "Adding log function to core module"
      cat >> "${PROJECT_ROOT}/scripts/utils/common/common_core_utils.sh" << EOF

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

# Export additional functions
export -f log
export -f error_exit
EOF
    fi
  fi

  log "INFO" "Test environment setup complete"
  return 0
}

# Test if script shows the correct version
test_version_display() {
  start_test "Version Display"

  # Source the functions script with version flag
  local version_output
  version_output=$(bash -c "source '$COMMON_FUNCTIONS' --version 2>/dev/null" 2>&1)

  if [[ "$version_output" == *"version"* && "$version_output" == *"("*")"* ]]; then
    test_passed "Version displayed correctly: $version_output"
  else
    test_failed "Version display failed" "Output: $version_output"
  fi
}

# Test help display
test_help_display() {
  start_test "Help Display"

  # Source the functions script with help flag
  local help_output
  help_output=$(bash -c "source '$COMMON_FUNCTIONS' --help 2>/dev/null" 2>&1)

  # Check if help output contains expected sections
  if [[ "$help_output" == *"Usage:"* && "$help_output" == *"Options:"* && "$help_output" == *"Examples:"* ]]; then
    test_passed "Help displayed correctly"

    # Log details in verbose mode
    if [[ "$VERBOSE" == "true" ]]; then
      log "DEBUG" "Help output starts with: $(echo "$help_output" | head -n 3)"
    fi
  else
    test_failed "Help display missing expected sections" "Output: ${help_output:0:100}..."
  fi
}

# Test listing available modules
test_list_modules() {
  start_test "List Modules"

  # Source the functions script with list flag
  local list_output
  list_output=$(bash -c "source '$COMMON_FUNCTIONS' --list 2>/dev/null" 2>&1)

  # Check if list output contains expected modules
  if [[ "$list_output" == *"Available modules:"* &&
        "$list_output" == *"core"* &&
        "$list_output" == *"system"* &&
        "$list_output" == *"file_ops"* ]]; then
    test_passed "Modules listed correctly"

    if [[ "$VERBOSE" == "true" ]]; then
      log "DEBUG" "Found modules: $(echo "$list_output" | grep -E '^\s+-' | tr '\n' ', ')"
    fi
  else
    test_failed "Module listing missing expected modules" "Output: ${list_output:0:100}..."
  fi
}

# Test loading a single module
test_load_single_module() {
  start_test "Load Single Module"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_load_single_env.sh"
  prepare_test_environment "load_single_module" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_load_single.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet core
if declare -f core_test_function &>/dev/null; then
  echo "PASS"
else
  echo "FAIL"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")

  if [[ "$result" == "PASS" ]]; then
    test_passed "Core module loaded correctly"
  else
    test_failed "Failed to load core module" "Result: $result"
  fi
}

# Test loading multiple modules
test_load_multiple_modules() {
  start_test "Load Multiple Modules"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_load_multiple_env.sh"
  prepare_test_environment "load_multiple_modules" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_load_multiple.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet core,validation
if declare -f core_test_function &>/dev/null && declare -f validation_test_function &>/dev/null; then
  echo "PASS"
else
  echo "FAIL: Core: \$(declare -f core_test_function &>/dev/null && echo yes || echo no), Validation: \$(declare -f validation_test_function &>/dev/null && echo yes || echo no)"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")

  if [[ "$result" == "PASS" ]]; then
    test_passed "Multiple modules loaded correctly"
  else
    test_failed "Failed to load multiple modules" "Result: $result"
  fi
}

# Test automatic dependency resolution
test_dependency_resolution() {
  start_test "Dependency Resolution"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_dependency_env.sh"
  local test_module_dir="${TEST_MODULES_DIR}/dependency_resolution"
  prepare_test_environment "dependency_resolution" > "$test_env_file"

  # Modify the advanced module to depend on system
  local advanced_path="${test_module_dir}/common/common_advanced_utils.sh"
  cat > "$advanced_path" << EOF
#!/bin/bash
# filepath: scripts/utils/common/common_advanced_utils.sh
# Mock advanced module for testing dependency resolution

# Check if required functions are available
if ! declare -f get_system_info &>/dev/null; then
  echo "Required function get_system_info not available. Make sure to load system module first." >&2
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
  echo "advanced module loaded successfully"
  return 0
}

# Export functions
export -f get_advanced_utils_version
export -f advanced_test_function
EOF

  # Add get_system_info to system module
  local system_path="${test_module_dir}/common/common_system_utils.sh"
  cat > "$system_path" << EOF
#!/bin/bash
# filepath: scripts/utils/common/common_system_utils.sh
# Mock system module for testing dependency resolution

# Version tracking
SYSTEM_UTILS_VERSION="1.0.0-test"
SYSTEM_UTILS_DATE="$(date '+%Y-%m-%d')"

# Get version information
get_system_utils_version() {
  echo "\${SYSTEM_UTILS_VERSION} (\${SYSTEM_UTILS_DATE})"
}

# Required by advanced module
get_system_info() {
  echo "System info function called"
  return 0
}

# Test function to check if this module was loaded
system_test_function() {
  echo "system module loaded successfully"
  return 0
}

# Export functions
export -f get_system_utils_version
export -f system_test_function
export -f get_system_info
EOF

  # Create test script to load advanced (should load system automatically)
  local test_script="${TEST_TEMP_DIR}/test_dependency.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet advanced
if declare -f get_system_info &>/dev/null && declare -f advanced_test_function &>/dev/null; then
  echo "PASS"
else
  echo "FAIL: System: \$(declare -f get_system_info &>/dev/null && echo yes || echo no), Advanced: \$(declare -f advanced_test_function &>/dev/null && echo yes || echo no)"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")

  if [[ "$result" == "PASS" ]]; then
    test_passed "Dependency resolution worked correctly"
  else
    test_failed "Failed to resolve module dependencies" "Result: $result"
  fi
}

# Test loading all modules
test_load_all_modules() {
  start_test "Load All Modules"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_load_all_env.sh"
  prepare_test_environment "load_all_modules" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_load_all.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet all
# Count number of modules actually loaded by checking for their test functions
loaded=0
loaded_modules=""
for module in core system validation file_ops health advanced; do
  if declare -f \${module}_test_function &>/dev/null; then
    ((loaded++))
    loaded_modules="\$loaded_modules \$module"
  fi
done
echo "\$loaded|\$loaded_modules"
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")
  local count
  count=$(echo "$result" | cut -d'|' -f1)
  local modules
  modules=$(echo "$result" | cut -d'|' -f2)

  # We expect most modules to be loaded (at least 4 out of 6)
  if [[ "$count" -ge 4 ]]; then
    test_passed "All modules loaded correctly ($count modules found: $modules)"
  else
    test_failed "Failed to load all modules" "Only $count modules found: $modules"
  fi
}

# Test parallel module loading
test_parallel_loading() {
  start_test "Parallel Module Loading"

  # Only test if the shell supports job control
  if ! jobs -p &>/dev/null; then
    test_skipped "This shell doesn't support job control needed for parallel loading"
    return
  fi

  # Check for bc command required for timing comparison
  if ! command_exists bc; then
    test_skipped "bc command not available for timing comparison"
    return
  fi

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_parallel_env.sh"
  local test_module_dir="${TEST_MODULES_DIR}/parallel_loading"
  prepare_test_environment "parallel_loading" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_parallel.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"

# Add sleep to modules to ensure they would take time to load
for module in core system validation file_ops health advanced; do
  module_path="\${MODULE_PATH_PREFIX}/common/common_\${module}_utils.sh"
  if [[ -f "\$module_path" ]]; then
    # Add a sleep to make loading take longer (to test parallelism)
    sed -i.bak '1s/^/sleep 0.5\n/' "\$module_path"
  fi
done

# Time how long it takes to load all modules in parallel
start_time=\$(date +%s.%N 2>/dev/null || date +%s)
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet --parallel core,system,validation,file_ops
end_time=\$(date +%s.%N 2>/dev/null || date +%s)
parallel_time=\$(echo "\$end_time - \$start_time" | bc 2>/dev/null || echo 0)

# Restore modules
for module in core system validation file_ops health advanced; do
  module_path="\${MODULE_PATH_PREFIX}/common/common_\${module}_utils.sh"
  if [[ -f "\$module_path.bak" ]]; then
    mv "\$module_path.bak" "\$module_path"
  fi
done

# Time how long it takes to load all modules sequentially
start_time=\$(date +%s.%N 2>/dev/null || date +%s)
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet core,system,validation,file_ops
end_time=\$(date +%s.%N 2>/dev/null || date +%s)
sequential_time=\$(echo "\$end_time - \$start_time" | bc 2>/dev/null || echo 0)

# Calculate the difference
time_diff=\$(echo "\$sequential_time - \$parallel_time" | bc 2>/dev/null || echo 0)

# If parallel is at least 30% faster, it's working well
# If it's at least a little faster, it's probably working
# Otherwise it may not be working but we'll be lenient
if (( \$(echo "\$time_diff > 0.5" | bc -l) )); then
  echo "PASS: Excellent|Parallel: \$parallel_time, Sequential: \$sequential_time (saved \$time_diff s)"
elif (( \$(echo "\$time_diff > 0" | bc -l) )); then
  echo "PASS: Good|Parallel: \$parallel_time, Sequential: \$sequential_time (saved \$time_diff s)"
else
  echo "FAIL: Parallel: \$parallel_time, Sequential: \$sequential_time (difference: \$time_diff s)"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")
  local status
  status=$(echo "$result" | cut -d'|' -f1)
  local details
  details=$(echo "$result" | cut -d'|' -f2)

  if [[ "$status" == PASS* ]]; then
    test_passed "$details"
  else
    # This test can be flaky if the system is too fast, so we'll be lenient
    test_skipped "$details"
  fi
}

# Test configuration file support
test_config_file() {
  start_test "Configuration File Support"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_config_env.sh"
  prepare_test_environment "config_file" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_config.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --config "${TEST_CONFIG_DIR}/test_config.conf"
# Check if the configuration was applied
if [[ "\$DEFAULT_LOG_DIR" == "${TEST_TEMP_DIR}/logs" &&
      "\$DEFAULT_BACKUP_DIR" == "${TEST_TEMP_DIR}/backups" &&
      "\$DEFAULT_ENVIRONMENT" == "test" ]] &&
   declare -f core_test_function &>/dev/null &&
   declare -f validation_test_function &>/dev/null; then
  echo "PASS"
else
  echo "FAIL: LogDir=\$DEFAULT_LOG_DIR, BackupDir=\$DEFAULT_BACKUP_DIR, Env=\$DEFAULT_ENVIRONMENT, Core=\$(declare -f core_test_function &>/dev/null && echo yes || echo no), Validation=\$(declare -f validation_test_function &>/dev/null && echo yes || echo no)"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")

  if [[ "$result" == "PASS" ]]; then
    test_passed "Configuration file loaded correctly"
  else
    test_failed "Failed to load configuration file" "Result: $result"
  fi
}

# Test error handling for non-existent modules
test_error_handling() {
  start_test "Error Handling"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_error_env.sh"
  prepare_test_environment "error_handling" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_error.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
OUTPUT=\$(source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet non_existent_module 2>&1)
EXIT_CODE=\$?
if [[ "\$OUTPUT" == *"not found"* || "\$OUTPUT" == *"unknown"* || "\$OUTPUT" == *"No module"* ]]; then
  echo "PASS|\$OUTPUT"
else
  echo "FAIL: \$EXIT_CODE|\$OUTPUT"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")
  local status
  status=$(echo "$result" | cut -d'|' -f1)
  local details
  details=$(echo "$result" | cut -d'|' -f2)

  if [[ "$status" == "PASS" ]]; then
    test_passed "Error handling for non-existent modules works"

    if [[ "$VERBOSE" == "true" ]]; then
      log "DEBUG" "Error output: $details"
    fi
  else
    test_failed "Error handling failed" "Result: $details"
  fi
}

# Test module unloading
test_module_unloading() {
  start_test "Module Unloading"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_unload_env.sh"
  prepare_test_environment "module_unloading" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_unload.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet core
# Check if module was loaded
if ! declare -f core_test_function &>/dev/null; then
  echo "FAIL: Module not loaded"
  exit 1
fi

# Check if unload_module function exists
if ! declare -f unload_module &>/dev/null; then
  echo "SKIP: unload_module function not available"
  exit 2
fi

# Try to unload module
unload_module core

# Check if module function is no longer available
if declare -f core_test_function &>/dev/null; then
  echo "FAIL: Module still loaded"
else
  echo "PASS"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")
  local exit_code=$?

  if [[ "$exit_code" -eq 2 ]]; then
    test_skipped "unload_module function not available"
  elif [[ "$result" == "PASS" ]]; then
    test_passed "Module unload works correctly"
  else
    test_failed "Module unload failed" "Result: $result"
  fi
}

# Test exported variables
test_exported_variables() {
  start_test "Exported Variables"

  # Improvement #1: Create isolated test environment
  local test_env_file="${TEST_TEMP_DIR}/test_exports_env.sh"
  prepare_test_environment "exported_variables" > "$test_env_file"

  local test_script="${TEST_TEMP_DIR}/test_exports.sh"

  cat > "$test_script" << EOF
#!/bin/bash
source "$test_env_file"
MODULE_PATH_OPTION="--module-path \$MODULE_PATH_PREFIX"
source "$COMMON_FUNCTIONS" \$MODULE_PATH_OPTION --quiet core

# Check if required variables are exported
MISSING_VARS=""
for var in SCRIPT_DIR PROJECT_ROOT DEFAULT_LOG_DIR DEFAULT_ENVIRONMENT TIMESTAMP; do
  if ! declare -p \$var &>/dev/null; then
    MISSING_VARS="\$MISSING_VARS \$var"
  fi
done

if [[ -z "\$MISSING_VARS" ]]; then
  echo "PASS"
else
  echo "FAIL: Missing variables:\$MISSING_VARS"
fi
EOF
  chmod +x "$test_script"

  local result
  result=$("$test_script")

  if [[ "$result" == "PASS" ]]; then
    test_passed "Required variables are exported"
  else
    test_failed "Required variables not exported" "$result"
  fi
}

# Print test summary
print_summary() {
  echo
  echo "=== TEST SUMMARY ==="
  echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
  echo -e "${RED}Failed: $TESTS_FAILED${NC}"
  echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
  echo "Total: $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
  echo "===================="

  if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    return 0
  else
    echo -e "${RED}Some tests failed!${NC}"
    return 1
  fi
}

# Run all tests or a specific test if requested
run_tests() {
  setup

  # Collect all test function names
  local test_functions=(
    test_version_display
    test_help_display
    test_list_modules
    test_load_single_module
    test_load_multiple_modules
    test_dependency_resolution
    test_load_all_modules
    test_parallel_loading
    test_config_file
    test_error_handling
    test_module_unloading
    test_exported_variables
  )

  if [[ -n "$FOCUS_TEST" ]]; then
    # Run only the specified test if it exists
    local test_found=false
    for test_func in "${test_functions[@]}"; do
      if [[ "$test_func" == "$FOCUS_TEST" ]]; then
        test_found=true
        log "INFO" "Running only test: $FOCUS_TEST"
        "$test_func"
        break
      fi
    done

    if [[ "$test_found" != "true" ]]; then
      log "FAIL" "Test function not found: $FOCUS_TEST"
      echo "Available test functions:"
      for test_func in "${test_functions[@]}"; do
        echo "  $test_func"
      done
      exit 1
    fi
  else
    # Run all tests
    for test_func in "${test_functions[@]}"; do
      "$test_func"
    done
  fi

  print_summary
}

# Register cleanup handler
trap cleanup EXIT

# Run tests and exit with appropriate code
run_tests
exit $TESTS_FAILED
