#!/bin/bash
# -----------------------------------------------------------------------------
# lint.sh - Python Code Linting and Formatting Tool
#
# Part of Cloud Infrastructure Platform
#
# This script runs various code quality tools on Python code:
# - flake8: Style guide enforcement
# - isort: Import sorting
# - black: Code formatting
# - bandit: Security issue detection
# - mypy: Optional static type checking
#
# Usage: ./lint.sh [--fix] [--check] [--security] [--types] [path1 path2 ...]
# -----------------------------------------------------------------------------

set -o pipefail

# Script version
readonly SCRIPT_VERSION="1.1.0"

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"
CONFIG_DIR="${PROJECT_ROOT}/config"
VERBOSE=false
FIX_MODE=false
CHECK_MODE=false
SECURITY_MODE=false
TYPES_MODE=false
EXIT_CODE=0
PATHS=()

# Default Python paths to lint
DEFAULT_PATHS=(
    "app.py"
    "api/"
    "blueprints/"
    "core/"
    "models/"
    "extensions/"
    "services/"
)

# Config files
FLAKE8_CONFIG="${CONFIG_DIR}/.flake8"
ISORT_CONFIG="${CONFIG_DIR}/.isort.cfg"
BLACK_CONFIG="${CONFIG_DIR}/pyproject.toml"
BANDIT_CONFIG="${CONFIG_DIR}/.bandit"
MYPY_CONFIG="${CONFIG_DIR}/mypy.ini"

# Import logging utilities if available
if [[ -f "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh"
else
    # Minimal logging if logging_utils is not available
    log_info() { echo "[INFO] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "${VERBOSE}" == "true" ]] && echo "[DEBUG] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
    log_success() { echo "[SUCCESS] $1"; }
fi

# Function to display usage
usage() {
    cat <<EOF
Python Code Linting and Formatting Tool (v${SCRIPT_VERSION})

Usage: $0 [options] [path1 path2 ...]

Options:
  --fix              Run formatters to fix code issues automatically
  --check            Run in check mode (no changes, only reports issues)
  --security         Run security checks only
  --types            Run type checking with mypy
  --verbose          Display detailed output
  --help             Display this help message

If no paths are specified, the following default paths will be used:
  ${DEFAULT_PATHS[*]}

Examples:
  $0 --fix                   # Fix formatting issues in default paths
  $0 --check api/            # Check for issues in api/ directory
  $0 --security              # Run security checks only
  $0 --types core/ models/   # Run type checking on specific directories

EOF
    exit 1
}

# Function to check if tool is installed
check_tool() {
    local tool=$1
    if ! command -v "$tool" &>/dev/null; then
        log_error "$tool is not installed. Please install it first:"
        case "$tool" in
            flake8)
                echo "  pip install flake8"
                ;;
            isort)
                echo "  pip install isort"
                ;;
            black)
                echo "  pip install black"
                ;;
            bandit)
                echo "  pip install bandit"
                ;;
            mypy)
                echo "  pip install mypy"
                ;;
            *)
                echo "  pip install $tool"
                ;;
        esac
        return 1
    fi
    return 0
}

# Function to run flake8
run_flake8() {
    local flake8_args=()

    log_info "Running flake8..."

    # Add config file if it exists
    if [[ -f "$FLAKE8_CONFIG" ]]; then
        flake8_args+=(--config "$FLAKE8_CONFIG")
        log_debug "Using flake8 config: $FLAKE8_CONFIG"
    fi

    # Run flake8
    if ! flake8 "${flake8_args[@]}" "$@"; then
        log_error "flake8 found style issues"
        EXIT_CODE=1
        return 1
    fi

    log_success "flake8 check passed"
    return 0
}

# Function to run isort
run_isort() {
    local isort_args=()

    # Add profile if no config
    if [[ ! -f "$ISORT_CONFIG" ]]; then
        isort_args+=(--profile black)
    else
        isort_args+=(--settings-path "$ISORT_CONFIG")
        log_debug "Using isort config: $ISORT_CONFIG"
    fi

    # Add check flag if not in fix mode
    if [[ "$FIX_MODE" != "true" ]]; then
        isort_args+=(--check)
    fi

    log_info "Running isort..."

    # Run isort
    if ! isort "${isort_args[@]}" "$@"; then
        if [[ "$FIX_MODE" == "true" ]]; then
            log_success "isort fixed import ordering"
        else
            log_error "isort found import ordering issues"
            EXIT_CODE=1
            return 1
        fi
    else
        log_success "isort check passed"
    fi

    return 0
}

# Function to run black
run_black() {
    local black_args=()

    # Add config file if it exists
    if [[ -f "$BLACK_CONFIG" ]]; then
        black_args+=(--config "$BLACK_CONFIG")
        log_debug "Using black config: $BLACK_CONFIG"
    fi

    # Add check flag if not in fix mode
    if [[ "$FIX_MODE" != "true" ]]; then
        black_args+=(--check)
    fi

    log_info "Running black..."

    # Run black
    if ! black "${black_args[@]}" "$@"; then
        if [[ "$FIX_MODE" == "true" ]]; then
            log_success "black reformatted code"
        else
            log_error "black found formatting issues"
            EXIT_CODE=1
            return 1
        fi
    else
        log_success "black check passed"
    fi

    return 0
}

# Function to run bandit
run_bandit() {
    local bandit_args=("-r")

    log_info "Running bandit security checks..."

    # Add config file if it exists
    if [[ -f "$BANDIT_CONFIG" ]]; then
        bandit_args+=(-c "$BANDIT_CONFIG")
        log_debug "Using bandit config: $BANDIT_CONFIG"
    fi

    # Run bandit
    if ! bandit "${bandit_args[@]}" "$@"; then
        log_error "bandit found security issues"
        EXIT_CODE=1
        return 1
    fi

    log_success "bandit security check passed"
    return 0
}

# Function to run mypy
run_mypy() {
    local mypy_args=()

    log_info "Running mypy type checking..."

    # Add config file if it exists
    if [[ -f "$MYPY_CONFIG" ]]; then
        mypy_args+=(--config-file "$MYPY_CONFIG")
        log_debug "Using mypy config: $MYPY_CONFIG"
    fi

    # Check if mypy is installed, and run only if it is
    if check_tool mypy; then
        if ! mypy "${mypy_args[@]}" "$@"; then
            log_error "mypy found type issues"
            EXIT_CODE=1
            return 1
        fi
        log_success "mypy type check passed"
    else
        log_warning "Skipping mypy type checking (not installed)"
    fi

    return 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --fix)
            FIX_MODE=true
            shift
            ;;
        --check)
            CHECK_MODE=true
            shift
            ;;
        --security)
            SECURITY_MODE=true
            shift
            ;;
        --types)
            TYPES_MODE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            ;;
        -*)
            log_error "Unknown option: $key"
            usage
            ;;
        *)
            PATHS+=("$key")
            shift
            ;;
    esac
done

# Use default paths if none specified
if [[ ${#PATHS[@]} -eq 0 ]]; then
    PATHS=("${DEFAULT_PATHS[@]}")
fi

# Verify the paths exist
for path in "${PATHS[@]}"; do
    if [[ ! -e "$path" ]]; then
        log_warning "Path does not exist: $path"
    fi
done

# Check if required tools are installed
check_tool flake8 || EXIT_CODE=1
check_tool isort || EXIT_CODE=1
check_tool black || EXIT_CODE=1
check_tool bandit || EXIT_CODE=1

# Run the requested tools
if [[ "$EXIT_CODE" -eq 0 ]]; then
    log_info "Starting code quality checks on: ${PATHS[*]}"

    # Run specific tools based on mode
    if [[ "$SECURITY_MODE" == "true" ]]; then
        # Run security checks only
        run_bandit "${PATHS[@]}"
    elif [[ "$TYPES_MODE" == "true" ]]; then
        # Run type checks only
        run_mypy "${PATHS[@]}"
    else
        # Run all tools
        run_flake8 "${PATHS[@]}"
        run_isort "${PATHS[@]}"
        run_black "${PATHS[@]}"

        # Run security checks unless explicitly in check/fix mode
        if [[ "$CHECK_MODE" != "true" && "$FIX_MODE" != "true" ]]; then
            run_bandit "${PATHS[@]}"
        fi

        # Run type checking if requested
        if [[ "$TYPES_MODE" == "true" ]]; then
            run_mypy "${PATHS[@]}"
        fi
    fi
fi

# Final summary
if [[ "$EXIT_CODE" -eq 0 ]]; then
    log_success "All checks completed successfully!"
else
    log_error "Some checks failed. Please fix the issues and try again."
fi

exit $EXIT_CODE
