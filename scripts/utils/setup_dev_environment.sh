#!/bin/bash
# -----------------------------------------------------------------------------
# setup_dev_environment.sh - Development Environment Setup Tool
#
# Part of Cloud Infrastructure Platform
#
# This script automates the setup of a development environment for the
# Cloud Infrastructure Platform. It creates a virtual environment,
# installs dependencies, sets up configuration files, initializes the
# database, and creates an admin user.
#
# Usage: ./setup_dev_environment.sh [--force] [--skip-venv] [--python python3.8]
# -----------------------------------------------------------------------------

set -o pipefail

# Script version for tracking changes and compatibility
readonly SCRIPT_VERSION="1.0.0"

# Default values
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"
VENV_DIR="${PROJECT_ROOT}/venv"
PYTHON_CMD="python3"
ENV_FILE="${PROJECT_ROOT}/.env"
REQUIREMENTS_FILE="${PROJECT_ROOT}/requirements.txt"
FORCE=false
SKIP_VENV=false
VERBOSE=false
DEBUG_MODE=false

# Import logging utilities if available
if [[ -f "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh"
else
    # Minimal logging if logging_utils is not available
    log_info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
    log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; }
    log_debug() { [[ "${VERBOSE}" == "true" ]] && echo -e "\033[0;37m[DEBUG]\033[0m $1"; }
    log_warning() { echo -e "\033[0;33m[WARNING]\033[0m $1" >&2; }
    log_success() { echo -e "\033[0;32m[SUCCESS]\033[0m $1"; }
fi

# Function to display usage information
usage() {
    cat <<EOF
Development Environment Setup Tool v${SCRIPT_VERSION}

This script sets up a complete development environment for the Cloud Infrastructure Platform.

Usage: $(basename "$0") [options]

Options:
  --python <command>    Python command to use (default: python3)
  --venv-dir <path>     Custom virtual environment directory (default: ${VENV_DIR})
  --force, -f           Force setup even if environment already exists
  --skip-venv           Skip virtual environment creation (use existing)
  --verbose, -v         Enable verbose output
  --debug               Enable debug mode with additional output
  --help, -h            Display this help message

Examples:
  ./$(basename "$0")                    # Standard setup
  ./$(basename "$0") --python python3.8  # Use specific Python version
  ./$(basename "$0") --force             # Force recreation of environment
  ./$(basename "$0") --skip-venv         # Use existing virtual environment

This script performs the following operations:
  1. Creates a Python virtual environment
  2. Installs required dependencies
  3. Sets up configuration files
  4. Initializes the database
  5. Creates an admin user
EOF
    exit 1
}

# Function to check if a command exists
check_command() {
    local cmd=$1
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command '$cmd' not found. Please install it and try again."
        exit 1
    fi
}

# Function to check Python version
check_python_version() {
    local min_version="3.6.0"
    local python_version

    # Get Python version
    python_version=$("$PYTHON_CMD" -c "import sys; print('{}.{}.{}'.format(*sys.version_info[:3]))" 2>/dev/null) || {
        log_error "Failed to determine Python version. Is '$PYTHON_CMD' installed?"
        exit 1
    }

    log_debug "Python version: $python_version"

    # Compare versions (simplified)
    if [[ "$(echo -e "$min_version\n$python_version" | sort -V | head -n 1)" != "$min_version" ]]; then
        log_warning "Python version $python_version is lower than recommended minimum version $min_version"
        log_warning "Some features may not work correctly"

        # Prompt to continue
        read -r -p "Continue anyway? [y/N] " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log_error "Setup aborted"
            exit 1
        fi
    fi
}

# Function to set up virtual environment
setup_virtual_environment() {
    log_info "Setting up Python virtual environment in ${VENV_DIR}"

    # Check if venv already exists and handle accordingly
    if [[ -d "$VENV_DIR" ]]; then
        if [[ "$FORCE" == "true" ]]; then
            log_warning "Removing existing virtual environment"
            rm -rf "$VENV_DIR"
        elif [[ "$SKIP_VENV" == "true" ]]; then
            log_info "Using existing virtual environment"
            return 0
        else
            log_error "Virtual environment already exists at ${VENV_DIR}"
            log_error "Use --force to recreate or --skip-venv to use existing"
            exit 1
        fi
    fi

    # Create virtual environment
    log_info "Creating new virtual environment"
    "$PYTHON_CMD" -m venv "$VENV_DIR" || {
        log_error "Failed to create virtual environment"
        exit 1
    }

    log_success "Virtual environment created successfully"
    return 0
}

# Function to activate virtual environment
activate_virtual_environment() {
    log_info "Activating virtual environment"

    # Check if venv exists
    if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
        log_error "Virtual environment activation script not found"
        exit 1
    fi

    # Use source to activate the environment
    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate" || {
        log_error "Failed to activate virtual environment"
        exit 1
    }

    log_debug "Python interpreter: $(which python)"
    log_success "Virtual environment activated"
}

# Function to install dependencies
install_dependencies() {
    log_info "Installing dependencies from ${REQUIREMENTS_FILE}"

    if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
        log_error "Requirements file not found: ${REQUIREMENTS_FILE}"
        exit 1
    fi

    # Upgrade pip first
    pip install --upgrade pip || {
        log_error "Failed to upgrade pip"
        return 1
    }

    # Install requirements
    if [[ "$VERBOSE" == "true" ]]; then
        pip install -r "$REQUIREMENTS_FILE" || {
            log_error "Failed to install requirements"
            return 1
        }
    else
        pip install -r "$REQUIREMENTS_FILE" >/dev/null 2>&1 || {
            log_error "Failed to install requirements"
            log_error "Run with --verbose for more details"
            return 1
        }
    fi

    log_success "Dependencies installed successfully"
    return 0
}

# Function to set up configuration files
setup_config_files() {
    log_info "Setting up configuration files"

    # Set up .env file if it doesn't exist
    if [[ ! -f "$ENV_FILE" ]]; then
        log_info "Creating .env file from template"

        # Check for template files in order of preference
        if [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
            cp "${PROJECT_ROOT}/.env.example" "$ENV_FILE" || {
                log_error "Failed to copy .env.example to .env"
                return 1
            }
        elif [[ -f "${PROJECT_ROOT}/.env.development" ]]; then
            cp "${PROJECT_ROOT}/.env.development" "$ENV_FILE" || {
                log_error "Failed to copy .env.development to .env"
                return 1
            }
        else
            log_error "No template .env file found (.env.example or .env.development)"
            log_error "Please create a .env file manually"
            return 1
        fi

        # Set appropriate permissions
        chmod 600 "$ENV_FILE"

        log_success "Environment configuration file created"
    else
        if [[ "$FORCE" == "true" ]]; then
            log_warning "Overwriting existing .env file with template"
            cp "${PROJECT_ROOT}/.env.example" "$ENV_FILE" || {
                log_error "Failed to overwrite .env file"
                return 1
            }
        else
            log_info "Using existing .env file"
        fi
    fi

    # Update .env file with development settings if needed
    log_debug "Ensuring development settings are configured"
    if ! grep -q "^FLASK_ENV=development" "$ENV_FILE"; then
        echo -e "\n# Added by setup script" >> "$ENV_FILE"
        echo "FLASK_ENV=development" >> "$ENV_FILE"
    fi

    if ! grep -q "^DEBUG=True" "$ENV_FILE"; then
        echo "DEBUG=True" >> "$ENV_FILE"
    fi

    if [[ "$DEBUG_MODE" == "true" ]] && ! grep -q "^FLASK_DEBUG=1" "$ENV_FILE"; then
        echo "FLASK_DEBUG=1" >> "$ENV_FILE"
    fi

    return 0
}

# Function to initialize database
initialize_database() {
    log_info "Initializing database"

    # Check if flask command is available
    check_command flask

    # Run database migrations
    log_info "Running database migrations"
    flask db upgrade || {
        log_error "Failed to run database migrations"
        log_error "Make sure your database is properly configured in .env"
        return 1
    }

    # Create test data if in debug mode
    if [[ "$DEBUG_MODE" == "true" ]]; then
        log_info "Creating test data"
        if flask create-test-data &>/dev/null; then
            log_success "Test data created"
        else
            log_warning "Failed to create test data (command may not exist)"
        fi
    fi

    log_success "Database initialized successfully"
    return 0
}

# Function to create admin user
create_admin_user() {
    log_info "Creating admin user"

    # Check if flask command is available
    check_command flask

    # Run the create-admin command
    if flask create-admin; then
        log_success "Admin user created successfully"
        return 0
    else
        log_warning "Failed to create admin user"
        log_warning "This may be expected if an admin user already exists"
        return 0
    fi
}

# Function to verify environment
verify_environment() {
    log_info "Verifying environment setup"

    local all_passed=true

    # Check if flask app can be imported
    if python -c "from app import app" &>/dev/null; then
        log_success "✅ Flask application can be imported"
    else
        log_error "❌ Flask application cannot be imported"
        all_passed=false
    fi

    # Check database connection
    if python -c "from app import db; db.engine.connect()" &>/dev/null; then
        log_success "✅ Database connection successful"
    else
        log_warning "❌ Database connection failed"
        all_passed=false
    fi

    if [[ "$all_passed" == "true" ]]; then
        log_success "Environment verification completed successfully"
        return 0
    else
        log_warning "Environment verification completed with warnings"
        return 1
    fi
}

# Function to show next steps
show_next_steps() {
    cat <<EOF

$(log_success "Development environment setup complete!")

Next Steps:
-----------
1. Activate the virtual environment:
   source ${VENV_DIR}/bin/activate

2. Start the development server:
   flask run

3. Access the application:
   http://localhost:5000

Documentation:
-------------
- Development Guide: ${PROJECT_ROOT}/docs/development/getting-started.md
- API Documentation: ${PROJECT_ROOT}/docs/api/README.md

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --python)
            PYTHON_CMD="$2"
            shift 2
            ;;
        --venv-dir)
            VENV_DIR="$2"
            shift 2
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --skip-venv)
            SKIP_VENV=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Main execution
log_info "Starting development environment setup (v${SCRIPT_VERSION})"
log_info "Project root: ${PROJECT_ROOT}"

# Check required commands
check_command "$PYTHON_CMD"
check_command pip
check_command git

# Check Python version
check_python_version

# Set up virtual environment
if [[ "$SKIP_VENV" != "true" ]]; then
    setup_virtual_environment
fi

# Activate virtual environment
activate_virtual_environment

# Install dependencies
install_dependencies

# Set up configuration files
setup_config_files

# Initialize database
initialize_database

# Create admin user
create_admin_user

# Verify environment
verify_environment

# Show completion message and next steps
show_next_steps

exit 0
