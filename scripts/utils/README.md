# Utility Scripts for Cloud Infrastructure Platform

## Overview

This directory contains utility scripts for configuring, managing, and maintaining the Cloud Infrastructure Platform. These scripts provide standardized functionality for common operations such as environment configuration, file operations, system monitoring, validation, and developer workflows.

## Key Scripts

- **`common_functions.sh`**: Core script that provides shared functionality for all platform scripts
  - **Usage**: Source this script in other shell scripts to use its functions
  - **Features**:
    - Modular loading of utility components
    - Standardized logging framework
    - Error handling and reporting
    - Parallel module loading for improved performance

- **`env_setup.sh`**: Configures environment variables for different deployment environments
  - **Usage**: Execute or source this script to set up environment variables
  - **Features**:
    - Environment-specific configuration
    - Secret management integration
    - Cloud provider credential setup
    - Configuration validation

## Directory Structure

```plaintext
scripts/utils/
├── common_functions.sh          # Core functions script
├── env_setup.sh                 # Environment setup utility
├── README.md                    # This documentation
├── common/                      # Common modules used by common_functions.sh
│   ├── common_advanced_utils.sh # Advanced utilities
│   ├── common_cloud_utils.sh    # Cloud provider integrations
│   ├── common_core_utils.sh     # Core utility functions
│   ├── common_database_utils.sh # Database operations
│   ├── common_file_ops_utils.sh # File operation utilities
│   ├── common_health_utils.sh   # Health check functions
│   ├── common_network_utils.sh  # Network operation utilities
│   ├── common_system_utils.sh   # System utilities
│   └── common_validation_utils.sh # Input validation utilities
├── dev_tools/                   # Development utilities
│   ├── generate_docs.sh         # Documentation generation utility
│   ├── lint.sh                  # Code linting utility
│   └── setup_dev_environment.sh # Development environment setup
├── python/                      # Python helper scripts
│   ├── generate_sample_data.py  # Creates sample data for testing
│   └── json_yaml_converter.py   # Converts between JSON and YAML
└── testing/                     # Testing utilities
    ├── test_common_functions.sh # Tests for common_functions.sh
    └── test_utils.sh            # General testing utilities
```

## Best Practices & Security

- Always source `common_functions.sh` before using any utility functions
- Use dedicated validation functions from `common_validation_utils.sh` for input sanitization
- Follow the principle of least privilege when executing commands
- Store sensitive credentials in environment variables, never hardcode
- Implement proper error handling with appropriate exit codes
- Include detailed logging with correct severity levels
- Use atomic file operations when modifying configuration files
- Set appropriate permissions for files containing sensitive information
- Ensure resource cleanup in error cases using trap handlers
- Run linting regularly using `lint.sh` to maintain code quality
- Keep test coverage high for all utility functions
- Use timeout mechanisms for operations that might hang

## Common Features

- Standardized logging with multiple levels (DEBUG, INFO, WARNING, ERROR)
- Input validation and sanitization
- Environment-specific configuration management
- Secure file operations with atomic updates
- Health check capabilities for services and resources
- Cloud provider integration with multi-provider support
- Retry mechanisms with exponential backoff
- Resource cleanup with trap handlers
- Parallel execution support for improved performance
- Configurable timeout handling

## Usage

### Environment Setup

```bash
# Configure environment variables for development
./scripts/utils/env_setup.sh --env development

# Configure environment for production
./scripts/utils/env_setup.sh --env production
```

### Code Quality Tools

```bash
# Run linting tools on code
./scripts/utils/dev_tools/lint.sh

# Run with specific options
./scripts/utils/dev_tools/lint.sh --fix --path scripts/deployment
```

### Development Environment Setup

```bash
# Set up development environment
./scripts/utils/dev_tools/setup_dev_environment.sh

# Set up environment with specific options
./scripts/utils/dev_tools/setup_dev_environment.sh --with-cloud-sdk --skip-db
```

### Common Functions Usage

```bash
# Source common functions in a script
source "$(dirname "$0")/../utils/common_functions.sh"

# Load specific modules
source "$(dirname "$0")/../utils/common_functions.sh" core,file_ops,validation

# Load modules in parallel for improved performance
source "$(dirname "$0")/../utils/common_functions.sh" --parallel core,file_ops,validation
```

## Related Documentation

- Development Guide
- Testing Guide
- Script Development Standards
- Common Functions Reference
