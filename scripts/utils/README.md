# Utility Scripts for Cloud Infrastructure Platform

## Overview
This directory contains utility scripts for configuring, managing, and maintaining the Cloud Infrastructure Platform.

## Key Scripts
- **`common_functions.sh`**: Core script that provides shared functionality for all platform scripts
- **`env_setup.sh`**: Configures environment variables for different deployment environments

## Directory Structure
```bash
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

## Best Practices

- Use `common_functions.sh` for shared functionality across scripts
- Source the appropriate environment using env_setup.sh at the beginning of scripts
- Run linting regularly during development to maintain code quality
- Keep test coverage high for all utility functions
- Follow the established error handling patterns for consistent behavior
- Use the validation functions for input sanitization
- Always include proper logging with appropriate severity levels
- Implement timeout mechanisms for operations that might hang
- Use atomic file operations when modifying configuration files
- Ensure proper resource cleanup in error cases using trap handlers

## Security Considerations

- Always validate and sanitize user inputs
- Use dedicated functions from common_validation_utils.sh for input validation
- Never execute commands with unchecked user input
- Follow the principle of least privilege
- Use secure methods for credential handling via environment variables
- Implement proper error handling and logging for security-related operations
- Set appropriate file permissions when creating new files

## Additional Resources

- For more information on individual utility modules, see their respective header comments
- See the Development Guide for more details on script development standards
- Check the Testing Guide for information on testing utilities
