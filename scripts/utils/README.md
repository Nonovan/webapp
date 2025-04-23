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
./utils/env_setup.sh --env development

# Configure environment for production
./utils/env_setup.sh --env production

```

### Development Tools

```bash
# Set up development environment
./utils/dev_tools/setup_dev_environment.sh

# Run linting tools on code
./utils/dev_tools/lint.sh

```

## Best Practices

- Use `common_functions.sh` for shared functionality across scripts
- Source the appropriate environment using env_setup.sh at the beginning of scripts
- Run linting regularly during development to maintain code quality
- Keep test coverage high for all utility functions
