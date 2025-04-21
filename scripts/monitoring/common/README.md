# Common Monitoring Utilities

This directory contains common utilities and shared functions used across monitoring scripts for the Cloud Infrastructure Platform.

## Overview

These utilities provide standardized functionality used by multiple monitoring components, ensuring consistency in logging, error handling, and configuration management.

## Components

- `logging_utils.sh` - Standard logging functions with consistent formatting
- `config_loader.sh` - Loads environment-specific configuration files
- `credentials_manager.sh` - Secure handling of authentication credentials
- `network_utils.sh` - Common network connectivity and testing functions
- `date_utils.sh` - Date and time manipulation functions
- `validation.sh` - Input validation and sanitization
- `format_utils.sh` - Output formatting for reports and notifications
- `error_handling.sh` - Standardized error handling and reporting

## Usage

These utilities are designed to be sourced by other scripts:

```bash
#!/bin/bash
# Source common utilities
source "$(dirname "$0")/../common/logging_utils.sh"
source "$(dirname "$0")/../common/config_loader.sh"

# Use the utilities
log_info "Starting monitoring process"
load_config "$ENVIRONMENT"
```

## Key Features

- Standardized logging with severity levels (INFO, WARNING, ERROR, CRITICAL)
- Environment-aware configuration management
- Secure credential handling without exposing sensitive information
- Consistent error handling and exit codes
- Output formatting in multiple formats (text, JSON, CSV)

## Best Practices

- Always use these common utilities rather than implementing similar functionality
- Follow the error handling patterns to ensure proper exit codes
- Use the validation functions to sanitize inputs
- Log appropriately using the provided severity levels

## Related Files

- [Core Configuration](../config/defaults.conf)
- [Environment Configurations](../../../deployment/environments/)
