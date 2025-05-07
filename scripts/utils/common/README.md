# Common Utility Modules for Cloud Infrastructure Platform

This directory contains shared utility modules that provide reusable functionality across the Cloud Infrastructure Platform. These modules are primarily loaded through `common_functions.sh` and implement standardized operations for logging, file handling, system operations, networking, and more.

## Overview

These utility modules form the foundation of the platform's shell scripting capabilities. They are designed to be:

- **Modular**: Each module focuses on a specific area of functionality
- **Reusable**: Functions can be used across different scripts
- **Secure**: Implementing security best practices by default
- **Consistent**: Following standard patterns for error handling and logging
- **Well-documented**: With complete documentation of parameters and return values

## Module Structure

Each module follows a consistent structure:

- Version information
- Dependency checking
- Core functionality organized by purpose
- Function exports at the end

## Available Modules

| Module | Description | Key Functions |
|--------|-------------|--------------|
| [`common_core_utils.sh`](common_core_utils.sh) | Core logging and environment functions | `log`, `error_exit`, `warn`, `debug`, `load_env` |
| [`common_system_utils.sh`](common_system_utils.sh) | System information and OS operations | `get_system_info`, `check_disk_space`, `execute_with_timeout` |
| [`common_file_ops_utils.sh`](common_file_ops_utils.sh) | File operations and manipulation | `backup_file`, `atomic_write_file`, `get_file_hash` |
| [`common_validation_utils.sh`](common_validation_utils.sh) | Input validation and sanitization | `is_valid_ip`, `is_number`, `sanitize_input` |
| [`common_health_utils.sh`](common_health_utils.sh) | Health checks and monitoring | `is_service_running`, `check_disk_usage_threshold` |
| [`common_advanced_utils.sh`](common_advanced_utils.sh) | Advanced utilities | `send_notification`, `parse_json`, `generate_random_string` |
| [`common_network_utils.sh`](common_network_utils.sh) | Network operations | `check_url`, `resolve_hostname`, `is_port_in_use` |
| [`common_cloud_utils.sh`](common_cloud_utils.sh) | Cloud provider integrations | `check_aws_auth`, `create_secure_s3_bucket` |
| [`common_database_utils.sh`](common_database_utils.sh) | Database operations | `check_postgres_connection`, `pg_execute` |

## Usage

These modules are typically loaded through the parent `common_functions.sh` script:

```bash
# Source all default modules
source "$(dirname "$0")/../scripts/utils/common_functions.sh"

# Or source specific modules
source "$(dirname "$0")/../scripts/utils/common_functions.sh" core,file_ops,validation
```

Direct usage of an individual module is possible but not recommended as it requires handling dependencies manually:

```bash
# First load the core module (contains required functions)
source "$(dirname "$0")/../scripts/utils/common/common_core_utils.sh"

# Then load other modules that depend on core
source "$(dirname "$0")/../scripts/utils/common/common_file_ops_utils.sh"
```

## Key Module Details

### Core Utilities (`common_core_utils.sh`)

Foundation module providing logging and environment functions:

- `log`, `error_exit`, `warn`, `debug` - Standard logging functions
- `init_log_file`, `rotate_log_file` - Log file management
- `load_env`, `save_env` - Environment variable handling
- `detect_environment` - Environment detection

### System Utilities (`common_system_utils.sh`)

System information retrieval and operations:

- `get_system_info` - Retrieves OS, kernel, hostname information
- `check_disk_space` - Verifies available disk space
- `is_port_in_use` - Checks if a network port is in use
- `execute_with_timeout` - Run commands with timeout protection
- `get_memory_info` - Memory usage information

### File Operations (`common_file_ops_utils.sh`)

Secure file handling operations:

- `backup_file` - Creates timestamped backups
- `atomic_write_file` - Ensures atomic file updates
- `get_file_hash` - Calculates file checksums
- `verify_file_integrity` - Validates file contents
- `find_files` - Safely searches for files

### Validation Utilities (`common_validation_utils.sh`)

Input validation and sanitization:

- `is_valid_ip` - Validates IP address format
- `is_number` - Checks for numeric values
- `has_min_length` - String length validation
- `sanitize_input` - Removes dangerous characters
- `is_safe_path` - Prevents path traversal attacks

## Constants and Environment Variables

Important constants defined in these modules:

- File permissions: `DEFAULT_FILE_PERMS`, `DEFAULT_LOG_FILE_PERMS`
- Logging constants: `DEFAULT_LOG_MAX_SIZE`, `DEFAULT_LOG_BACKUPS`
- Error prefixes: `ERROR_PREFIX`, `WARNING_PREFIX`, `INFO_PREFIX`
- Security settings: `DEFAULT_SECRET_FILE_PERMS`, `DEFAULT_VALIDATION_TIMEOUT`

## Best Practices

When using these utility modules:

1. **Always source common_functions.sh** rather than individual modules
2. **Use parallel loading** for performance: `--parallel` option
3. **Handle errors appropriately** using the provided error functions
4. **Validate all inputs** with the validation utilities
5. **Secure sensitive files** using the recommended permission constants
6. **Clean up resources** with proper trap handlers
7. **Use atomic operations** for file modifications

## Version Information

Each module maintains its own version using constants like `CORE_UTILS_VERSION`, `SYSTEM_UTILS_VERSION`, etc.
