# Core Scripts for Cloud Infrastructure Platform

This directory contains core utility scripts that are essential for the operation and maintenance of the Cloud Infrastructure Platform. These scripts provide foundational functionality used across various modules and services.

## Overview

The core scripts in this directory are designed to streamline operations, enhance security, and ensure compliance across the Cloud Infrastructure Platform. These scripts include utilities for system information, resource monitoring, error handling, logging, configuration loading, and security functions. These core scripts form the foundation for the platform's operational capabilities.

## Key Scripts

- **`common.sh`**: Core shell utility functions used across multiple scripts.
  - **Usage**: Source this script in other shell scripts to use its functions.
  - **Features**:
    - Common utility functions
    - Cross-platform compatibility functions
    - Environment detection

- **`config_loader.py`**: Loads and validates configuration from various sources.
  - **Usage**: Import this module to handle configuration loading.
  - **Features**:
    - Multi-format configuration support (JSON, YAML, INI)
    - Environment-specific configuration
    - Configuration validation

- **`environment.py`**: Manages environment variables and settings.
  - **Usage**: Import this module to access environment settings.
  - **Features**:
    - Environment variable management
    - Runtime environment detection
    - Environment-specific behavior

- **`error_handler.py`**: Provides standardized error handling.
  - **Usage**: Import this module to implement consistent error handling.
  - **Features**:
    - Structured error reporting
    - Error categorization
    - Custom exception types

- **`logger.py`**: Provides a standardized logging interface.
  - **Usage**: Import this module to implement consistent logging.
  - **Features**:
    - Multiple log levels (DEBUG, INFO, WARNING, ERROR)
    - Configurable log destinations
    - Log rotation and management

- **`notification.py`**: Sends notifications through various channels.
  - **Usage**: Import this module to send notifications.
  - **Features**:
    - Multiple notification channels
    - Templated notifications
    - Notification priorities

## Security Module

The `security/` directory contains specific security-related functionality:

- **`crypto.py`**: Provides cryptographic operations.
  - **Usage**: Import this module for secure encryption and decryption.
  - **Features**:
    - Symmetric and asymmetric encryption
    - Secure hash functions
    - Key management

- **`integrity_check.py`**: Ensures file integrity through hash verification.
  - **Usage**: Import this module to verify file integrity.
  - **Features**:
    - Multiple hash algorithm support
    - Automated verification
    - Change detection

- **`permissions.py`**: Manages file and resource permissions.
  - **Usage**: Import this module to handle permission checks and changes.
  - **Features**:
    - Permission validation
    - Secure permission setting
    - Permission audit functions

## System Module

The `system/` directory contains functionality for system operations:

- **`cloud_provider.py`**: Manages interactions with cloud providers.
  - **Usage**: Import this module to interact with cloud services.
  - **Features**:
    - Multi-cloud provider support
    - Cloud resource management
    - Provider-specific functionality

- **`resource_monitor.py`**: Monitors system resource usage.
  - **Usage**: Import this module to track resource utilization.
  - **Features**:
    - CPU, memory, disk, and network monitoring
    - Resource utilization alerts
    - Performance metrics collection

- **`system_info.py`**: Collects system information.
  - **Usage**: Import this module to gather system details.
  - **Features**:
    - Hardware information collection
    - Operating system details
    - Network configuration data

## Best Practices

- **Reusability**: Import appropriate modules rather than duplicating functionality.
- **Security**: Use security functions from the security module for all sensitive operations.
- **Logging**: Use the logger module consistently for all log messages.
- **Error Handling**: Implement proper error handling with the `error_handler` module.
- **Configuration**: Use the `config_loader` to ensure consistent configuration management.
- **Testing**: Test scripts in a staging environment before deploying to production.

## Directory Structure

```bash
scripts/core/
├── common.sh               # Common shell utility functions
├── config_loader.py        # Configuration loading and validation
├── environment.py          # Environment variable and settings management
├── error_handler.py        # Standardized error handling
├── logger.py               # Logging functionality
├── notification.py         # Notification services
├── README.md               # This documentation
├── security/               # Security-related functionality
│   ├── crypto.py           # Cryptographic operations
│   ├── integrity_check.py  # File integrity verification
│   └── permissions.py      # Permission management
└── system/                 # System operation functionality
    ├── cloud_provider.py   # Cloud provider interactions
    ├── resource_monitor.py # System resource monitoring
    └── system_info.py      # System information collection
```

## Usage Examples

### Python Modules

```python
# Using the logger
from scripts.core.logger import Logger

log = Logger.get_logger("my_module")
log.info("Operation completed successfully")
log.error("Failed to connect to service", exc_info=True)

# Using configuration loader
from scripts.core.config_loader import ConfigLoader

config = ConfigLoader.load("config/app.yaml")
database_url = config.get("database.url")

# Using resource monitoring
from scripts.core.system.resource_monitor import ResourceMonitor

monitor = ResourceMonitor()
cpu_usage = monitor.get_cpu_usage()
if cpu_usage > 90:
    monitor.send_alert("High CPU Usage", f"Current usage: {cpu_usage}%")
```

### Shell Scripts

```bash
# Source common shell functions
source "$(dirname "$0")/../core/common.sh"

# Use functions from common.sh
if command_exists "aws"; then
    log_info "AWS CLI is available"
else
    log_error "AWS CLI not found"
    exit 1
fi
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
