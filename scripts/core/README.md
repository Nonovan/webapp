# Core Scripts for Cloud Infrastructure Platform

This directory contains core utility scripts that are essential for the operation and maintenance of the Cloud Infrastructure Platform. These scripts provide foundational functionality used across various modules and services.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Security Module](#security-module)
- [System Module](#system-module)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
  - [Python Modules](#python-modules)
  - [Shell Scripts](#shell-scripts)
  - [Logging](#logging)
  - [Configuration Loading](#configuration-loading)
  - [Security Operations](#security-operations)
  - [Resource Monitoring](#resource-monitoring)
  - [Error Handling](#error-handling)
  - [Notifications](#notifications)
- [Module Dependencies](#module-dependencies)
- [Related Documentation](#related-documentation)
- [Version History](#version-history)

## Overview

The core scripts in this directory are designed to streamline operations, enhance security, and ensure compliance across the Cloud Infrastructure Platform. These scripts include utilities for system information, resource monitoring, error handling, logging, configuration loading, and security functions. These core scripts form the foundation for the platform's operational capabilities.

## Key Components

- **`common.sh`**: Core shell utility functions used across multiple scripts.
  - **Usage**: Source this script in other shell scripts to use its functions.
  - **Features**:
    - Common utility functions
    - Cross-platform compatibility functions
    - Environment detection
    - Error handling primitives
    - Logging utilities

- **`config_loader.py`**: Loads and validates configuration from various sources.
  - **Usage**: Import this module to handle configuration loading.
  - **Features**:
    - Multi-format support (JSON, YAML, INI)
    - Environment-specific configuration
    - Configuration validation
    - Schema enforcement
    - Default value handling

- **`environment.py`**: Manages environment variables and settings.
  - **Usage**: Import this module to access environment settings.
  - **Features**:
    - Environment variable management
    - Runtime environment detection
    - Environment-specific behavior
    - Secure secrets handling
    - Configuration override mechanism

- **`error_handler.py`**: Provides standardized error handling.
  - **Usage**: Import this module to implement consistent error handling.
  - **Features**:
    - Structured error reporting
    - Error categorization
    - Custom exception types
    - Error tracking integration
    - Error correlation

- **`logger.py`**: Provides a standardized logging interface.
  - **Usage**: Import this module to implement consistent logging.
  - **Features**:
    - Multiple log levels (DEBUG, INFO, WARNING, ERROR)
    - Configurable log destinations
    - Log rotation and management
    - Structured logging format
    - Integration with monitoring systems

- **`notification.py`**: Sends notifications through various channels.
  - **Usage**: Import this module to send notifications.
  - **Features**:
    - Multiple notification channels (email, SMS, chat)
    - Templated notifications
    - Notification priorities
    - Rate limiting
    - Delivery verification

## Directory Structure

```plaintext
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

## Security Module

The `security/` directory contains specific security-related functionality:

- **`crypto.py`**: Provides cryptographic operations.
  - **Usage**: Import this module for secure encryption and decryption.
  - **Features**:
    - Symmetric and asymmetric encryption
    - Secure hash functions
    - Key management
    - Digital signatures
    - Password hashing and verification

- **`integrity_check.py`**: Ensures file integrity through hash verification.
  - **Usage**: Import this module to verify file integrity.
  - **Features**:
    - Multiple hash algorithm support
    - Automated verification
    - Change detection
    - Baseline generation and comparison
    - Integrity alerts

- **`permissions.py`**: Manages file and resource permissions.
  - **Usage**: Import this module to handle permission checks and changes.
  - **Features**:
    - Permission validation
    - Secure permission setting
    - Permission audit functions
    - Security baseline enforcement
    - Compliance checking

## System Module

The `system/` directory contains functionality for system operations:

- **`cloud_provider.py`**: Manages interactions with cloud providers.
  - **Usage**: Import this module to interact with cloud services.
  - **Features**:
    - Multi-cloud provider support (AWS, Azure, GCP)
    - Cloud resource management
    - Provider-specific functionality
    - Authentication handling
    - Request retries with exponential backoff

- **`resource_monitor.py`**: Monitors system resource usage.
  - **Usage**: Import this module to track resource utilization.
  - **Features**:
    - CPU, memory, disk, and network monitoring
    - Resource utilization alerts
    - Performance metrics collection
    - Threshold management
    - Historical tracking

- **`system_info.py`**: Collects system information.
  - **Usage**: Import this module to gather system details.
  - **Features**:
    - Hardware information collection
    - Operating system details
    - Network configuration data
    - Service status monitoring
    - Environment identification

## Best Practices & Security

- **Reusability**: Import appropriate modules rather than duplicating functionality
- **Security**: Use security functions from the security module for all sensitive operations
- **Logging**: Use the logger module consistently for all log messages with appropriate levels
- **Error Handling**: Implement proper error handling with the `error_handler` module
- **Configuration**: Use the `config_loader` to ensure consistent configuration management
- **Input Validation**: Validate all inputs, especially those from external sources
- **Testing**: Test scripts in a staging environment before deploying to production
- **Authentication**: Apply proper credential management for all service connections
- **Permissions**: Follow principle of least privilege for all operations
- **Secrets**: Never hardcode secrets; use environment variables or secure storage
- **Timeout Management**: Implement appropriate timeouts for external operations
- **Resource Cleanup**: Ensure resources are properly released, even in error cases
- **Failure Recovery**: Implement retries with exponential backoff for transient failures

## Common Features

- Environment detection and configuration
- Standardized logging with multiple levels
- Comprehensive error handling
- Secure cryptographic operations
- File integrity verification
- Cloud provider integration
- Resource usage monitoring
- System information gathering
- Secure notification delivery
- Request ID correlation
- Performance metrics collection
- File operation atomicity
- Circuit breaker patterns
- Exponential backoff retry mechanisms
- Input validation and sanitization
- Safe default configurations
- Tracing and observability

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

### Logging

```python
# Import the logger module
from scripts.core.logger import Logger

# Create a logger for the current module
log = Logger.get_logger(__name__)

# Log messages at different levels
log.debug("Detailed debugging information")
log.info("General operational information")
log.warning("Warning about potential issues")
log.error("Error that doesn't prevent execution")
log.critical("Critical error that prevents execution")

# Log with additional context
log.info("User operation", extra={"user_id": 12345, "operation": "update"})

# Log exceptions with traceback
try:
    # Some operation
    result = 10 / 0
except Exception as e:
    log.error("Operation failed", exc_info=True)
```

### Configuration Loading

```python
# Import the configuration loader
from scripts.core.config_loader import ConfigLoader

# Load configuration with environment-specific overrides
config = ConfigLoader.load("config/database.yaml", environment="production")

# Access configuration values with defaults
host = config.get("database.host", default="localhost")
port = config.get_int("database.port", default=5432)
max_connections = config.get_int("database.max_connections", default=100)

# Validate configuration against schema
is_valid = config.validate("schemas/database_schema.json")
if not is_valid:
    raise ValueError("Invalid database configuration")
```

### Security Operations

```python
# Import security modules
from scripts.core.security.crypto import encrypt_data, decrypt_data
from scripts.core.security.integrity_check import verify_file_integrity
from scripts.core.security.permissions import check_file_permissions

# Encrypt and decrypt sensitive data
secret_key = os.environ.get("SECRET_KEY")
encrypted_data = encrypt_data("sensitive information", secret_key)
decrypted_data = decrypt_data(encrypted_data, secret_key)

# Verify file integrity
integrity_ok = verify_file_integrity("/etc/config/app.conf",
                                    baseline_path="/var/baseline/checksums.json")
if not integrity_ok:
    log.critical("Configuration file integrity check failed")
    # Take appropriate action

# Check file permissions
if not check_file_permissions("/etc/config/app.conf", mode=0o640):
    log.warning("Configuration file has incorrect permissions")
    # Fix permissions or alert
```

### Resource Monitoring

```python
# Import resource monitoring
from scripts.core.system.resource_monitor import ResourceMonitor

# Create monitor instance
monitor = ResourceMonitor()

# Get system metrics
cpu_usage = monitor.get_cpu_usage()
memory_usage = monitor.get_memory_usage()
disk_usage = monitor.get_disk_usage("/var/log")

# Check thresholds and alert if necessary
if cpu_usage > 90:
    monitor.send_alert("HIGH_CPU", f"CPU usage at {cpu_usage}%")

# Track historical metrics
monitor.record_metric("cpu_usage", cpu_usage)
monitor.record_metric("memory_usage", memory_usage)

# Get cloud provider metrics
cloud_metrics = monitor.get_cloud_metrics("aws", "ec2", instance_id="i-12345")
```

### Error Handling

```python
# Import error handler
from scripts.core.error_handler import ErrorHandler, ApplicationError

# Create error handler with correlation ID
handler = ErrorHandler(correlation_id="req-abc-123")

try:
    # Some operation
    result = perform_operation()
except ConnectionError as e:
    # Handle specific error type
    handler.handle_error(e, "Failed to connect to service", retry=True)
except ApplicationError as e:
    # Custom application error
    handler.handle_error(e, "Application error occurred", alert=True)
except Exception as e:
    # Generic error
    handler.handle_error(e, "Unexpected error", critical=True)
```

### Notifications

```python
# Import notification module
from scripts.core.notification import NotificationService

# Create notification service
notifier = NotificationService()

# Send simple notification
notifier.send("Alert: System restart required", channels=["email"])

# Send with template
notifier.send_template("system_alert",
                     {"alert_level": "critical", "message": "Disk space low"},
                     recipients=["admin@example.com"],
                     priority="high")

# Send with channel-specific options
notifier.send("Database backup completed",
            channels=["slack"],
            channel_options={
                "slack": {"channel": "#ops", "color": "good"}
            })
```

## Module Dependencies

- **Logger**: No internal dependencies
- **ConfigLoader**: Depends on `logger`
- **Environment**: Depends on `logger` and `config_loader`
- **ErrorHandler**: Depends on `logger` and `notification`
- **Security modules**: Depend on `logger` and `error_handler`
- **System modules**: Depend on `logger`, `error_handler`, and `config_loader`
- **Notification**: Depends on `logger` and `config_loader`

## Related Documentation

- Error Handling Guidelines
- Logging Standards
- Security Best Practices
- Configuration Management
- Monitoring Framework
- Core Module API Reference
- Notification System Guide
- Resource Monitoring Guide
- Cloud Integration Reference
- Integrity Monitoring Guide

## Version History

- **0.0.2 (2024-01-05)**: Major refactor with modular design and enhanced security
- **0.0.1 (2023-04-15)**: Initial release of core script utilities
