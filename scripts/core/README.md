# Core Scripts for Cloud Infrastructure Platform

This directory contains core utility scripts that are essential for the operation and maintenance of the Cloud Infrastructure Platform. These scripts provide foundational functionality used across various modules and services.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Security Module](#security-module)
- [System Module](#system-module)
- [Initialization](#initialization)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Usage Examples](#usage-examples)
  - [Python Modules](#python-modules)
  - [Shell Scripts](#shell-scripts)
  - [Logging](#logging)
  - [Configuration Loading](#configuration-loading)
  - [Security Operations](#security-operations)
  - [Resource Monitoring](#resource-monitoring)
  - [System Information](#system-information)
  - [Error Handling](#error-handling)
  - [Notifications](#notifications)
  - [Initialization](#initialization-usage)
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

- **`error_handler.py`**: Provides standardized error handling.
  - **Usage**: Import this module to handle errors consistently.
  - **Features**:
    - Centralized error handling
    - Error categorization
    - Standardized logging
    - Alert generation
    - Error context preservation

- **`logger.py`**: Implements a robust logging system.
  - **Usage**: Import this module for consistent logging.
  - **Features**:
    - Multiple log levels
    - Contextual information
    - Output formatting
    - Log rotation
    - Environment-aware verbosity

- **`notification.py`**: Handles sending notifications across multiple channels.
  - **Usage**: Import this module to send system alerts and notifications.
  - **Features**:
    - Multi-channel support (email, SMS, chat)
    - Priority levels
    - Template rendering
    - Rate limiting
    - Delivery confirmation

- **`__init__.py`**: Centralizes initialization of core components.
  - **Usage**: Import to initialize core components or run directly to test initialization.
  - **Features**:
    - Unified environment setup
    - Centralized logging configuration
    - Configuration loading and validation
    - Dependency-aware component initialization
    - Command-line interface
    - Status reporting
    - Component availability tracking
    - Minimal logging setup
    - Error handling during initialization

- **`env_manager.py`**: Manages script-specific environment variables and integration with core environment.
  - **Usage**: Import this module for script environment management.
  - **Features**:
    - Integration with `core.environment` module
    - Script-specific environment detection
    - Environment variable validation
    - Environment file management
    - Secure credential handling
    - Environment comparison utilities

## Directory Structure

```plaintext
scripts/core/
├── common.sh               # Common shell utility functions
├── config_loader.py        # Configuration loading and validation
├── env_manager.py          # Environment management for scripts
├── error_handler.py        # Standardized error handling
├── __init__.py             # Core initialization module
├── logger.py               # Logging functionality
├── notification.py         # Notification services
├── README.md               # This documentation
├── security/               # Security-related functionality
│   ├── crypto.py           # Cryptographic operations
│   ├── integrity_check.py  # File integrity verification
│   ├── permissions.py      # Permission management
│   └── __init__.py         # Security module initialization
└── system/                 # System operation functionality
    ├── cloud_provider.py   # Cloud provider interactions
    ├── resource_monitor.py # System resource monitoring
    ├── system_info.py      # System information collection
    └── __init__.py         # System module initialization
```

> **Note**: Environment management functionality is provided by the `core.environment` module from the main application package, not in this scripts directory. For environment variable handling and environment detection, import directly from `core.environment` rather than from `scripts.core`. The `env_manager.py` module provides a bridge between script-specific environment needs and the core environment module.

## Security Module

The `security/` directory contains comprehensive security-related functionality:

- **`crypto.py`**: Provides cryptographic operations framework.
  - **Usage**: Import this module for secure encryption, hashing, and key management.
  - **Features**:
    - AES-GCM encryption with authenticated encryption
    - RSA asymmetric encryption for key exchange
    - Secure key derivation functions (PBKDF2, Argon2)
    - Cryptographically secure random number generation
    - Password hashing with adjustable work factors
    - Digital signature generation and verification
    - Hash computation with multiple algorithms
    - Key rotation management
    - Secure data wiping
    - Cryptographic parameter validation

- **`integrity_check.py`**: Ensures file integrity through hash verification.
  - **Usage**: Import this module to verify file integrity and detect unauthorized changes.
  - **Features**:
    - Multiple hash algorithm support (SHA-256, SHA-512, BLAKE2)
    - Baseline generation for integrity verification
    - Change detection with detailed reporting
    - Recursive directory scanning
    - File exclusion patterns
    - Integrity status caching
    - Verification scheduling
    - Critical file prioritization
    - Tamper evidence logging
    - Integration with notification system
    - Secure baseline storage

- **`permissions.py`**: Manages file and directory permissions management.
  - **Usage**: Import this module to handle permission checks and enforcement.
  - **Features**:
    - Permission validation against security baselines
    - Recursive permission application
    - Security-focused permission patterns
    - Ownership verification
    - SUID/SGID detection
    - World-writable file detection
    - Executable stack detection
    - Compliance checking against standards
    - Permission audit logging
    - Platform-aware permission handling
    - Security policy enforcement

- **`__init__.py`**: Centralizes security component initialization.
  - **Usage**: Import to initialize security modules with dependencies.
  - **Features**:
    - Security component dependency resolution
    - Cryptography subsystem initialization
    - File integrity monitoring setup
    - Permission management configuration
    - Security metrics collection
    - Centralized security logging
    - Component availability tracking
    - Initialization status reporting

## System Module

The `system/` directory contains functionality for system operations:

- **`cloud_provider.py`**: Manages interactions with cloud service providers.
  - **Usage**: Import this module to interact with cloud services across multiple platforms.
  - **Features**:
    - Multi-cloud provider support (AWS, Azure, GCP)
    - Cloud resource management
    - Provider-specific functionality
    - Authentication handling
    - Request retries with exponential backoff
    - Error handling with circuit breakers
    - Resource provisioning and management
    - Cost optimization utilities
    - Cross-provider abstraction layer
    - Secure credential management

- **`resource_monitor.py`**: Monitors system resource usage across the platform.
  - **Usage**: Import this module to track resource utilization and set up alerts.
  - **Features**:
    - CPU, memory, disk, and network monitoring
    - Resource utilization alerts
    - Performance metrics collection
    - Threshold management
    - Historical tracking
    - Time-series data collection
    - Alert escalation policies
    - Customizable monitoring intervals
    - Resource trend analysis
    - Integration with notification system

- **`system_info.py`**: Collects detailed system information for operations and diagnostics.
  - **Usage**: Import this module to gather comprehensive system details.
  - **Features**:
    - Hardware information collection
    - Operating system details
    - Network configuration data
    - Service status monitoring
    - Environment identification
    - Container and virtualization detection
    - System capability assessment
    - Dependency verification
    - Configuration validation
    - Performance baseline measurement

- **`__init__.py`**: Centralizes system component initialization.
  - **Usage**: Import to initialize system modules with dependencies.
  - **Features**:
    - System component dependency resolution
    - Component availability tracking
    - System prerequisite verification
    - Cloud provider initialization
    - Resource monitoring setup
    - System information configuration

## Initialization

The `__init__.py` module in the core directory provides centralized initialization for all core components:

- **Dependency Resolution**: Components are initialized in the correct order based on dependencies.
- **Component Availability Tracking**: Keeps track of which components are successfully initialized.
- **Minimal Logging Setup**: Provides basic logging before full logger is initialized.
- **Environment Setup**: Configures the running environment based on parameters or environment variables.
- **Command Line Interface**: Provides CLI options for initialization and component status checking.
- **Script Environment Setup**: One-step function for setting up script environment with proper logging and configuration.
- **Graceful Degradation**: Handles missing or failed components by continuing with limited functionality.
- **Centralized Configuration**: Provides unified configuration loading across components.
- **Status Reporting**: Ability to check and report on component initialization status.
- **Multiple Environment Sources**: Support for both `core.environment` and script-specific `env_manager`.
- **Security Initialization**: Secure defaults for security components based on environment.
- **System Component Integration**: Proper initialization of system components with error handling.

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
- **Initialization Order**: Follow proper initialization order through the `__init__.py` module
- **Component Availability**: Always check component availability before using functionality
- **Graceful Degradation**: Handle missing or unavailable components with fallback behavior
- **Environment Awareness**: Ensure components behave appropriately for current environment

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
- Centralized component initialization
- Component availability tracking
- Dependency resolution
- Configuration validation
- Secure credential handling
- Environment-specific behavior
- CLI interfaces for components

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

# Using environment functionality from core package
from core.environment import get_current_environment, is_production

env = get_current_environment()
if is_production():
    log.info("Running in production environment")
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
from scripts.core.security.crypto import encrypt_data, decrypt_data, generate_key
from scripts.core.security.integrity_check import verify_file_integrity, create_baseline
from scripts.core.security.permissions import check_file_permissions, set_secure_permissions

# Generate a secure encryption key
encryption_key = generate_key()

# Encrypt and decrypt sensitive data
secret_key = os.environ.get("SECRET_KEY")
encrypted_data = encrypt_data("sensitive information", secret_key)
decrypted_data = decrypt_data(encrypted_data, secret_key)

# Create integrity baseline
create_baseline("/etc/config", "/var/baseline/checksums.json",
                algorithms=["sha256"], exclude_patterns=["*.tmp"])

# Verify file integrity
integrity_ok = verify_file_integrity("/etc/config/app.conf",
                                    baseline_path="/var/baseline/checksums.json")
if not integrity_ok:
    log.critical("Configuration file integrity check failed")
    # Take appropriate action

# Check file permissions
if not check_file_permissions("/etc/config/app.conf", mode=0o640):
    log.warning("Configuration file has incorrect permissions")
    # Fix permissions
    set_secure_permissions("/etc/config/app.conf", mode=0o640,
                          owner="root", group="app")
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

### System Information

```python
# Import system information module
from scripts.core.system.system_info import SystemInfo

# Create system info instance
sys_info = SystemInfo()

# Get basic system information
os_info = sys_info.get_os_info()
print(f"OS: {os_info['name']} {os_info['version']}")
print(f"Kernel: {sys_info.get_kernel_version()}")
print(f"CPU cores: {sys_info.get_cpu_count()}")

# Check service status
if sys_info.is_service_running("nginx"):
    print("NGINX is running")
else:
    print("NGINX is not running")

# Get network information
network_info = sys_info.get_network_info()
for interface, details in network_info.items():
    print(f"Interface: {interface}, IP: {details['ip']}")

# Check system capabilities
if sys_info.has_capability("docker"):
    print("Docker is available")
    containers = sys_info.get_container_info()
    print(f"Running containers: {len(containers)}")

# Generate comprehensive report
report = sys_info.generate_report(include_sensitive=False)
sys_info.save_report(report, "/var/log/system_report.json")
```

### Error Handling

```python
# Import error handler
from scripts.core.error_handler import ErrorHandler, ApplicationError, ErrorCategory

# Create error handler with correlation ID
handler = ErrorHandler(correlation_id="req-abc-123")

try:
    # Some operation
    result = perform_operation()
except ConnectionError as e:
    # Handle specific error type
    handler.handle_error(e, "Failed to connect to service",
                        category=ErrorCategory.NETWORK, retry=True)
except ApplicationError as e:
    # Custom application error
    handler.handle_error(e, "Application error occurred",
                        category=ErrorCategory.APPLICATION, alert=True)
except Exception as e:
    # Generic error
    handler.handle_error(e, "Unexpected error",
                        category=ErrorCategory.SYSTEM, critical=True)
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

### Initialization Usage

```python
# Import core initialization module
from scripts.core import setup_script_environment, get_component_status

# Set up script environment with specific configuration
success = setup_script_environment(
    config_file="config/app.yaml",
    environment="production",
    log_level="INFO"
)

# Check component status
components = get_component_status()
if not components["logger"] or not components["config_loader"]:
    print("Critical components not available")
    sys.exit(1)

# Load application configuration
from scripts.core import load_configuration
config = load_configuration()

# Initialize security components
from scripts.core.security import initialize_security_components
security_success, security_errors = initialize_security_components(
    security_level="high",
    log_level="INFO"
)

# Access environment functionality from main core package
from core.environment import get_current_environment, is_production
env = get_current_environment()
if is_production():
    print("Running in production environment")

# Run as command-line tool to check initialization status
# python -m scripts.core --environment production --log-level DEBUG --status
```

## Module Dependencies

- **Logger**: No internal dependencies
- **ConfigLoader**: Depends on `logger`
- **ErrorHandler**: Depends on `logger` and `notification`
- **Security modules**: Depend on `logger` and `error_handler`
- **System modules**: Depend on `logger`, `error_handler`, and `config_loader`
- **Notification**: Depends on `logger` and `config_loader`
- **`__init__.py`**: Manages dependencies for all other modules
- **All scripts/core components**: May depend on `core.environment` from main application package
- **env_manager**: Bridges between scripts/core and `core.environment`

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
- Cryptographic Standards
- File Integrity Monitoring Guide
- Permission Security Model
- Security Architecture Overview
- System Information Collection Guide
- Component Initialization Guide
- Environment Management Guide
- Initialization Sequence Documentation
- Core Module API Integration Guide
- Script Environment Configuration Guide

## Version History

- **0.0.3 (2024-10-20)**: Added centralized initialization system with dependency resolution
- **0.0.2 (2024-01-05)**: Major refactor with modular design and enhanced security
- **0.0.1 (2023-04-15)**: Initial release of core script utilities
