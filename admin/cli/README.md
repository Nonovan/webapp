# Admin CLI Tools

This directory contains command-line interface tools for administrative tasks in the Cloud Infrastructure Platform. These CLI tools provide administrators with efficient ways to manage users, configure system settings, and perform security operations.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
  - [Core Command Framework](#core-command-framework)
  - [User Administration](#user-administration)
  - [User Import](#user-import)
  - [Permission Management](#permission-management)
  - [System Configuration](#system-configuration)
  - [Security Administration](#security-administration)
  - [Commands Testing](#commands-testing)
  - [Command Dependencies](#command-dependencies)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The Admin CLI tools provide command-line interfaces for performing administrative tasks that would otherwise require accessing the web interface. These tools are designed for system administrators who need to perform batch operations, automate routine tasks, or administer the system in environments where the web interface may not be available. The tools implement the same security controls as the web interface, requiring proper authentication and authorization for all operations.

## Key Components

- **`admin_commands.py`**: Core command registry and execution framework
  - Command registration and discovery system
  - Permission verification for all commands
  - Input validation framework
  - Output formatting options
  - Execution logging capabilities
  - Command dependency management
  - Test mode for command validation

- **`base_command.py`**: Base class for command handlers
  - Consistent command structure
  - Standardized registration mechanism
  - Built-in permission integration
  - Simplified audit logging
  - Category organization

- **`command_tester.py`**: Command testing utilities
  - Mock command creation
  - Command execution verification
  - Argument validation
  - Test-only execution mode
  - Dependency validation

- **`grant_permissions.py`**: Permission management utility
  - Role-based access control management
  - Permission assignment to users and roles
  - Permission delegation with expiration
  - Permission verification and validation
  - Audit logging of permission changes
  - Export/import of permission configurations

- **`security_admin.py`**: Security administration commands
  - Security policy configuration
  - Authentication settings management
  - Security log review and export
  - Security control verification
  - Compliance monitoring capabilities

- **`system_configuration.py`**: System configuration management
  - Environment configuration settings
  - Configuration value validation against schemas
  - Configuration export and import functionality
  - Default configuration initialization
  - Secure handling of sensitive configuration values
  - Comprehensive audit logging of configuration changes

- **`user_admin.py`**: User account management
  - User creation, modification, and deletion
  - Bulk user operations and import/export
  - Password management and reset
  - MFA requirement management
  - User locking and unlocking
  - User permission and role assignment
  - Structured data import with validation

## Directory Structure

```plaintext
admin/cli/
├── README.md                # This documentation
├── __init__.py              # Package initialization and shared utilities
├── admin_commands.py        # Core command registry and framework
├── auth.py                  # Authentication utilities
├── base_command.py          # Base class for command handlers
├── command_tester.py        # Testing utilities for commands
├── commands/                # Command implementations
│   ├── __init__.py          # Command package initialization
│   └── system_commands.py   # System command implementations
├── grant_permissions.py     # Permission management utility
├── security_admin.py        # Security administration commands
├── system_configuration.py  # System configuration management
└── user_admin.py            # User account management
```

## Usage

### Core Command Framework

```bash
# Get help on available commands
python admin_commands.py --help

# Run a command with verbose output
python admin_commands.py --command system-status --verbose

# Export command output to JSON
python admin_commands.py --command list-users --output json > users.json

# Check command dependencies
python admin_commands.py --command system-status --check-dependencies
```

### User Administration

```bash
# Create a new user
python user_admin.py create --username jsmith --email john.smith@example.com --roles user,developer

# List all users with a specific role
python user_admin.py list --role admin --output-format table

# Reset user password
python user_admin.py reset-password --username jsmith --send-email

# Lock a user account
python user_admin.py lock --username jsmith --reason "Security policy violation" --duration 24h

# Export user data to CSV
python user_admin.py export --role operator --output users.csv
```

### User Import

```bash
# Import users from a CSV file
python user_admin.py import --file users.csv --reason "Onboarding new department"

# Import users from a JSON file
python user_admin.py import --file users.json --reason "System migration"

# Perform a dry run to validate import data without making changes
python user_admin.py import --file users.csv --dry-run --reason "Validation only"

# Import with specific format if auto-detection fails
python user_admin.py import --file users.txt --format csv --reason "Custom format file"
```

### Permission Management

```bash
# Grant a permission to a user
python grant_permissions.py grant --user jsmith --permission "api:read" --reason "Project access requirement"

# Grant temporary permissions with expiration
python grant_permissions.py grant --user jsmith --permission "system:write" --expires "2023-07-15T18:00:00" --reason "Deployment window"

# Revoke a permission
python grant_permissions.py revoke --user jsmith --permission "api:write" --reason "No longer required"

# List all permissions for a user
python grant_permissions.py list --user jsmith --output-format json
```

### System Configuration

```bash
# Get current system configuration
python system_configuration.py --show

# Get a specific configuration value
python system_configuration.py --get "security.session.timeout"

# Update configuration settings
python system_configuration.py --set security.session.timeout=30 --set security.login.max_attempts=5

# Export configuration to a file
python system_configuration.py --export --output config_backup.json

# Import configuration from a file
python system_configuration.py --import config_backup.json --environment staging

# Validate configuration against schemas
python system_configuration.py --validate --schema-dir /etc/cloud-platform/schemas

# Initialize default configurations
python system_configuration.py --init-defaults
```

### Security Administration

```bash
# Check security compliance status
python security_admin.py compliance-check

# Enable enhanced security controls
python security_admin.py security-posture --level enhanced

# Generate security report
python security_admin.py generate-report --format pdf --output security_report.pdf

# Review failed login attempts
python security_admin.py audit --event login_failed --days 7
```

### Commands Testing

```bash
# Run in test mode without executing actual commands
python admin_commands.py --command user-status --test-mode

# Dump test results to a file for verification
python admin_commands.py --command user-status --test-mode --dump-test-results test_output.json

# Use the command tester in Python scripts
python -c "from admin.cli import CommandTester; tester = CommandTester(); tester.execute('user-status'); print(tester.verify_command_called('user-status'))"
```

### Command Dependencies

```bash
# Check if all command dependencies are satisfied
python admin_commands.py --command deploy-system --check-dependencies

# Execute a command with all its dependencies
python admin_commands.py --command full-backup --verbose
```

## Best Practices & Security

- **Authentication**: Always authenticate with appropriate credentials before executing commands
- **Audit Trail**: All operations are logged for audit purposes
- **Batch Operations**: Use caution with batch operations to avoid unintended changes
- **Configuration Management**: Back up configurations before making system-wide changes
- **Data Validation**: Always validate import data before performing bulk operations
- **Least Privilege**: Run commands with the minimum required permissions
- **Multi-factor Authentication**: Enable MFA for administrative access
- **Parameter Validation**: Validate all input parameters before execution
- **Permission Review**: Regularly review temporary permission grants
- **Secure Connections**: Use secure connections for remote administration
- **Timeout Controls**: Implement session timeouts for administrative sessions
- **Reason Documentation**: Always provide meaningful reasons for security-relevant operations
- **Emergency Access**: Follow proper procedures for emergency access scenarios
- **Dry Runs**: Use dry-run options for bulk operations to verify expected changes
- **Testing**: Use command testing facilities to validate command behavior before production use
- **Dependency Management**: Be aware of command dependencies and their implications

## Common Features

All CLI tools share these common features:

- **Consistent Command Structure**: Standard command format across all tools
- **Data Import/Export**: Support for importing and exporting data in multiple formats
- **Dry Run Mode**: Preview changes without applying them for bulk operations
- **Error Handling**: Comprehensive error handling with clear messages
- **Flexible Output Formats**: Support for multiple output formats (text, JSON, CSV, table)
- **Help System**: Built-in documentation and examples
- **Input Validation**: Thorough validation of all command parameters
- **Logging**: Comprehensive logging of all operations with appropriate detail
- **Multi-Environment Support**: Support for different environments (development, staging, production)
- **Permission Checks**: Pre-execution permission verification
- **Rate Limiting**: Protection against command abuse
- **Return Codes**: Standardized return codes for scripting integration
- **MFA Integration**: Support for multi-factor authentication on sensitive operations
- **Audit Integration**: Detailed audit logging for accountability
- **Reason Tracking**: Required documentation of reasons for security-relevant changes
- **Command Testing**: Built-in testing facilities for command validation
- **Dependency Management**: Support for command dependencies and validation

## Related Documentation

- Administrative API
- Security Administration Tools
- System Configuration Guide
- User Management Guide
- Permission Model Reference
- CLI Development Guide
- Administrative Workflows
- Security Controls Framework
- Audit Requirements
- Emergency Access Procedures
- Data Import Format Specifications
- Batch Processing Guidelines
- Command Testing Guide
- Command Dependencies Documentation
- Base Command Development Guide
