# Admin CLI Tools

This directory contains command-line interface tools for administrative tasks in the Cloud Infrastructure Platform. These CLI tools provide administrators with efficient ways to manage users, configure system settings, and perform security operations.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The Admin CLI tools provide command-line interfaces for performing administrative tasks that would otherwise require accessing the web interface. These tools are designed for system administrators who need to perform batch operations, automate routine tasks, or administer the system in environments where the web interface may not be available. The tools implement the same security controls as the web interface, requiring proper authentication and authorization for all operations.

## Key Components

- **`admin_commands.py`**: Core command registry and execution framework
  - Command registration and discovery system
  - Permission verification for all commands
  - Input validation framework
  - Output formatting options
  - Execution logging capabilities

- **`grant_permissions.py`**: Permission management utility
  - Role-based access control management
  - Permission assignment to users and groups
  - Temporary permission grants with expiration
  - Permission verification and validation
  - Audit logging of permission changes

- **`security_admin.py`**: Security administration commands
  - Security policy configuration
  - Authentication settings management
  - Security log review and export
  - Security control verification
  - Compliance monitoring capabilities

- **`system_configuration.py`**: System configuration management
  - Environment configuration settings
  - Service startup and shutdown
  - System parameter tuning
  - Performance optimization settings
  - Resource allocation management

- **`user_admin.py`**: User account management
  - User creation, modification, and deactivation
  - Bulk user operations
  - Password management and reset
  - User group assignment
  - Account lockout management

## Directory Structure

```plaintext
admin/cli/
├── README.md              # This documentation
├── admin_commands.py      # Core command registry and framework
├── grant_permissions.py   # Permission management utility
├── security_admin.py      # Security administration commands
├── system_configuration.py # System configuration management
└── user_admin.py          # User account management
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
```

### User Management

```bash
# Create a new user
python user_admin.py create --username jsmith --email john.smith@example.com --roles user,developer

# Deactivate a user account
python user_admin.py deactivate --username jsmith --reason "Extended leave"

# Reset user password
python user_admin.py reset-password --username jsmith --send-email

# List all users with a specific role
python user_admin.py list --role admin --output-format table
```

### Permission Management

```bash
# Grant a permission to a user
python grant_permissions.py --user jsmith --permission "api:read" --reason "Project access requirement"

# Grant temporary permissions with expiration
python grant_permissions.py --user jsmith --permission "system:write" --expires "2023-07-15T18:00:00" --reason "Deployment window"

# List permissions for a specific user
python grant_permissions.py --list --user jsmith

# Revoke a permission
python grant_permissions.py --user jsmith --permission "api:write" --revoke --reason "No longer required"
```

### System Configuration

```bash
# Get current system configuration
python system_configuration.py --show

# Update a configuration setting
python system_configuration.py --set max_connections=500

# Export configuration to file
python system_configuration.py --export --output config_backup.json

# Import configuration from file
python system_configuration.py --import --input config_backup.json --environment staging
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

## Best Practices & Security

- **Authentication**: Always authenticate with appropriate credentials before executing commands
- **Audit Trail**: All operations are logged for audit purposes
- **Batch Operations**: Use caution with batch operations to avoid unintended changes
- **Configuration Management**: Back up configurations before making system-wide changes
- **Least Privilege**: Run commands with the minimum required permissions
- **Multi-factor Authentication**: Enable MFA for administrative access
- **Parameter Validation**: Validate all input parameters before execution
- **Permission Review**: Regularly review temporary permission grants
- **Secure Connections**: Use secure connections for remote administration
- **Timeout Controls**: Implement session timeouts for administrative sessions

## Common Features

All CLI tools share these common features:

- **Consistent Command Structure**: Standard command format across all tools
- **Error Handling**: Comprehensive error handling with clear messages
- **Flexible Output Formats**: Support for multiple output formats (text, JSON, CSV)
- **Help System**: Built-in documentation and examples
- **Input Validation**: Thorough validation of all command parameters
- **Logging**: Comprehensive logging of all operations with appropriate detail
- **Multi-Environment Support**: Support for different environments (development, staging, production)
- **Permission Checks**: Pre-execution permission verification
- **Rate Limiting**: Protection against command abuse
- **Return Codes**: Standardized return codes for scripting integration

## Related Documentation

- Administrative API
- Security Administration Tools
- System Configuration Guide
- User Management Guide
- Permission Model Reference
- CLI Development Guide
- Administrative Workflows
