# CLI Package

This package provides command-line interfaces for the Cloud Infrastructure Platform, implementing application management, database operations, infrastructure deployment, and system administration capabilities.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
- [Authentication](#authentication)
- [Security Features](#security-features)
- [Common Patterns](#common-patterns)
- [Related Documentation](#related-documentation)

## Overview

The CLI package delivers a comprehensive set of command-line tools for managing all aspects of the Cloud Infrastructure Platform. Built on Flask's CLI functionality with Click, it provides a consistent interface for database management, user administration, system operations, and multi-cloud deployments. The CLI implements proper authentication, authorization, comprehensive logging, and thorough validation across all operations to ensure secure and reliable command execution in all environments.

## Key Components

- **`__init__.py`**: Package initialization and command registration
  - Command discovery and registration
  - Global CLI configuration
  - Integration with Flask application
  - Version information and tracking
  - Core CLI functionality exports

- **`cli_constants.py`**: Centralized constants for CLI operations
  - Environment definitions
  - Exit code standards
  - File and directory paths
  - Security configuration
  - Format standards
  - Command group naming
  - Default configuration values
  - Version information

- **`app/`**: Core application management commands
  - Command group organization
  - Database management operations
  - Monitoring and metrics commands
  - System administration utilities
  - User management functionality
  - Security baseline management
  - Maintenance operations
  - File integrity monitoring

- **`common/`**: Shared CLI utilities and helpers
  - Authentication functionality
  - Configuration management
  - Error handling patterns
  - Input validation utilities
  - Progress reporting components
  - Path safety validation
  - File integrity verification
  - Secure command execution
  - Environment verification
  - Resource cleanup utilities

- **`deploy/`**: Infrastructure deployment commands
  - AWS deployment operations
  - Azure resource management
  - Docker container operations
  - GCP integration commands
  - Kubernetes deployment utilities
  - Provider-agnostic deployment tools
  - Infrastructure status monitoring
  - Deployment verification and rollback

## Directory Structure

```plaintext
cli/
├── README.md                # This documentation
├── __init__.py              # Package initialization
├── cli_constants.py         # Centralized CLI constants
├── app/                     # Application management commands
│   ├── README.md            # Application CLI documentation
│   ├── __init__.py          # Application CLI initialization
│   ├── config.py            # Configuration utilities
│   ├── utils.py             # App-specific utilities
│   └── commands/            # Command group implementations
│       ├── README.md        # Command documentation
│       ├── __init__.py      # Command registration
│       ├── db.py            # Database management commands
│       ├── maintenance.py   # System maintenance commands
│       ├── monitor.py       # Monitoring commands
│       ├── security.py      # Security management commands
│       ├── system.py        # System administration commands
│       └── user.py          # User management commands
├── common/                  # Shared CLI functionality
│   ├── README.md            # Common utilities documentation
│   ├── __init__.py          # Common utilities initialization
│   ├── security.py          # Security utility functions
│   └── utils.py             # Core utility functions
└── deploy/                  # Infrastructure deployment
    ├── README.md            # Deployment CLI documentation
    ├── __init__.py          # Deployment CLI initialization
    ├── aws.py               # AWS deployment commands
    ├── azure.py             # Azure deployment commands
    ├── docker.py            # Docker container operations
    ├── gcp.py               # GCP deployment commands
    ├── general.py           # Provider-agnostic commands
    └── kubernetes.py        # Kubernetes deployment commands
```

## Usage

The CLI is accessed through the Flask CLI interface:

```bash
# Get help on available commands
flask --help

# Get help for specific command groups
flask deploy --help
flask db --help
flask user --help
flask security --help
flask maintenance --help

# Execute commands with appropriate options
flask <command-group> <command> [options]
```

### Application Management Commands

```bash
# Database operations
flask db init --env development
flask db migrate --message "Add user preferences"
flask db backup --compress

# User management
flask user create --username admin --email admin@example.com --role admin
flask user list --role operator
flask user reset-password username

# System operations
flask system status
flask system health --detailed
flask system config --verify

# Security operations
flask security check-baseline --verbose
flask security update-baseline --auto
flask security events --days 7 --severity critical
flask security list-monitored --format json

# Maintenance operations
flask maintenance cache-clear --type all
flask maintenance logs-rotate --compress --max-age 90
flask maintenance cleanup --older-than 30 --type logs
```

### Deployment Commands

```bash
# AWS deployments
flask deploy aws deploy --env production --region us-west-2
flask deploy aws status --env production

# Azure deployments
flask deploy azure deploy --env production --resource-group my-group
flask deploy azure teardown --env staging

# Docker operations
flask deploy docker build --env production --tag v1.2.3
flask deploy docker compose --env development --action up

# Kubernetes deployments
flask deploy k8s deploy --env production --namespace platform
flask deploy k8s status --env production
```

### Initialization Commands

```bash
# Initialize project components
flask init config --env development
flask init db --env development --seed
flask init security --baseline
flask init project --env development --with-db --with-config
```

## Authentication

The CLI supports multiple authentication methods:

1. **Environment-based Authentication**:

   ```bash
   # Set authentication variables for CLI session
   export PLATFORM_API_KEY="your-api-key"
   flask system status
   ```

2. **Interactive Login**:

   ```bash
   # Authenticate for an interactive session
   flask auth login
   # Enter credentials when prompted
   ```

3. **Command-specific Authentication**:

   ```bash
   # Pass authentication with command
   flask user list --key-file /path/to/key.json
   ```

4. **Configuration-based Authentication**:

   ```bash
   # Configure default authentication once
   flask config set-auth --key-file /path/to/key.json
   # Then run commands without authentication parameters
   flask system health
   ```

## Security Features

- **Access Control**: Commands validate appropriate permissions before execution
- **Audit Logging**: All operations are logged for accountability
- **Configuration Validation**: Pre-execution validation of parameters and configurations
- **Credential Handling**: Secure handling of authentication credentials
- **Environment Awareness**: Different security controls per environment
- **Error Handling**: Secure error messages that don't leak sensitive information
- **File Integrity Monitoring**: Verification of critical file integrity against baselines
- **Input Validation**: Thorough validation of all command inputs
- **Path Safety**: Prevention of directory traversal vulnerabilities
- **Resource Protection**: Proper cleanup of resources after errors
- **Safe Defaults**: Conservative default settings for all operations
- **Secure Command Execution**: Validation of commands to prevent injection attacks
- **Secure Resource Cleanup**: Safe removal of temporary files and resources
- **Transaction Management**: Proper transaction handling for database operations

## Common Patterns

### Command Structure

```python
@command_group.command('name')
@click.option('--option', help='Description')
@require_permission('required:permission')
def command_name(option):
    """Command documentation string."""
    try:
        # Command implementation
        with click.progressbar(length=steps, label='Operation') as bar:
            # Execute steps with progress updates
            bar.update(1)

        # Success message
        logger.info('Operation completed successfully: %s', details)
        click.echo('Success message')

        return EXIT_SUCCESS

    except Exception as e:
        # Proper error handling
        logger.error('Operation failed: %s', e)
        # Cleanup if necessary
        raise click.ClickException(str(e))
```

### Error Handling

```python
try:
    # Operation that might fail
    result = perform_operation(args)

    # Handle expected failure conditions
    if not result.success:
        if result.reason == 'permission_denied':
            logger.error("Permission denied: %s", result.details)
            return EXIT_PERMISSION_ERROR
        elif result.reason == 'resource_not_found':
            logger.error("Resource not found: %s", result.details)
            return EXIT_RESOURCE_ERROR
        else:
            logger.error("Operation failed: %s", result.details)
            return EXIT_ERROR

    return EXIT_SUCCESS

except ConnectionError as e:
    logger.error("Connection error: %s", e)
    return EXIT_CONNECTIVITY_ERROR
except TimeoutError as e:
    logger.error("Operation timed out: %s", e)
    return EXIT_TIMEOUT_ERROR
except Exception as e:
    logger.error("Unexpected error: %s", e)
    return EXIT_ERROR
```

### Authentication Check

```python
def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            logger.error("Authentication required")
            raise click.ClickException("Authentication required")
        return f(*args, **kwargs)
    return decorated
```

### Permission Verification

```python
def require_permission(permission_name):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not has_permission(permission_name):
                logger.error("Permission denied: %s required", permission_name)
                raise click.ClickException(f"Permission denied: {permission_name} required")
            return f(*args, **kwargs)
        return decorated
    return decorator
```

### Confirmation Prompts

```python
if destructive_operation and not force:
    if not confirm_action("This operation will delete data. Continue?", default=False):
        click.echo("Operation cancelled")
        return EXIT_SUCCESS
```

### Path Safety Validation

```python
# Validate path is safe before file operations
if not is_safe_file_operation('write', user_specified_path):
    logger.error("Unsafe file path specified: %s", user_specified_path)
    return EXIT_PERMISSION_ERROR
```

## Related Documentation

- Application CLI Documentation
- CLI Architecture Guide
- Cloud Provider Documentation
- Command Development Guide
- Deployment Architecture
- Environment Configuration
- File Integrity Monitoring Guide
- Flask CLI Integration
- Permission Model Reference
- Security Baseline Management
- Security Controls Documentation
- System Administration Guide
- User Authentication Guide
- User Management Documentation
