# Common CLI Utilities

This directory contains shared utility functions and common components used by the command-line interface tools of the Cloud Infrastructure Platform. These utilities provide consistent functionality for authentication, logging, configuration management, and error handling across CLI commands.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
- [Security Features](#security-features)
- [Common Patterns](#common-patterns)
- [Related Documentation](#related-documentation)

## Overview

The common CLI utilities implement core functionality shared across different command groups and CLI applications. These utilities ensure consistent behavior, standardized error handling, proper authentication, and logging across all CLI commands. They abstract common operations and provide reusable implementations that follow platform security standards, reducing code duplication and ensuring consistent user experience.

## Key Components

- **`__init__.py`**: Package initialization and exports
  - Module documentation
  - Public interface definition
  - Type hints and annotations
  - Version information
  - Package configuration

- **`utils.py`**: Core utility functions
  - Authentication helpers
  - CLI formatting utilities
  - Configuration management
  - Error handling patterns
  - Input validation
  - Logging configuration
  - Output formatting helpers
  - Progress reporting
  - Resource management

## Directory Structure

```plaintext
cli/common/
├── README.md      # This documentation
├── __init__.py    # Package initialization and exports
└── utils.py       # Core utility functions
```

## Usage Examples

### Authentication

```python
from cli.common import require_auth, is_authenticated

@require_auth
def command_requiring_auth():
    """Command that requires authentication."""
    click.echo("Authenticated operation")
    return 0

# Or use the direct check
def another_command():
    # Check if authenticated
    if not is_authenticated():
        click.echo("Authentication required")
        return 1

    # Proceed with authenticated operation
    click.echo("Authenticated operation")
    return 0
```

### Configuration Management

```python
from cli.common import load_config, save_config, get_config_value

def configure_command(key, value):
    """Update configuration setting."""
    # Load current configuration
    config = load_config()

    # Update configuration
    config[key] = value

    # Save updated configuration
    save_config(config)
    click.echo(f"Configuration updated: {key}={value}")

# Get environment-specific configuration
api_url = get_config_value('api_url', default='http://localhost:5000/api',
                          environment='development')
```

### Error Handling

```python
from cli.common import handle_error, EXIT_ERROR

@click.command()
def operation_with_error_handling():
    """Command with standardized error handling."""
    try:
        # Operation that might fail
        perform_operation()
        click.echo("Operation completed successfully!")

    except Exception as e:
        # Standardized error handling
        handle_error(e, "Failed to complete operation")
        return EXIT_ERROR

    return 0
```

### Progress Reporting

```python
from cli.common import create_progress_bar

def long_running_operation():
    """Operation with progress reporting."""
    total_steps = 5
    with create_progress_bar(total_steps, "Processing") as progress:
        # Step 1: Initialize
        perform_initialization()
        progress.update(1)

        # Step 2: Process data
        process_data()
        progress.update(1)

        # Additional steps...

    click.echo("Operation completed")
```

### Input Validation

```python
from cli.common import validate_input, prompt_with_validation

def command_with_validation(parameter):
    # Validate input
    is_valid, error = validate_input(parameter, {
        'required': True,
        'min_length': 3,
        'pattern': r'^[a-zA-Z0-9_-]+$',
        'pattern_message': 'Must contain only alphanumeric characters, underscores, and hyphens'
    })

    if not is_valid:
        click.echo(f"Invalid parameter: {error}")
        return 1

    # Or use validation with prompt
    name = prompt_with_validation(
        "Enter resource name",
        {
            'required': True,
            'min_length': 3,
            'max_length': 50,
            'pattern': r'^[a-zA-Z0-9_-]+$'
        }
    )
```

### Output Formatting

```python
from cli.common import format_output

def get_data_command(format_type='text'):
    # Get data
    data = [
        {'id': 1, 'name': 'Resource 1', 'status': 'active'},
        {'id': 2, 'name': 'Resource 2', 'status': 'inactive'},
    ]

    # Format output based on user preference
    formatted_output = format_output(data, format_type)
    click.echo(formatted_output)
```

## Security Features

- **Authentication Integration**: Standardized authentication handling
- **Configuration Security**: Secure handling of configuration files and values
- **Credential Protection**: Proper handling of sensitive credentials
- **Environment Awareness**: Different security controls per environment
- **Input Validation**: Thorough validation of all command parameters
- **Logging Controls**: Secure logging that protects sensitive data
- **Permission Verification**: Standardized permission checking
- **Resource Protection**: Safe resource handling and cleanup
- **Secure Defaults**: Conservative security defaults throughout
- **Token Management**: Secure handling of authentication tokens

## Common Patterns

### Authentication Check

```python
def require_auth(func):
    """Decorator to require authentication for a command."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Check if user is authenticated
        if not is_authenticated():
            click.echo("Authentication required")
            click.echo("Please login using: flask auth login")
            return EXIT_AUTH_ERROR
        return func(*args, **kwargs)
    return wrapper
```

### Configuration Access

```python
def get_config_value(key, default=None, environment=None):
    """Get configuration value with fallbacks and environment support."""
    # Try environment-specific configuration first
    if environment:
        env_config = load_config(environment)
        if key in env_config:
            return env_config[key]

    # Try global configuration
    config = load_config()

    # Try dot notation (e.g., environments.development.api_url)
    if '.' in key:
        parts = key.split('.')
        value = config
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    return config.get(key, default)
```

### Standardized Exit Codes

```python
# Exit code constants
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_AUTH_ERROR = 2
EXIT_PERMISSION_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_RESOURCE_ERROR = 5

def command_with_exit_codes():
    """Command using standardized exit codes."""
    try:
        # Operation that might fail
        result = perform_operation()

        # Check result success
        if not result.success:
            if result.error_type == "validation":
                click.echo(f"Validation error: {result.message}")
                return EXIT_VALIDATION_ERROR
            elif result.error_type == "permission":
                click.echo(f"Permission error: {result.message}")
                return EXIT_PERMISSION_ERROR

        return EXIT_SUCCESS

    except Exception as e:
        click.echo(f"Operation failed: {str(e)}")
        return EXIT_ERROR
```

### Confirmation Prompt

```python
def dangerous_operation():
    """Command that performs a dangerous operation."""
    if not confirm_action("This will permanently delete resources. Continue?",
                         default=False):
        click.echo("Operation cancelled")
        return EXIT_SUCCESS

    # Proceed with dangerous operation
    click.echo("Performing operation...")
    # Implementation...

    return EXIT_SUCCESS
```

## Related Documentation

- CLI Architecture Guide
- CLI Command Development Guide
- Command Line Interface Best Practices
- Configuration Management Guide
- Error Handling Standards
- Flask-Click Integration Guide
- Security Controls Documentation
- User Authentication Guide
