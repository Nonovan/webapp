# Common CLI Utilities

This directory contains shared utility functions and common components used by the command-line interface tools of the Cloud Infrastructure Platform. These utilities provide consistent functionality for authentication, logging, configuration management, error handling, file integrity validation, and security across CLI commands.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage Examples](#usage-examples)
  - [Authentication](#authentication)
  - [Configuration Management](#configuration-management)
  - [Error Handling](#error-handling)
  - [Progress Reporting](#progress-reporting)
  - [Input Validation](#input-validation)
  - [Output Formatting](#output-formatting)
  - [Path Safety Validation](#path-safety-validation)
  - [File Integrity Verification](#file-integrity-verification)
  - [Secure Command Execution](#secure-command-execution)
  - [Environment Verification](#environment-verification)
  - [Secure Resource Management](#secure-resource-management)
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

- **`security.py`**: Security utility functions
  - Path safety validation
  - File integrity verification
  - Command execution safety
  - Environment verification
  - Secure resource cleanup
  - Script integrity verification

## Directory Structure

```plaintext
cli/common/
├── README.md      # This documentation
├── __init__.py    # Package initialization and exports
├── security.py    # Security utility functions
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

### Path Safety Validation

```python
from cli.common import is_within_directory, sanitize_path, is_safe_file_operation

def process_user_file(file_path):
    """Process a user-provided file with path safety checks."""
    # Define allowed base directories for file operations
    safe_dirs = ['/app/uploads', '/app/temp']

    # Sanitize and validate the provided path
    try:
        safe_path = sanitize_path(file_path)
    except ValueError as e:
        click.echo(f"Path validation failed: {e}")
        return EXIT_VALIDATION_ERROR

    # Verify path is within allowed directories
    if not is_within_directory(safe_path, safe_dirs):
        click.echo(f"Path {safe_path} is outside of allowed directories")
        return EXIT_PERMISSION_ERROR

    # Verify specific operation is safe
    if not is_safe_file_operation('read', safe_path, safe_dirs):
        click.echo(f"Reading from {safe_path} is not permitted")
        return EXIT_PERMISSION_ERROR

    # Proceed with operation if checks pass
    with open(safe_path, 'r') as f:
        contents = f.read()

    click.echo(f"File processed successfully: {len(contents)} bytes read")
    return EXIT_SUCCESS
```

### File Integrity Verification

```python
from cli.common import calculate_file_hash, verify_file_signature, verify_script_integrity

def check_config_integrity(config_path):
    """Verify the integrity of a configuration file."""
    # Calculate the current hash of the file
    current_hash = calculate_file_hash(config_path)
    click.echo(f"Current file hash: {current_hash}")

    # Check if file has been modified from baseline
    baseline_hash = "a1b2c3d4e5f6..." # Stored securely elsewhere
    if verify_script_integrity(config_path, baseline_hash)[0]:
        click.echo("Configuration file integrity verified")
    else:
        click.echo("Warning: Configuration file may have been modified")

    # For files with detached signatures
    signature_path = f"{config_path}.sig"
    if os.path.exists(signature_path):
        is_valid = verify_file_signature(config_path, signature_path)
        result = "verified" if is_valid else "failed verification"
        click.echo(f"Digital signature {result}")
```

### Secure Command Execution

```python
from cli.common import safe_execute_command

def run_security_scan():
    """Run an external security scanning tool with safety controls."""
    # Define command with proper argument separation (no shell)
    command = [
        'security-scanner',
        '--scan-type', 'quick',
        '--output', 'json',
        '--no-colors'
    ]

    # Execute with security controls
    returncode, stdout, stderr = safe_execute_command(
        command,
        timeout=300,  # 5 minute timeout
        safe_env=True  # Use sanitized environment
    )

    # Process result
    if returncode == 0:
        try:
            results = json.loads(stdout)
            click.echo(f"Scan completed with {len(results['findings'])} findings")
        except json.JSONDecodeError:
            click.echo("Error parsing scanner output")
            return EXIT_ERROR
    else:
        click.echo(f"Scan failed: {stderr}")
        return EXIT_ERROR

    return EXIT_SUCCESS
```

### Environment Verification

```python
from cli.common import verify_cli_environment

def setup_command():
    """Initialize with environment security verification."""
    # Check CLI environment security
    is_safe, issues = verify_cli_environment()

    if not is_safe:
        click.echo("Security issues detected in the CLI environment:")
        for issue in issues:
            click.echo(f" - {issue}")

        # For critical issues, abort
        if any("world-writable" in issue for issue in issues):
            click.echo("Aborting due to critical security concerns")
            return EXIT_PERMISSION_ERROR

        # For warnings, proceed with notice
        click.echo("Proceeding despite warnings - review issues above")

    # Continue with environment setup
    click.echo("Environment verified, proceeding with setup")
```

### Secure Resource Management

```python
from cli.common import get_safe_config_dir, secure_resource_cleanup

def backup_command():
    """Create a backup with secure resource management."""
    # Get secure directory for output
    config_dir = get_safe_config_dir()
    backup_path = os.path.join(config_dir, f"backup-{int(time.time())}.zip")

    temp_files = []
    try:
        # Create temporary working files
        temp_dir = tempfile.mkdtemp()
        temp_files.append(temp_dir)

        # Create backup archive
        # ...backup implementation...

        # Move to final location
        shutil.move(temp_backup_path, backup_path)

        click.echo(f"Backup created at {backup_path}")

    except Exception as e:
        click.echo(f"Backup failed: {e}")
        return EXIT_ERROR
    finally:
        # Clean up resources securely
        failed_cleanups = secure_resource_cleanup(temp_files)
        if failed_cleanups:
            click.echo(f"Warning: Failed to clean up {len(failed_cleanups)} resources")

    return EXIT_SUCCESS
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
- **Path Safety**: Prevention of directory traversal vulnerabilities
- **Command Execution**: Secure execution patterns for external commands
- **File Integrity**: Verification of critical script and configuration integrity
- **Environment Verification**: Detection of suspicious environment conditions
- **Atomic Operations**: Safe and atomic file operations to prevent corruption
- **Resource Cleanup**: Secure cleanup of temporary resources

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

### Path Safety Validation Prompt

```python
def ensure_safe_operation(file_path, operation_type):
    """Validate and ensure path safety for file operations."""
    # Define safe directories
    safe_dirs = [os.getcwd(), '/app/data', '/app/config']

    # Normalize and validate path
    abs_path = os.path.abspath(os.path.normpath(file_path))

    # Check if path is within allowed directories
    if not is_within_directory(abs_path, safe_dirs):
        click.echo(f"Security error: Path {file_path} is outside allowed directories")
        return False

    # Validate specific operation type
    if operation_type == 'write':
        if os.path.exists(abs_path) and not os.access(abs_path, os.W_OK):
            click.echo(f"Permission error: Cannot write to {file_path}")
            return False

    return True
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
- File Integrity Monitoring Guide
- File Path Safety Guide
- Command Execution Security
- Resource Management Guidelines
- CLI Environment Security
