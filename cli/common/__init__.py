"""
Common utilities for the Cloud Infrastructure Platform CLI.

This package provides shared functionality used across CLI commands including
authentication, configuration management, error handling, input validation,
logging, and progress reporting. These utilities ensure consistent behavior
and standardized patterns across all CLI commands.

The common utilities implement core functionality shared across different
command groups and CLI applications. They abstract common operations and
provide reusable implementations that follow platform security standards,
reducing code duplication and ensuring consistent user experience.
"""

from .utils import (
    # Authentication and authorization
    require_auth,
    require_permission,
    is_authenticated,
    has_permission,
    get_auth_token_path,

    # Configuration management
    load_config,
    save_config,
    get_config_value,
    get_current_environment,
    set_current_environment,

    # Error handling
    handle_error,

    # Logging
    configure_logging,

    # Output formatting
    format_output,

    # Progress reporting
    create_progress_bar,

    # Input validation and prompting
    validate_input,
    prompt_with_validation,
    confirm_action,

    # API client
    get_api_client,

    # Exit codes
    EXIT_SUCCESS,
    EXIT_ERROR,
    EXIT_AUTH_ERROR,
    EXIT_PERMISSION_ERROR,
    EXIT_VALIDATION_ERROR,
    EXIT_RESOURCE_ERROR,

    # Version information
    print_version
)

# Import security utilities
from .security import (
    # Path safety
    is_within_directory,
    sanitize_path,
    is_safe_file_operation,

    # Command execution safety
    safe_execute_command,
    verify_cli_environment,

    # File integrity
    verify_file_signature,
    calculate_file_hash,
    verify_script_integrity,

    # Resource management
    get_safe_config_dir,
    secure_resource_cleanup,

    # Permission validation
    validate_file_permissions,

    # Secure temporary directory
    create_secure_tempdir,

    # Data protection
    protect_sensitive_data,

    # Security constants
    CLI_SECURITY_CONSTANTS
)

# Version information
__version__ = '0.1.1'

# Export symbols for package-level imports
__all__ = [
    # Authentication and authorization
    'require_auth',
    'require_permission',
    'is_authenticated',
    'has_permission',
    'get_auth_token_path',

    # Configuration management
    'load_config',
    'save_config',
    'get_config_value',
    'get_current_environment',
    'set_current_environment',

    # Error handling
    'handle_error',

    # Logging
    'configure_logging',

    # Output formatting
    'format_output',

    # Progress reporting
    'create_progress_bar',

    # Input validation and prompting
    'validate_input',
    'prompt_with_validation',
    'confirm_action',

    # API client
    'get_api_client',

    # Path and filesystem security
    'is_within_directory',
    'sanitize_path',
    'is_safe_file_operation',

    # Command execution safety
    'safe_execute_command',
    'verify_cli_environment',

    # File integrity
    'verify_file_signature',
    'calculate_file_hash',
    'verify_script_integrity',

    # Resource management
    'get_safe_config_dir',
    'secure_resource_cleanup',

    # Permission validation
    'validate_file_permissions',

    # Secure temporary directory
    'create_secure_tempdir',

    # Data protection
    'protect_sensitive_data',

    # Security constants
    'CLI_SECURITY_CONSTANTS',

    # Exit codes
    'EXIT_SUCCESS',
    'EXIT_ERROR',
    'EXIT_AUTH_ERROR',
    'EXIT_PERMISSION_ERROR',
    'EXIT_VALIDATION_ERROR',
    'EXIT_RESOURCE_ERROR',

    # Version information
    'print_version'
]
