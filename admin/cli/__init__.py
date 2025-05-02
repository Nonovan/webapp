"""
Administrative Command-Line Interface Package

This package provides a collection of command-line tools for administrative operations
in the Cloud Infrastructure Platform. These CLI tools enable administrators to manage
users, control permissions, configure system settings, and perform security operations
with proper authentication, authorization, and comprehensive audit logging.

Key components include:
- Core command registration and execution framework
- User account management utilities
- Permission control and delegation
- System configuration management
- Security administration tools

All tools implement consistent command structure, authentication, authorization,
and comprehensive audit logging to ensure secure administration across development,
staging, and production environments.
"""

import logging
import os
import sys
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Callable, Optional, Tuple, Union

# Setup package logging
logger = logging.getLogger(__name__)

# Version information
__version__ = '1.0.0'
__author__ = 'Cloud Infrastructure Platform Team'
__email__ = 'admin-team@example.com'

# Try importing admin CLI components
# These are imported conditionally to allow selective loading based on availability

# User administration
try:
    from .user_admin import (
        create_user,
        update_user,
        get_user,
        list_users,
        delete_user,
        reset_password,
        lock_unlock_user,
        bulk_import_users,
        export_users,
        manage_mfa
    )
    USER_ADMIN_AVAILABLE = True
except ImportError as e:
    logger.debug(f"User administration not available: {e}")
    USER_ADMIN_AVAILABLE = False

# Permission management
try:
    from .grant_permissions import (
        grant_permission,
        revoke_permission,
        check_permission,
        list_permissions,
        delegate_permission,
        get_user_permissions,
        get_role_permissions
    )
    PERMISSION_MANAGEMENT_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Permission management not available: {e}")
    PERMISSION_MANAGEMENT_AVAILABLE = False

# System configuration
try:
    from .system_configuration import (
        list_configs,
        get_config_value,
        set_config_value,
        delete_config_value,
        export_configs,
        import_configs,
        validate_configs,
        initialize_defaults
    )
    SYSTEM_CONFIG_AVAILABLE = True
except ImportError as e:
    logger.debug(f"System configuration not available: {e}")
    SYSTEM_CONFIG_AVAILABLE = False

# Security administration
try:
    from .security_admin import (
        execute_command,
        register_command,
        list_commands,
        authenticate
    )
    SECURITY_ADMIN_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Security administration not available: {e}")
    SECURITY_ADMIN_AVAILABLE = False

# Core command framework
try:
    from .admin_commands import (
        execute_command as execute_admin_command,
        register_command as register_admin_command,
        format_output,
        mask_sensitive_data,
        get_command_help
    )
    ADMIN_COMMANDS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Admin command framework not available: {e}")
    ADMIN_COMMANDS_AVAILABLE = False

# Common command exit codes (used across CLI tools)
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5
EXIT_NOT_FOUND = 6

def get_available_commands() -> Dict[str, bool]:
    """Returns a dictionary of available command modules within this package."""
    return {
        "admin_commands": ADMIN_COMMANDS_AVAILABLE,
        "user_admin": USER_ADMIN_AVAILABLE,
        "grant_permissions": PERMISSION_MANAGEMENT_AVAILABLE,
        "system_configuration": SYSTEM_CONFIG_AVAILABLE,
        "security_admin": SECURITY_ADMIN_AVAILABLE
    }

def initialize_user_import(
    file_path: str,
    file_format: Optional[str] = None,
    required_fields: List[str] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Initialize user import by loading and validating data from a file.

    Processes the specified file (CSV or JSON) and performs basic validation
    to ensure that all required fields are present.

    Args:
        file_path: Path to the import file
        file_format: Format of the file ('csv' or 'json'), can be auto-detected
        required_fields: List of required fields for valid user data

    Returns:
        Tuple containing:
        - List of user data dictionaries from the file
        - Dictionary with stats (total records, invalid records, etc.)

    Raises:
        ValueError: If file has invalid format or missing required fields
        FileNotFoundError: If the specified file does not exist
        IOError: If there's an error reading the file
    """
    if required_fields is None:
        # Default required fields for user data
        required_fields = ['username', 'email']

    stats = {
        'total': 0,
        'invalid_format': 0,
        'missing_fields': 0,
        'valid': 0
    }

    # Check file existence
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Import file not found: {file_path}")

    # Auto-detect format if not specified
    if not file_format:
        if file_path.lower().endswith('.json'):
            file_format = 'json'
        elif file_path.lower().endswith('.csv'):
            file_format = 'csv'
        else:
            raise ValueError("Could not determine file format from extension. Please specify format.")

    # Load the file based on format
    try:
        users_data = []

        if file_format.lower() == 'json':
            with open(file_path, 'r') as f:
                json_data = json.load(f)

                # Handle both array and object formats
                if isinstance(json_data, list):
                    users_data = json_data
                elif isinstance(json_data, dict) and 'users' in json_data:
                    users_data = json_data['users']
                else:
                    users_data = [json_data]  # Single user

        elif file_format.lower() == 'csv':
            with open(file_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                users_data = list(reader)

                # Convert boolean fields
                for user in users_data:
                    for field in ['require_mfa', 'require_password_change']:
                        if field in user and isinstance(user[field], str):
                            user[field] = user[field].lower() in ('true', 'yes', '1', 'y')
        else:
            raise ValueError(f"Unsupported file format: {file_format}. Supported formats are CSV and JSON.")

        # Basic validation
        stats['total'] = len(users_data)
        valid_users = []

        for i, user in enumerate(users_data):
            # Check for required fields
            missing_fields = [field for field in required_fields if field not in user or not user[field]]

            if missing_fields:
                stats['missing_fields'] += 1
                logger.warning(f"Record {i+1}: Missing required fields: {', '.join(missing_fields)}")
                continue

            # Add validated user to result
            valid_users.append(user)
            stats['valid'] += 1

        return valid_users, stats

    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in file: {file_path}")
    except csv.Error as e:
        raise ValueError(f"CSV parsing error: {e}")
    except Exception as e:
        raise IOError(f"Error reading import file: {e}")

def run_command(command_module: str, args: Optional[List[str]] = None) -> int:
    """
    Run a specific admin CLI command with the given arguments.

    Args:
        command_module: Name of the command module to run
        args: List of command-line arguments (default: sys.argv[1:])

    Returns:
        Exit code from the command execution
    """
    if args is None:
        args = sys.argv[1:]

    # Import the appropriate module's main function dynamically
    try:
        if command_module == "user_admin":
            from .user_admin import main
        elif command_module == "grant_permissions":
            from .grant_permissions import main
        elif command_module == "system_configuration":
            from .system_configuration import main
        elif command_module == "security_admin":
            from .security_admin import main
        elif command_module == "admin_commands":
            from .admin_commands import main
        else:
            logger.error(f"Unknown command module: {command_module}")
            return EXIT_ERROR

        # Execute the main function and return its result
        return main(args)
    except ImportError as e:
        logger.error(f"Failed to import {command_module}: {e}")
        return EXIT_ERROR
    except Exception as e:
        logger.exception(f"Error executing {command_module}: {e}")
        return EXIT_ERROR

# Define public exports for this package
__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__email__',

    # Package utilities
    'get_available_commands',
    'run_command',
    'initialize_user_import',

    # Exit codes
    'EXIT_SUCCESS',
    'EXIT_ERROR',
    'EXIT_PERMISSION_ERROR',
    'EXIT_RESOURCE_ERROR',
    'EXIT_VALIDATION_ERROR',
    'EXIT_AUTHENTICATION_ERROR',
    'EXIT_NOT_FOUND'
]

# Add available functionality to exports
if USER_ADMIN_AVAILABLE:
    __all__.extend([
        'create_user',
        'update_user',
        'get_user',
        'list_users',
        'delete_user',
        'reset_password',
        'lock_unlock_user',
        'bulk_import_users',
        'export_users',
        'manage_mfa'
    ])

if PERMISSION_MANAGEMENT_AVAILABLE:
    __all__.extend([
        'grant_permission',
        'revoke_permission',
        'check_permission',
        'list_permissions',
        'delegate_permission',
        'get_user_permissions',
        'get_role_permissions'
    ])

if SYSTEM_CONFIG_AVAILABLE:
    __all__.extend([
        'list_configs',
        'get_config_value',
        'set_config_value',
        'delete_config_value',
        'export_configs',
        'import_configs',
        'validate_configs',
        'initialize_defaults'
    ])

if SECURITY_ADMIN_AVAILABLE:
    __all__.extend([
        'execute_command',
        'register_command',
        'list_commands',
        'authenticate'
    ])

if ADMIN_COMMANDS_AVAILABLE:
    __all__.extend([
        'execute_admin_command',
        'register_admin_command',
        'format_output',
        'mask_sensitive_data',
        'get_command_help'
    ])

# Log initialization status
logger.debug(f"Admin CLI package initialized with: {', '.join([k for k, v in get_available_commands().items() if v])}")
