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

# Base command class
try:
    from .base_command import BaseCommand
    BASE_COMMAND_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Base command class not available: {e}")
    BASE_COMMAND_AVAILABLE = False

# Command tester
try:
    from .command_tester import (
        CommandTester,
        mock_command,
        verify_command_called,
        verify_command_args,
        verify_command_permissions
    )
    COMMAND_TESTER_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Command tester not available: {e}")
    COMMAND_TESTER_AVAILABLE = False

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
        merge_configs,
        initialize_defaults
    )
    SYSTEM_CONFIG_AVAILABLE = True
except ImportError as e:
    logger.debug(f"System configuration not available: {e}")
    SYSTEM_CONFIG_AVAILABLE = False

# Security administration
try:
    from .security_admin import (
        execute_command as execute_security_command,
        register_command as register_security_command,
        list_commands as list_security_commands,
        authenticate as security_authenticate
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
        add_command_dependency,
        validate_dependencies,
        format_output,
        mask_sensitive_data,
        get_command_help,
        list_commands,
        enable_test_mode,
        disable_test_mode,
        get_test_results,
        clear_test_results,
        authenticate,
        CommandError,
        ValidationError,
        PermissionError,
        AuthenticationError,
        DependencyError
    )
    ADMIN_COMMANDS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"Admin command framework not available: {e}")
    ADMIN_COMMANDS_AVAILABLE = False

# System commands
try:
    from .commands.system_commands import (
        HelpCommand,
        ListCategoriesCommand,
        VersionCommand,
        CheckPermissionsCommand
    )
    SYSTEM_COMMANDS_AVAILABLE = True
except ImportError as e:
    logger.debug(f"System commands not available: {e}")
    SYSTEM_COMMANDS_AVAILABLE = False

# Common command exit codes (used across CLI tools)
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION_ERROR = 2
EXIT_RESOURCE_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_AUTHENTICATION_ERROR = 5
EXIT_NOT_FOUND = 6
EXIT_DEPENDENCY_ERROR = 7
EXIT_OPERATION_CANCELLED = 8
EXIT_TEST_MODE = 100  # Special exit code for test mode


def get_available_commands() -> Dict[str, bool]:
    """Returns a dictionary of available command modules within this package."""
    return {
        "admin_commands": ADMIN_COMMANDS_AVAILABLE,
        "user_admin": USER_ADMIN_AVAILABLE,
        "grant_permissions": PERMISSION_MANAGEMENT_AVAILABLE,
        "system_configuration": SYSTEM_CONFIG_AVAILABLE,
        "security_admin": SECURITY_ADMIN_AVAILABLE,
        "system_commands": SYSTEM_COMMANDS_AVAILABLE,
        "base_command": BASE_COMMAND_AVAILABLE,
        "command_tester": COMMAND_TESTER_AVAILABLE
    }


def initialize_user_import(
    file_path: str,
    file_format: Optional[str] = None,
    required_fields: List[str] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Initialize user import from a file.

    Args:
        file_path: Path to the import file
        file_format: Format of the import file (json or csv, auto-detected if None)
        required_fields: List of fields that must be present in the import data

    Returns:
        Tuple of (user_data, stats)
    """
    if required_fields is None:
        required_fields = ["username", "email"]

    stats = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "errors": []
    }

    if not os.path.exists(file_path):
        stats["errors"].append(f"File not found: {file_path}")
        return [], stats

    # Auto-detect format if not specified
    if file_format is None:
        if file_path.endswith('.json'):
            file_format = 'json'
        elif file_path.endswith('.csv'):
            file_format = 'csv'
        else:
            stats["errors"].append("Could not determine file format. Please specify --format")
            return [], stats

    # Read data based on format
    user_data = []
    try:
        if file_format == 'json':
            with open(file_path, 'r') as f:
                user_data = json.load(f)
                # Handle both list and dict formats
                if isinstance(user_data, dict):
                    if "users" in user_data:
                        user_data = user_data["users"]
                    else:
                        user_data = [user_data]
        elif file_format == 'csv':
            with open(file_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                user_data = list(reader)
        else:
            stats["errors"].append(f"Unsupported file format: {file_format}")
            return [], stats

        # Validate data
        stats["total"] = len(user_data)
        for i, user in enumerate(user_data):
            user_errors = []
            for field in required_fields:
                if field not in user or not user[field]:
                    user_errors.append(f"Missing required field: {field}")

            if user_errors:
                stats["invalid"] += 1
                stats["errors"].append(f"User at index {i}: {', '.join(user_errors)}")
            else:
                stats["valid"] += 1

        return user_data, stats

    except (json.JSONDecodeError, csv.Error) as e:
        stats["errors"].append(f"Error parsing file: {str(e)}")
        return [], stats
    except Exception as e:
        stats["errors"].append(f"Unexpected error: {str(e)}")
        return [], stats


def run_command(command_module: str, args: Optional[List[str]] = None) -> int:
    """
    Run a CLI command module with the specified arguments.

    Args:
        command_module: Name of the command module
        args: Command line arguments (None uses sys.argv)

    Returns:
        Exit code
    """
    if args is None:
        args = sys.argv[1:]

    try:
        # Import the module
        module = __import__(f"admin.cli.{command_module}", fromlist=["main"])

        if not hasattr(module, "main"):
            logger.error(f"Module {command_module} does not have a main function")
            return EXIT_ERROR

        # Run the command
        return module.main(args)
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
    'EXIT_NOT_FOUND',
    'EXIT_DEPENDENCY_ERROR',
    'EXIT_OPERATION_CANCELLED',
    'EXIT_TEST_MODE'
]

# Add base classes for command structure
if BASE_COMMAND_AVAILABLE:
    __all__.extend([
        'BaseCommand'
    ])

# Add command testing utilities
if COMMAND_TESTER_AVAILABLE:
    __all__.extend([
        'CommandTester',
        'mock_command',
        'verify_command_called',
        'verify_command_args',
        'verify_command_permissions'
    ])

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
        'merge_configs',
        'initialize_defaults'
    ])

if SECURITY_ADMIN_AVAILABLE:
    __all__.extend([
        'execute_security_command',
        'register_security_command',
        'list_security_commands',
        'security_authenticate'
    ])

if ADMIN_COMMANDS_AVAILABLE:
    __all__.extend([
        'execute_admin_command',
        'register_admin_command',
        'add_command_dependency',
        'validate_dependencies',
        'format_output',
        'mask_sensitive_data',
        'get_command_help',
        'list_commands',
        'enable_test_mode',
        'disable_test_mode',
        'get_test_results',
        'clear_test_results',
        'authenticate',
        'CommandError',
        'ValidationError',
        'PermissionError',
        'AuthenticationError',
        'DependencyError'
    ])

if SYSTEM_COMMANDS_AVAILABLE:
    __all__.extend([
        'HelpCommand',
        'ListCategoriesCommand',
        'VersionCommand',
        'CheckPermissionsCommand'
    ])

# Log initialization status
logger.debug(f"Admin CLI package initialized with: {', '.join([k for k, v in get_available_commands().items() if v])}")
