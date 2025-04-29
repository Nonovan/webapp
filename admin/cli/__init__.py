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
from typing import Dict, Any, List, Callable, Optional, Tuple

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
