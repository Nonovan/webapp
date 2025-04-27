"""
Common utilities for the Cloud Infrastructure Platform CLI.

This module provides shared functionality used across CLI commands including
authentication, configuration management, error handling, input validation,
logging, and progress reporting. These utilities ensure consistent behavior
and standardized patterns across all CLI commands.
"""

import functools
import json
import logging
import os
import sys
from tabulate import tabulate
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union, cast

import click
from flask import current_app

# Type variables for callable signatures
F = TypeVar('F', bound=Callable[..., Any])

# Standard exit codes for consistent CLI behavior
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_AUTH_ERROR = 2
EXIT_PERMISSION_ERROR = 3
EXIT_VALIDATION_ERROR = 4
EXIT_RESOURCE_ERROR = 5

# Configure logger
logger = logging.getLogger('cli')

# Cache for configuration to avoid reloading
_config_cache: Dict[str, Dict[str, Any]] = {}


def configure_logging(verbose: bool = False) -> None:
    """
    Configure logging for CLI commands with appropriate handlers and formatters.

    Args:
        verbose: Whether to enable verbose (DEBUG) logging
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)

    # Create console handler if not already configured
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)

        # Create formatter
        if verbose:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            formatter = logging.Formatter('%(message)s')

        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Don't propagate to Flask logger
    logger.propagate = False


def require_auth(func: F) -> F:
    """
    Decorator to require authentication for a command.

    Args:
        func: The CLI function to wrap

    Returns:
        The wrapped function that checks for authentication
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Check if user is authenticated
        if not is_authenticated():
            click.echo("Authentication required")
            click.echo("Please login using: flask auth login")
            return EXIT_AUTH_ERROR
        return func(*args, **kwargs)

    return cast(F, wrapper)


def require_permission(permission: str) -> Callable[[F], F]:
    """
    Decorator to require specific permission for a command.

    Args:
        permission: The permission required to run the command

    Returns:
        Decorator function that checks for required permission
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # First check authentication
            if not is_authenticated():
                click.echo("Authentication required")
                click.echo("Please login using: flask auth login")
                return EXIT_AUTH_ERROR

            # Then check permission
            if not has_permission(permission):
                click.echo(f"Permission denied: {permission} is required")
                return EXIT_PERMISSION_ERROR

            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def is_authenticated() -> bool:
    """
    Check if the user is authenticated.

    Returns:
        True if authenticated, False otherwise
    """
    try:
        # Try to get user from Flask application context
        if current_app:
            from flask import session
            return session.get('authenticated', False) and session.get('user_id') is not None

        # Fallback to token-based check if not in app context
        token_file = get_auth_token_path()
        if not token_file.exists():
            return False

        # Check if token is valid
        token_data = json.loads(token_file.read_text())
        expiry = datetime.fromisoformat(token_data.get('expires', '2000-01-01'))

        if expiry < datetime.now():
            return False

        return True
    except Exception as e:
        logger.debug(f"Error checking authentication: {str(e)}")
        return False


def has_permission(permission: str) -> bool:
    """
    Check if the current user has a specific permission.

    Args:
        permission: The permission to check

    Returns:
        True if the user has the permission, False otherwise
    """
    try:
        # Try to use Flask's security system if available
        if current_app:
            from flask import session

            # Get user permission from session
            user_perms = session.get('permissions', [])
            if permission in user_perms:
                return True

            # Check for role-based permissions
            user_roles = session.get('roles', [])
            if 'admin' in user_roles:
                return True  # Admin has all permissions

            # Check with authentication provider
            from core.security import check_permission
            return check_permission(permission)

        # Fallback to checking local token
        token_file = get_auth_token_path()
        if not token_file.exists():
            return False

        token_data = json.loads(token_file.read_text())
        permissions = token_data.get('permissions', [])
        roles = token_data.get('roles', [])

        # Direct permission match or admin role grants all permissions
        return permission in permissions or 'admin' in roles

    except Exception as e:
        logger.debug(f"Error checking permission: {str(e)}")
        return False


def get_auth_token_path() -> Path:
    """
    Get the path to the authentication token file.

    Returns:
        Path to the token file
    """
    config_dir = Path.home() / '.config' / 'cloudplatform'
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / 'auth_token.json'


def handle_error(error: Exception, message: str = "An error occurred") -> None:
    """
    Handle and log errors in a consistent way.

    Args:
        error: The exception that was raised
        message: User-friendly error message to display
    """
    # Log the full error for debugging
    logger.error(f"{message}: {str(error)}", exc_info=True)

    # Display a user-friendly message
    click.echo(click.style(f"Error: {message}", fg='red'))

    # Optional: Add more detailed error information for verbose mode
    if logger.level == logging.DEBUG:
        click.echo(f"Details: {str(error)}")


def load_config(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration settings for the CLI.

    Args:
        environment: Optional environment name to load environment-specific config

    Returns:
        Dictionary containing configuration values
    """
    # Use cached config if available
    cache_key = environment or 'default'
    if cache_key in _config_cache:
        return _config_cache[cache_key]

    try:
        # Determine config file location
        config_dir = Path.home() / '.config' / 'cloudplatform'
        config_dir.mkdir(parents=True, exist_ok=True)

        config_file = config_dir / 'config.json'

        # Create default config if it doesn't exist
        if not config_file.exists():
            default_config = {
                'default_environment': 'development',
                'environments': {
                    'development': {
                        'api_url': 'http://localhost:5000/api',
                        'timeout': 30
                    },
                    'production': {
                        'api_url': 'https://api.example.com/api',
                        'timeout': 60
                    }
                },
                'output_format': 'text',
                'debug': False
            }

            config_file.write_text(json.dumps(default_config, indent=2))

        # Load configuration
        config = json.loads(config_file.read_text())

        # If environment specified, return just that section, otherwise full config
        if environment:
            env_config = config.get('environments', {}).get(environment, {})
            _config_cache[environment] = env_config
            return env_config

        _config_cache[cache_key] = config
        return config

    except Exception as e:
        logger.error(f"Failed to load configuration: {str(e)}")
        # Return minimal default config
        return {
            'default_environment': 'development',
            'environments': {},
            'output_format': 'text',
            'debug': False
        }


def save_config(config: Dict[str, Any]) -> bool:
    """
    Save configuration settings for the CLI.

    Args:
        config: Dictionary containing configuration values

    Returns:
        True if saved successfully, False otherwise
    """
    try:
        # Determine config file location
        config_dir = Path.home() / '.config' / 'cloudplatform'
        config_dir.mkdir(parents=True, exist_ok=True)

        config_file = config_dir / 'config.json'

        # Write config with proper formatting
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        # Update cache with new config
        _config_cache['default'] = config

        # Clear any environment-specific caches that might be affected
        for env in config.get('environments', {}):
            if env in _config_cache:
                del _config_cache[env]

        return True
    except Exception as e:
        logger.error(f"Failed to save configuration: {str(e)}")
        return False


def get_config_value(key: str, default: Any = None, environment: Optional[str] = None) -> Any:
    """
    Get a configuration value with fallbacks and environment support.

    Args:
        key: The configuration key to look up
        default: Default value to return if key not found
        environment: Optional environment name for environment-specific config

    Returns:
        The configuration value or default if not found
    """
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


def create_progress_bar(total: int, label: str = "Processing",
                      show_percent: bool = True,
                      show_eta: bool = True) -> click.progressbar:
    """
    Create a standardized progress bar for CLI operations.

    Args:
        total: Total number of steps/items
        label: Description of the operation
        show_percent: Whether to show percentage complete
        show_eta: Whether to show estimated time remaining

    Returns:
        Click progress bar object
    """
    bar_template = '%(label)s [%(bar)s] %(info)s'

    if show_percent and show_eta:
        info_template = '%(percent).1f%% - %(eta)ds remaining'
    elif show_percent:
        info_template = '%(percent).1f%%'
    elif show_eta:
        info_template = '%(eta)ds remaining'
    else:
        info_template = ''

    return click.progressbar(
        length=total,
        label=label,
        bar_template=bar_template,
        info_sep='  ',
        show_eta=show_eta,
        show_percent=show_percent,
        info_sep_length=0,
        width=30,
        fill_char='=',
        empty_char=' ',
        show_pos=True,
        item_show_func=None,
        file=None,
        color=None
    )


def format_output(data: Any, format_type: str = 'text') -> str:
    """
    Format output data according to the specified format.

    Args:
        data: The data to format (dict, list, or primitive)
        format_type: Output format (text, json, csv, table)

    Returns:
        Formatted string representation of the data
    """
    format_type = format_type.lower()

    if format_type == 'json':
        return json.dumps(data, indent=2, sort_keys=True)

    elif format_type == 'csv':
        import csv
        from io import StringIO

        output = StringIO()
        if isinstance(data, list) and data and isinstance(data[0], dict):
            # Get fieldnames from first item
            fieldnames = list(data[0].keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
            return output.getvalue()
        else:
            return "Error: Data must be a list of dictionaries for CSV format"

    elif format_type == 'table':
        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                # Get headers from first item
                headers = list(data[0].keys())
                rows = [[item.get(key, "") for key in headers] for item in data]
                return tabulate(rows, headers=headers, tablefmt="grid")
            else:
                return tabulate(data, tablefmt="grid")
        elif isinstance(data, dict):
            return tabulate([(k, v) for k, v in data.items()],
                          headers=["Key", "Value"],
                          tablefmt="grid")
        else:
            return str(data)

    else:  # Default to text format
        if isinstance(data, dict):
            lines = [f"{k}: {v}" for k, v in data.items()]
            return "\n".join(lines)
        elif isinstance(data, list):
            if data and isinstance(data[0], dict):
                # Pretty print list of dicts
                lines = []
                for i, item in enumerate(data):
                    lines.append(f"Item {i+1}:")
                    for k, v in item.items():
                        lines.append(f"  {k}: {v}")
                return "\n".join(lines)
            else:
                return "\n".join([f"- {item}" for item in data])
        else:
            return str(data)


def validate_input(value: str,
                 rules: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate user input against a set of rules.

    Args:
        value: The input value to validate
        rules: Dictionary containing validation rules:
               - 'required': True/False
               - 'min_length': Minimum length
               - 'max_length': Maximum length
               - 'pattern': Regex pattern
               - 'choices': List of valid choices
               - 'validator': Custom validation function

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check if required
    if rules.get('required', False) and not value:
        return False, "This field is required"

    # Skip additional validation if empty and not required
    if not value:
        return True, None

    # Check min length
    min_length = rules.get('min_length')
    if min_length is not None and len(value) < min_length:
        return False, f"Must be at least {min_length} characters"

    # Check max length
    max_length = rules.get('max_length')
    if max_length is not None and len(value) > max_length:
        return False, f"Must be at most {max_length} characters"

    # Check pattern
    pattern = rules.get('pattern')
    if pattern is not None:
        import re
        if not re.match(pattern, value):
            return False, rules.get('pattern_message', "Invalid format")

    # Check choices
    choices = rules.get('choices')
    if choices is not None and value not in choices:
        choices_str = ", ".join(choices)
        return False, f"Must be one of: {choices_str}"

    # Custom validator
    validator = rules.get('validator')
    if validator is not None and callable(validator):
        result = validator(value)
        if isinstance(result, tuple) and len(result) == 2:
            is_valid, message = result
        else:
            raise ValueError("Validator must return a tuple (is_valid, message)")
        if not is_valid:
            return False, message

    return True, None


def prompt_with_validation(prompt: str,
                         rules: Dict[str, Any],
                         default: Optional[str] = None,
                         hide_input: bool = False,
                         confirmation_prompt: bool = False) -> Optional[str]:
    """
    Prompt user for input with validation.

    Args:
        prompt: The prompt text to display
        rules: Validation rules dictionary
        default: Default value (optional)
        hide_input: Whether to hide user input (for passwords)
        confirmation_prompt: Whether to prompt for confirmation

    Returns:
        Validated user input or None if user aborted
    """
    while True:
        # Prompt for input
        kwargs = {
            'default': default,
            'hide_input': hide_input,
            'confirmation_prompt': confirmation_prompt and hide_input
        }

        value = click.prompt(prompt, **kwargs)

        # Validate input
        is_valid, error = validate_input(value, rules)

        if is_valid:
            return value
        else:
            click.echo(click.style(f"Error: {error}", fg='red'))


def confirm_action(prompt: str,
                 abort: bool = False,
                 default: bool = False) -> bool:
    """
    Prompt for user confirmation with consistent formatting.

    Args:
        prompt: The confirmation prompt
        abort: Whether to abort execution if user declines
        default: Default response (True=Yes, False=No)

    Returns:
        True if confirmed, False otherwise
    """
    result = click.confirm(prompt, abort=abort, default=default)
    return result


def get_current_environment() -> str:
    """
    Get the current environment name from config or environment variables.

    Returns:
        Current environment name (e.g., development, production)
    """
    # Check environment variable first
    env = os.environ.get('CLOUDPLATFORM_ENV')
    if env:
        return env

    # Fall back to config
    config = load_config()
    return config.get('default_environment', 'development')


def set_current_environment(environment: str) -> bool:
    """
    Set the current environment in the configuration.

    Args:
        environment: Environment name to set as default

    Returns:
        True if successful, False otherwise
    """
    try:
        config = load_config()

        # Verify environment exists
        if environment not in config.get('environments', {}):
            click.echo(f"Environment '{environment}' not configured")
            return False

        config['default_environment'] = environment
        save_config(config)

        click.echo(f"Current environment set to: {environment}")
        return True
    except Exception as e:
        logger.error(f"Failed to set environment: {str(e)}")
        return False


def print_version() -> None:
    """
    Print version information for the CLI.
    """
    from importlib.metadata import version
    try:
        ver = version("cloudplatform-cli")
    except:
        # Fallback if package metadata not available
        ver = "1.0.0"

    click.echo(f"Cloud Infrastructure Platform CLI v{ver}")


def get_api_client(environment: Optional[str] = None) -> Any:
    """
    Get a configured API client for the specified environment.

    Args:
        environment: Environment name or None to use current environment

    Returns:
        Configured API client instance
    """
    from core.api import APIClient

    env = environment or get_current_environment()
    config = load_config(env)

    api_url = config.get('api_url')
    timeout = config.get('timeout', 30)

    # Get authentication token
    token = None
    token_file = get_auth_token_path()
    if token_file.exists():
        try:
            token_data = json.loads(token_file.read_text())
            token = token_data.get('token')
        except Exception:
            pass

    return APIClient(base_url=api_url, timeout=timeout, auth_token=token)
