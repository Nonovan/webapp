"""
Configuration management for the Cloud Infrastructure Platform CLI.

This module provides utilities for loading, validating, and working with
configuration settings for CLI commands. It abstracts environment-specific
configuration handling, manages sensitive data, and ensures secure configuration
file operations.
"""

import os
import json
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import click
from flask import Flask, current_app

from core.utils import get_logger
from core.security import check_file_integrity
from cli.common import (
    is_safe_file_operation,
    sanitize_path,
    protect_sensitive_data,
    EXIT_SUCCESS,
    EXIT_ERROR,
    EXIT_RESOURCE_ERROR
)

# Initialize logger
logger = get_logger(__name__)

# Constants for configuration management
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/cloudplatform")
DEFAULT_CONFIG_FILE = "cli_config.json"
CONFIG_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "templates")
SENSITIVE_FIELDS = ['password', 'token', 'secret', 'key', 'credential', 'auth']

# Environment-specific settings
ENVIRONMENTS = ['development', 'testing', 'staging', 'production']

# Global cache for configuration
_config_cache = {}


def get_config_path(filename: Optional[str] = None, env: Optional[str] = None) -> str:
    """
    Get the path to a configuration file.

    Args:
        filename: Custom filename (defaults to cli_config.json)
        env: Environment name to include in filename

    Returns:
        Path to the configuration file
    """
    if not filename:
        filename = f"cli_config{f'_{env}' if env else ''}.json"

    return os.path.join(DEFAULT_CONFIG_DIR, filename)


def load_config(env: Optional[str] = None, filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file with environment-specific overrides.

    Args:
        env: Optional environment name (development, testing, staging, production)
        filename: Optional custom configuration filename

    Returns:
        Dictionary containing configuration values
    """
    # Use cached config if available
    cache_key = env or 'default'
    if cache_key in _config_cache:
        return _config_cache[cache_key]

    try:
        # Ensure config directory exists
        os.makedirs(DEFAULT_CONFIG_DIR, exist_ok=True)

        # Get config file path
        config_file = Path(get_config_path(filename, env))

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
                'debug': False,
                'security': {
                    'mask_secrets': True,
                    'verify_integrity': True,
                    'auto_update_baseline': False
                }
            }

            # Write default config with secure permissions
            config_file.parent.mkdir(parents=True, exist_ok=True)
            config_file.write_text(json.dumps(default_config, indent=2))
            if os.name != 'nt':  # Set file permissions on Unix-like systems
                os.chmod(config_file, 0o600)  # Owner read/write only

        # Load configuration
        config = json.loads(config_file.read_text())

        # If environment specified, return just that section
        if env and env in config.get('environments', {}):
            env_config = config['environments'][env]
            _config_cache[cache_key] = env_config
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


def save_config(config: Dict[str, Any], env: Optional[str] = None,
                filename: Optional[str] = None) -> bool:
    """
    Save configuration to file.

    Args:
        config: Configuration dictionary to save
        env: Optional environment name
        filename: Optional custom filename

    Returns:
        True if saved successfully, False otherwise
    """
    try:
        config_path = get_config_path(filename, env)

        # Ensure path is safe before writing
        if not is_safe_file_operation('write', config_path):
            logger.error(f"Unsafe config path: {config_path}")
            return False

        # Ensure directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        # Write config with pretty formatting
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Set secure permissions
        if os.name != 'nt':  # Unix-like systems
            os.chmod(config_path, 0o600)  # Owner read/write only

        # Update cache
        cache_key = env or 'default'
        _config_cache[cache_key] = config

        return True

    except Exception as e:
        logger.error(f"Failed to save configuration: {str(e)}")
        return False


def get_config_value(key: str, default: Any = None, env: Optional[str] = None) -> Any:
    """
    Get a specific configuration value, supporting dot notation.

    Args:
        key: Configuration key to retrieve
        default: Default value if key not found
        env: Optional environment name

    Returns:
        Configuration value or default
    """
    try:
        # Try environment-specific configuration first
        if env:
            env_config = load_config(env)
            if key in env_config:
                return env_config[key]

        # Try global configuration
        config = load_config()

        # Handle dot notation (e.g., environments.development.api_url)
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

    except Exception as e:
        logger.debug(f"Error getting config value '{key}': {str(e)}")
        return default


def set_config_value(key: str, value: Any, env: Optional[str] = None) -> bool:
    """
    Set a specific configuration value, supporting dot notation.

    Args:
        key: Configuration key to set
        value: Value to set
        env: Optional environment name

    Returns:
        True if successful, False otherwise
    """
    try:
        config = load_config()

        # Handle environment-specific config
        if env:
            if 'environments' not in config:
                config['environments'] = {}
            if env not in config['environments']:
                config['environments'][env] = {}

            # Set in environment section
            config['environments'][env][key] = value
        else:
            # Handle dot notation for nested configuration
            if '.' in key:
                parts = key.split('.')
                current = config

                # Navigate to the deepest level
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]

                # Set the value at the deepest level
                current[parts[-1]] = value
            else:
                # Simple key-value at root level
                config[key] = value

        # Save the updated configuration
        return save_config(config)

    except Exception as e:
        logger.error(f"Failed to set config value '{key}': {str(e)}")
        return False


def get_current_environment() -> str:
    """
    Get the currently configured environment.

    Returns:
        Environment name (development, testing, staging, production)
    """
    # Check environment variable first
    env = os.environ.get('CLOUDPLATFORM_ENV')
    if env and env in ENVIRONMENTS:
        return env

    # Fall back to config file
    return get_config_value('default_environment', 'development')


def set_current_environment(env: str) -> bool:
    """
    Set the current default environment.

    Args:
        env: Environment name to set as default

    Returns:
        True if successful, False otherwise
    """
    if env not in ENVIRONMENTS:
        logger.error(f"Invalid environment: {env}")
        return False

    return set_config_value('default_environment', env)


def mask_sensitive_values(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mask sensitive values in configuration for display.

    Args:
        config_data: Configuration dictionary

    Returns:
        Configuration with sensitive values masked
    """
    masked_config = {}

    for key, value in config_data.items():
        if isinstance(value, dict):
            # Recursively mask nested dictionaries
            masked_config[key] = mask_sensitive_values(value)
        elif isinstance(value, str) and any(field in key.lower() for field in SENSITIVE_FIELDS):
            # Mask sensitive values like passwords and keys
            masked_config[key] = '********'
        else:
            masked_config[key] = value

    return masked_config


def initialize_config_from_template(env: str, template_path: Optional[str] = None,
                                   output_path: Optional[str] = None,
                                   overwrite: bool = False) -> Tuple[bool, str]:
    """
    Initialize configuration file from a template.

    Args:
        env: Target environment
        template_path: Path to template file (uses default if None)
        output_path: Path for output file (uses default if None)
        overwrite: Whether to overwrite existing file

    Returns:
        Tuple of (success, message)
    """
    try:
        # Set default paths if needed
        if not template_path:
            template_path = os.path.join(CONFIG_TEMPLATE_DIR, f"{env}.env.template")

        if not output_path:
            output_path = f".env.{env}"

        template_path = Path(template_path).absolute()
        output_path = Path(output_path).absolute()

        # Check if template exists
        if not template_path.exists():
            return False, f"Template file not found: {template_path}"

        # Check if output file exists and should not overwrite
        if output_path.exists() and not overwrite:
            return False, f"Output file already exists: {output_path}"

        # Read template content
        with open(template_path, 'r') as f:
            config_content = f.read()

        # Replace placeholders with environment-specific values
        replacements = {
            '{{environment}}': env,
            '{{timestamp}}': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            '{{secret_key}}': secrets.token_hex(24),
            '{{csrf_key}}': secrets.token_hex(16),
            '{{session_key}}': secrets.token_hex(16),
            '{{jwt_key}}': secrets.token_hex(16),
            '{{server_name}}': f"localhost:{5000 + (100 if env == 'testing' else 0)}"
        }

        for placeholder, value in replacements.items():
            config_content = config_content.replace(placeholder, value)

        # Create directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write output file
        with open(output_path, 'w') as f:
            f.write(config_content)

        return True, f"Configuration file created successfully: {output_path}"

    except Exception as e:
        logger.error(f"Failed to initialize configuration: {str(e)}")
        return False, f"Configuration initialization failed: {str(e)}"


def verify_configuration(config_data: Dict[str, Any], required_keys: List[str]) -> Tuple[bool, List[str]]:
    """
    Verify configuration contains all required keys.

    Args:
        config_data: Configuration dictionary
        required_keys: List of required keys

    Returns:
        Tuple of (is_valid, missing_keys)
    """
    missing_keys = []

    for key in required_keys:
        # Handle dot notation for nested keys
        if '.' in key:
            parts = key.split('.')
            value = config_data
            found = True

            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    missing_keys.append(key)
                    found = False
                    break
        else:
            if key not in config_data:
                missing_keys.append(key)

    return len(missing_keys) == 0, missing_keys


def categorize_config(config_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Categorize configuration values by common prefixes.

    Args:
        config_data: Configuration dictionary

    Returns:
        Dictionary grouped by category
    """
    categories = {
        'Database': {},
        'Security': {},
        'Email': {},
        'Cache': {},
        'Session': {},
        'Auth': {},
        'Logging': {},
        'Monitoring': {},
        'Features': {},
        'Debug': {},
        'Other': {}
    }

    # Define prefix mappings
    prefix_mappings = {
        'DATABASE': 'Database',
        'DB_': 'Database',
        'SQLALCHEMY': 'Database',
        'MAIL_': 'Email',
        'SMTP_': 'Email',
        'EMAIL_': 'Email',
        'REDIS_': 'Cache',
        'CACHE_': 'Cache',
        'SESSION_': 'Session',
        'SECURITY_': 'Security',
        'CSRF_': 'Security',
        'JWT_': 'Auth',
        'AUTH_': 'Auth',
        'OAUTH_': 'Auth',
        'DEBUG': 'Debug',
        'LOG_': 'Logging',
        'SENTRY_': 'Monitoring',
        'FEATURE_': 'Features',
    }

    for key, value in config_data.items():
        categorized = False

        for prefix, category in prefix_mappings.items():
            if key.startswith(prefix) or key.upper().startswith(prefix):
                categories[category][key] = value
                categorized = True
                break

        if not categorized:
            categories['Other'][key] = value

    # Remove empty categories
    return {cat: values for cat, values in categories.items() if values}


# Export all public functions and constants
__all__ = [
    'load_config',
    'save_config',
    'get_config_value',
    'set_config_value',
    'get_current_environment',
    'set_current_environment',
    'mask_sensitive_values',
    'initialize_config_from_template',
    'verify_configuration',
    'categorize_config',
    'get_config_path',
    'ENVIRONMENTS',
    'SENSITIVE_FIELDS'
]
