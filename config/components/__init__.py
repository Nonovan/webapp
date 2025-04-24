"""
Component configuration management for Cloud Infrastructure Platform.

This module provides utilities for loading and managing component-specific
configurations from different formats (INI, JSON, YAML) with support for
environment-specific overrides.
"""

import os
import json
import configparser
from pathlib import Path
from typing import Optional, Dict, Any, Union, List

# Try to import yaml if available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Configuration base paths
CONFIG_ROOT = Path(__file__).parent.parent
COMPONENTS_DIR = CONFIG_ROOT / 'components'
ENVIRONMENT_DIR = CONFIG_ROOT / 'environments'


def resolve_path(component_name: str, environment: Optional[str] = None,
               extension: Optional[str] = None) -> Path:
    """
    Resolve the path to a configuration file based on component name and environment.

    Args:
        component_name: Name of the component (e.g., 'database', 'api')
        environment: Optional environment name (e.g., 'development', 'production')
        extension: Optional file extension to override automatic detection

    Returns:
        Path: The resolved configuration file path
    """
    # Handle file extension
    if extension:
        if not extension.startswith('.'):
            extension = f'.{extension}'
    else:
        # Try to detect extension based on existing files
        extensions = ['.ini', '.json', '.yaml', '.yml']
        for ext in extensions:
            if (COMPONENTS_DIR / f"{component_name}{ext}").exists():
                extension = ext
                break
        # Default to .ini if not found
        if not extension:
            extension = '.ini'

    # Base component config
    base_config_path = COMPONENTS_DIR / f"{component_name}{extension}"

    # Environment-specific override if applicable
    if environment:
        env_config_path = ENVIRONMENT_DIR / environment / f"{component_name}{extension}"
        if env_config_path.exists():
            return env_config_path

    return base_config_path


def load_component_config(component_name: str, environment: Optional[str] = None,
                        extension: Optional[str] = None,
                        use_env_vars: bool = True) -> Union[configparser.ConfigParser, Dict[str, Any]]:
    """
    Load configuration for a specific component with optional environment override.

    Args:
        component_name: Name of the component (e.g., 'database', 'api')
        environment: Optional environment name (e.g., 'development', 'production')
        extension: Optional file extension to override automatic detection
        use_env_vars: Whether to apply environment variable overrides

    Returns:
        ConfigParser or dict: Loaded configuration
    """
    base_config_path = resolve_path(component_name, None, extension)

    # Initialize proper config object based on file type
    file_extension = base_config_path.suffix.lower()

    if not base_config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {base_config_path}")

    # Load base configuration based on file type
    if file_extension in ['.ini']:
        config = configparser.ConfigParser()
        config.read(base_config_path)

        # Load environment override if specified and exists
        if environment:
            env_config_path = ENVIRONMENT_DIR / environment / base_config_path.name
            if env_config_path.exists():
                config.read(env_config_path)

        # Apply environment variable overrides if requested
        if use_env_vars:
            _apply_env_var_overrides(config, component_name)

        return config

    elif file_extension in ['.json']:
        with open(base_config_path, 'r') as f:
            config = json.load(f)

        # Load environment override if specified and exists
        if environment:
            env_config_path = ENVIRONMENT_DIR / environment / base_config_path.name
            if env_config_path.exists():
                with open(env_config_path, 'r') as f:
                    env_config = json.load(f)
                # Merge configs (deep update)
                _deep_update(config, env_config)

        # Apply environment variable overrides if requested
        if use_env_vars:
            _apply_json_env_var_overrides(config, component_name)

        return config

    elif file_extension in ['.yaml', '.yml']:
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required to load YAML configuration files.")

        with open(base_config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Load environment override if specified and exists
        if environment:
            env_config_path = ENVIRONMENT_DIR / environment / base_config_path.name
            if env_config_path.exists():
                with open(env_config_path, 'r') as f:
                    env_config = yaml.safe_load(f)
                # Merge configs (deep update)
                _deep_update(config, env_config)

        # Apply environment variable overrides if requested
        if use_env_vars:
            _apply_json_env_var_overrides(config, component_name)

        return config

    else:
        raise ValueError(f"Unsupported configuration file format: {file_extension}")


def _deep_update(original: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively update a nested dictionary with values from another dictionary.

    Args:
        original: Original dictionary to update
        update: Dictionary with values to apply

    Returns:
        Dict: The updated dictionary
    """
    for key, value in update.items():
        if isinstance(value, dict) and key in original and isinstance(original[key], dict):
            _deep_update(original[key], value)
        else:
            original[key] = value
    return original


def _apply_env_var_overrides(config: configparser.ConfigParser, component_name: str) -> None:
    """
    Apply environment variable overrides to ConfigParser object.

    Environment variables should follow the pattern:
    CLOUDPLATFORM_{COMPONENT}_{SECTION}_{KEY}

    Args:
        config: ConfigParser object to update
        component_name: Name of the component for environment variable prefixing
    """
    prefix = f"CLOUDPLATFORM_{component_name.upper()}_"

    for env_var, value in os.environ.items():
        if env_var.startswith(prefix):
            # Extract section and key from environment variable name
            # Format: CLOUDPLATFORM_{COMPONENT}_{SECTION}_{KEY}
            _, _, section_key = env_var.partition(prefix)
            if '_' in section_key:
                section, key = section_key.split('_', 1)

                # Ensure section exists
                if section not in config:
                    config[section] = {}

                # Apply the override
                config[section][key] = value


def _apply_json_env_var_overrides(config: Dict[str, Any], component_name: str) -> None:
    """
    Apply environment variable overrides to a dictionary config.

    Environment variables should follow the pattern:
    CLOUDPLATFORM_{COMPONENT}_{PATH_WITH_UNDERSCORES}

    Args:
        config: Dictionary to update
        component_name: Name of the component for environment variable prefixing
    """
    prefix = f"CLOUDPLATFORM_{component_name.upper()}_"

    for env_var, value in os.environ.items():
        if env_var.startswith(prefix):
            # Extract path from environment variable name
            # Format: CLOUDPLATFORM_{COMPONENT}_{PATH_WITH_UNDERSCORES}
            _, _, path = env_var.partition(prefix)

            # Convert path to a list of keys
            keys = path.lower().split('_')

            # Navigate to the correct nested position and update value
            current = config
            for i, key in enumerate(keys[:-1]):
                if key not in current:
                    current[key] = {}
                current = current[key]

            # Set the value at the final position
            current[keys[-1]] = _convert_env_value(value)


def _convert_env_value(value: str) -> Any:
    """
    Convert environment variable string value to appropriate Python type.

    Args:
        value: String value from environment variable

    Returns:
        The value converted to an appropriate type
    """
    # Check for boolean
    if value.lower() in ('true', 'yes', '1'):
        return True
    if value.lower() in ('false', 'no', '0'):
        return False

    # Check for integer
    try:
        return int(value)
    except ValueError:
        pass

    # Check for float
    try:
        return float(value)
    except ValueError:
        pass

    # Check for JSON
    if (value.startswith('{') and value.endswith('}')) or \
       (value.startswith('[') and value.endswith(']')):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass

    # Return as string if no other type matches
    return value


# Export public functions
__all__ = [
    'load_component_config',
    'resolve_path',
]
