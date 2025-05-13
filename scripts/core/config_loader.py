#!/usr/bin/env python3
# filepath: scripts/core/config_loader.py
"""
Configuration Loading and Validation for Cloud Infrastructure Platform

This module provides functionality to load, validate, and access configuration settings
from various sources including YAML, JSON, and INI files. It supports environment-specific
configurations, schema validation, and secure handling of sensitive information.

Key features:
- Multi-format support (JSON, YAML, INI)
- Environment-specific configuration
- Configuration validation through JSON Schema
- Secure handling of sensitive data
- Default value handling
- Hierarchical configuration access
"""

import os
import sys
import json
import re
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Set, Tuple

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import jsonschema
    SCHEMA_VALIDATION_AVAILABLE = True
except ImportError:
    SCHEMA_VALIDATION_AVAILABLE = False

try:
    import configparser
    INI_AVAILABLE = True
except ImportError:
    INI_AVAILABLE = False

# Import logger if available, else configure minimal logger
try:
    from scripts.core.logger import Logger
    logger = Logger.get_logger(__name__)
except ImportError:
    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s in %(name)s: %(message)s',
        level=logging.INFO
    )
    logger = logging.getLogger(__name__)

# Constants
DEFAULT_CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config")
ENV_DEVELOPMENT = "development"
ENV_TESTING = "testing"
ENV_STAGING = "staging"
ENV_PRODUCTION = "production"
ENV_DR_RECOVERY = "dr-recovery"

# Sensitive keys pattern - used to mask sensitive values in logs
SENSITIVE_KEYS_PATTERN = re.compile(
    r'(password|secret|key|token|credential|auth|private|cert)',
    re.IGNORECASE
)

class ConfigError(Exception):
    """Exception raised for configuration errors."""
    pass

class ConfigLoader:
    """
    Main configuration loader class that handles loading and validating configuration
    from various sources, providing a unified interface to access configuration values.
    """

    def __init__(self, config_data: Dict[str, Any], config_file: str = None):
        """
        Initialize the configuration loader.

        Args:
            config_data: Dictionary containing configuration values
            config_file: Path to the configuration file (if loaded from file)
        """
        self._config = config_data
        self._config_file = config_file
        self._schema = None

    @classmethod
    def load(cls, config_file: str, environment: str = None,
             default_config: Dict[str, Any] = None) -> 'ConfigLoader':
        """
        Load configuration from a file with optional environment-specific overrides.

        Args:
            config_file: Path to the configuration file
            environment: Environment name (development, staging, production, etc.)
            default_config: Default configuration values

        Returns:
            ConfigLoader instance with loaded configuration

        Raises:
            ConfigError: If the configuration file cannot be loaded or is invalid
        """
        # Determine environment
        if environment is None:
            environment = os.environ.get('ENVIRONMENT', ENV_DEVELOPMENT)

        # Validate environment name
        environments = [ENV_DEVELOPMENT, ENV_TESTING, ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY]
        if environment not in environments:
            logger.warning(f"Unknown environment: {environment}, defaulting to {ENV_DEVELOPMENT}")
            environment = ENV_DEVELOPMENT

        logger.info(f"Loading configuration for environment: {environment}")

        # Start with default configuration if provided
        config_data = default_config.copy() if default_config else {}

        # Check if file exists
        if not os.path.isfile(config_file):
            # Try to find in default directories
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            alt_paths = [
                os.path.join(base_dir, config_file),
                os.path.join(base_dir, "config", config_file),
                os.path.join(DEFAULT_CONFIG_DIR, config_file)
            ]

            for path in alt_paths:
                if os.path.isfile(path):
                    config_file = path
                    break
            else:
                raise ConfigError(f"Configuration file not found: {config_file}")

        # Determine file format from extension
        _, ext = os.path.splitext(config_file)
        ext = ext.lower()

        try:
            # Load base configuration
            base_config = cls._load_config_file(config_file, ext)
            config_data.update(base_config)

            # Look for environment-specific configuration file
            env_config_file = os.path.join(
                os.path.dirname(config_file),
                f"{os.path.splitext(os.path.basename(config_file))[0]}.{environment}{ext}"
            )

            # Load environment-specific config if it exists
            if os.path.isfile(env_config_file):
                logger.debug(f"Loading environment-specific configuration: {env_config_file}")
                env_config = cls._load_config_file(env_config_file, ext)

                # Update configuration with environment-specific values
                cls._deep_update(config_data, env_config)

            # Check for environment-specific section in the configuration
            if environment in config_data:
                env_section = config_data.pop(environment, {})
                cls._deep_update(config_data, env_section)

            # Override with environment variables
            cls._apply_environment_variables(config_data)

            # Return initialized loader
            return cls(config_data, config_file)

        except Exception as e:
            raise ConfigError(f"Error loading configuration from {config_file}: {str(e)}") from e

    @classmethod
    def _load_config_file(cls, file_path: str, ext: str) -> Dict[str, Any]:
        """
        Load configuration from file based on its extension.

        Args:
            file_path: Path to the configuration file
            ext: File extension

        Returns:
            Dictionary containing configuration values

        Raises:
            ConfigError: If the file format is unsupported or the file is invalid
        """
        try:
            with open(file_path, 'r') as f:
                if ext in ('.yaml', '.yml'):
                    if not YAML_AVAILABLE:
                        raise ConfigError("YAML support not available. Install pyyaml package.")
                    return yaml.safe_load(f) or {}

                elif ext == '.json':
                    return json.load(f) or {}

                elif ext in ('.ini', '.cfg', '.conf', '.config', '.properties'):
                    if not INI_AVAILABLE:
                        raise ConfigError("ConfigParser support not available.")

                    parser = configparser.ConfigParser()
                    parser.read_file(f)

                    # Convert to dictionary
                    result = {}
                    for section in parser.sections():
                        result[section] = {}
                        for key, value in parser.items(section):
                            result[section][key] = cls._parse_ini_value(value)

                    return result

                else:
                    # Try to guess the format by content
                    content = f.read()

                    # Try JSON first
                    try:
                        return json.loads(content) or {}
                    except json.JSONDecodeError:
                        pass

                    # Try YAML
                    if YAML_AVAILABLE:
                        try:
                            return yaml.safe_load(content) or {}
                        except yaml.YAMLError:
                            pass

                    # Try INI format
                    if INI_AVAILABLE:
                        try:
                            parser = configparser.ConfigParser()
                            parser.read_string(content)

                            # Convert to dictionary
                            result = {}
                            for section in parser.sections():
                                result[section] = {}
                                for key, value in parser.items(section):
                                    result[section][key] = cls._parse_ini_value(value)

                            return result
                        except configparser.Error:
                            pass

                    # Fallback to plain text format: key=value
                    result = {}
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        if '=' in line:
                            key, value = line.split('=', 1)
                            result[key.strip()] = cls._parse_ini_value(value.strip())

                    if result:
                        return result

            # If we reached here, couldn't determine format
            raise ConfigError(f"Unsupported configuration file format: {ext}")

        except (OSError, IOError) as e:
            raise ConfigError(f"Failed to read configuration file {file_path}: {str(e)}")

    @staticmethod
    def _parse_ini_value(value: str) -> Any:
        """
        Parse INI values to convert them to appropriate Python types.

        Args:
            value: String value from INI file

        Returns:
            Parsed value
        """
        value = value.strip()

        # Boolean values
        if value.lower() in ('true', 'yes', 'on', '1'):
            return True
        elif value.lower() in ('false', 'no', 'off', '0'):
            return False

        # Try to convert to numeric
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass

        # Return as string
        return value

    @staticmethod
    def _deep_update(target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        Update target dictionary with values from source recursively.

        Args:
            target: Dictionary to update
            source: Dictionary with new values
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                ConfigLoader._deep_update(target[key], value)
            else:
                target[key] = value

    @classmethod
    def _apply_environment_variables(cls, config: Dict[str, Any]) -> None:
        """
        Override configuration values with environment variables.

        Args:
            config: Configuration dictionary to update
        """
        # Look for environment variables with CONFIG_ prefix
        for name, value in os.environ.items():
            if name.startswith('CONFIG_'):
                # Remove prefix and convert to lowercase
                key_path = name[7:].lower().split('__')

                # Navigate to the nested dictionary
                target = config
                for part in key_path[:-1]:
                    if part not in target:
                        target[part] = {}
                    elif not isinstance(target[part], dict):
                        # Convert to dictionary if it's not already
                        target[part] = {"_value": target[part]}
                    target = target[part]

                # Set the value
                target[key_path[-1]] = cls._parse_env_value(value)

    @staticmethod
    def _parse_env_value(value: str) -> Any:
        """
        Parse environment variable value into appropriate Python type.

        Args:
            value: String value from environment variable

        Returns:
            Parsed value
        """
        # Try to parse as JSON
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass

        # Try to convert to numeric or boolean
        return ConfigLoader._parse_ini_value(value)

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by key path.

        Args:
            key_path: Dot-separated path to the configuration value
            default: Default value to return if the key doesn't exist

        Returns:
            Configuration value or default
        """
        parts = key_path.split('.')
        result = self._config

        for part in parts:
            if not isinstance(result, dict):
                return default

            result = result.get(part)

            if result is None:
                return default

        return result

    def get_int(self, key_path: str, default: int = 0) -> int:
        """
        Get configuration value as integer.

        Args:
            key_path: Dot-separated path to the configuration value
            default: Default value to return if the key doesn't exist or cannot be converted

        Returns:
            Configuration value as integer
        """
        value = self.get(key_path, default)
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning(f"Failed to convert {key_path} to integer, using default: {default}")
            return default

    def get_float(self, key_path: str, default: float = 0.0) -> float:
        """
        Get configuration value as float.

        Args:
            key_path: Dot-separated path to the configuration value
            default: Default value to return if the key doesn't exist or cannot be converted

        Returns:
            Configuration value as float
        """
        value = self.get(key_path, default)
        try:
            return float(value)
        except (ValueError, TypeError):
            logger.warning(f"Failed to convert {key_path} to float, using default: {default}")
            return default

    def get_bool(self, key_path: str, default: bool = False) -> bool:
        """
        Get configuration value as boolean.

        Args:
            key_path: Dot-separated path to the configuration value
            default: Default value to return if the key doesn't exist or cannot be converted

        Returns:
            Configuration value as boolean
        """
        value = self.get(key_path, default)
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            value = value.lower()
            if value in ('true', 'yes', 'on', '1'):
                return True
            if value in ('false', 'no', 'off', '0'):
                return False

        try:
            return bool(int(value))
        except (ValueError, TypeError):
            logger.warning(f"Failed to convert {key_path} to boolean, using default: {default}")
            return default

    def get_list(self, key_path: str, default: List = None) -> List:
        """
        Get configuration value as list.

        Args:
            key_path: Dot-separated path to the configuration value
            default: Default value to return if the key doesn't exist or cannot be converted

        Returns:
            Configuration value as list
        """
        if default is None:
            default = []

        value = self.get(key_path, default)

        if isinstance(value, str):
            try:
                # Try to parse as JSON
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return parsed

                # Comma-separated values
                return [item.strip() for item in value.split(',')]

            except json.JSONDecodeError:
                return [item.strip() for item in value.split(',')]

        elif isinstance(value, list):
            return value

        else:
            try:
                return list(value)
            except (TypeError, ValueError):
                logger.warning(f"Failed to convert {key_path} to list, using default: {default}")
                return default

    def get_dict(self, key_path: str, default: Dict = None) -> Dict:
        """
        Get configuration value as dictionary.

        Args:
            key_path: Dot-separated path to the configuration value
            default: Default value to return if the key doesn't exist or cannot be converted

        Returns:
            Configuration value as dictionary
        """
        if default is None:
            default = {}

        value = self.get(key_path, default)

        if isinstance(value, str):
            try:
                # Try to parse as JSON
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse {key_path} as JSON dictionary")
                return default

        elif isinstance(value, dict):
            return value

        else:
            logger.warning(f"Value at {key_path} is not a dictionary, using default")
            return default

    def get_all(self) -> Dict[str, Any]:
        """
        Get the entire configuration dictionary.

        Returns:
            Copy of the configuration dictionary
        """
        return self._config.copy()

    def validate(self, schema_file: str = None, schema: Dict[str, Any] = None) -> bool:
        """
        Validate configuration against JSON schema.

        Args:
            schema_file: Path to JSON Schema file
            schema: Schema dictionary (alternative to schema_file)

        Returns:
            True if configuration is valid, False otherwise

        Raises:
            ConfigError: If schema validation is not available or schema file cannot be loaded
        """
        if not SCHEMA_VALIDATION_AVAILABLE:
            raise ConfigError("Schema validation requires jsonschema package.")

        # Load schema if file path provided
        if schema_file:
            try:
                with open(schema_file, 'r') as f:
                    self._schema = json.load(f)
            except (OSError, IOError) as e:
                raise ConfigError(f"Failed to read schema file {schema_file}: {str(e)}")
            except json.JSONDecodeError as e:
                raise ConfigError(f"Invalid JSON schema in {schema_file}: {str(e)}")
        elif schema:
            self._schema = schema
        elif self._schema is None:
            raise ConfigError("No schema provided for validation.")

        # Validate against schema
        try:
            jsonschema.validate(self._config, self._schema)
            logger.info("Configuration validation successful")
            return True
        except jsonschema.exceptions.ValidationError as e:
            logger.error(f"Configuration validation failed: {str(e)}")
            return False

    def save(self, file_path: str, format: str = None, include_sensitive: bool = False) -> None:
        """
        Save configuration to a file.

        Args:
            file_path: Path to save the configuration file
            format: File format (json, yaml, ini) - inferred from extension if not specified
            include_sensitive: Whether to include sensitive values

        Raises:
            ConfigError: If the file cannot be written or the format is unsupported
        """
        # Determine format from extension if not specified
        if format is None:
            _, ext = os.path.splitext(file_path)
            format = ext.lstrip('.').lower()
            if not format or format not in ('json', 'yaml', 'yml', 'ini'):
                format = 'json'  # Default to JSON

        # Create a copy of the configuration to avoid modifying the original
        config_to_save = self.get_all()

        # Mask sensitive values if needed
        if not include_sensitive:
            self._mask_sensitive_values(config_to_save)

        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

        try:
            with open(file_path, 'w') as f:
                if format in ('yaml', 'yml'):
                    if not YAML_AVAILABLE:
                        raise ConfigError("YAML support not available. Install pyyaml package.")
                    yaml.dump(config_to_save, f, default_flow_style=False)

                elif format == 'json':
                    json.dump(config_to_save, f, indent=2)

                elif format == 'ini':
                    if not INI_AVAILABLE:
                        raise ConfigError("ConfigParser support not available.")

                    parser = configparser.ConfigParser()

                    # Add a DEFAULT section if it doesn't exist
                    if 'DEFAULT' not in config_to_save:
                        config_to_save['DEFAULT'] = {}

                    # Add sections and values
                    for section, values in config_to_save.items():
                        parser[section] = {}

                        if isinstance(values, dict):
                            for key, value in values.items():
                                parser[section][key] = str(value)
                        else:
                            # If not a dictionary, add to DEFAULT section
                            parser['DEFAULT'][section] = str(values)

                    parser.write(f)

                else:
                    raise ConfigError(f"Unsupported configuration format: {format}")

            logger.info(f"Configuration saved to {file_path}")

        except (OSError, IOError) as e:
            raise ConfigError(f"Failed to write configuration file {file_path}: {str(e)}")

    def _mask_sensitive_values(self, config: Dict[str, Any], path: str = "") -> None:
        """
        Mask sensitive values in the configuration.

        Args:
            config: Configuration dictionary to update
            path: Current key path for nested values
        """
        for key, value in list(config.items()):
            current_path = f"{path}.{key}" if path else key

            if isinstance(value, dict):
                self._mask_sensitive_values(value, current_path)
            elif SENSITIVE_KEYS_PATTERN.search(key):
                config[key] = "[MASKED]"

    def __contains__(self, key: str) -> bool:
        """
        Check if configuration contains a key.

        Args:
            key: Key to check

        Returns:
            True if key exists, False otherwise
        """
        return self.get(key) is not None

    def __getitem__(self, key: str) -> Any:
        """
        Get configuration value by key.

        Args:
            key: Key to get

        Returns:
            Configuration value

        Raises:
            KeyError: If the key doesn't exist
        """
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __str__(self) -> str:
        """
        String representation of the configuration.

        Returns:
            String representation
        """
        config_str = json.dumps(self._config, indent=2)
        masked_config = re.sub(
            r'"([^"]*(?:password|secret|key|token|credential)[^"]*)"\s*:\s*"[^"]*"',
            r'"\1": "[MASKED]"',
            config_str,
            flags=re.IGNORECASE
        )
        return f"Configuration from {self._config_file or 'unknown source'}: {masked_config}"


# Module-level functions for convenience
def load_config(config_file: str, environment: str = None,
               default_config: Dict[str, Any] = None) -> ConfigLoader:
    """
    Load configuration from a file (convenience function).

    Args:
        config_file: Path to the configuration file
        environment: Environment name
        default_config: Default configuration values

    Returns:
        ConfigLoader instance
    """
    return ConfigLoader.load(config_file, environment, default_config)


def validate_config_file(config_file: str, schema_file: str,
                        environment: str = None) -> bool:
    """
    Validate a configuration file against a schema (convenience function).

    Args:
        config_file: Path to the configuration file
        schema_file: Path to the schema file
        environment: Environment name

    Returns:
        True if valid, False otherwise
    """
    config = load_config(config_file, environment)
    return config.validate(schema_file)


# Simple standalone test function
def main():
    """Simple test function when script is run directly."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Configuration Loader Test",
        epilog="Example: python config_loader.py -c config.yaml -e production"
    )

    parser.add_argument(
        "-c", "--config",
        dest="config_file",
        required=True,
        help="Path to configuration file"
    )
    parser.add_argument(
        "-e", "--environment",
        dest="environment",
        default=None,
        help="Environment (development, staging, production)"
    )
    parser.add_argument(
        "-s", "--schema",
        dest="schema_file",
        default=None,
        help="Path to JSON schema file for validation"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        help="Path to output processed configuration"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Load configuration
        config = load_config(args.config_file, args.environment)

        # Validate if schema provided
        if args.schema_file:
            valid = config.validate(args.schema_file)
            if not valid:
                logger.error("Configuration validation failed")
                sys.exit(1)

        # Save processed configuration if requested
        if args.output_file:
            config.save(args.output_file)

        # Print configuration summary
        logger.info("Configuration loaded successfully")
        print("Configuration Summary:")
        print(json.dumps(config.get_all(), indent=2, default=str))

    except ConfigError as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
