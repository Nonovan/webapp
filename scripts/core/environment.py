#!/usr/bin/env python3
# filepath: scripts/core/environment.py
"""
Environment Management for Cloud Infrastructure Platform

This module provides functionality to manage environment variables, detect runtime
environments, and handle environment-specific configuration. It supports secure
handling of sensitive data and provides a centralized interface for environment
settings across the platform.

Key features:
- Environment variable management
- Runtime environment detection
- Environment-specific behavior
- Secure secrets handling
- Configuration override mechanism
"""

import os
import sys
import re
import json
import logging
import socket
from typing import Dict, Any, Optional, Union, List, Set, Tuple, cast
from datetime import datetime
from enum import Enum
from pathlib import Path

# Try to import internal modules
try:
    from scripts.core.logger import Logger
    from scripts.core.config_loader import ConfigLoader, ConfigError
    INTERNAL_MODULES_AVAILABLE = True
except ImportError:
    INTERNAL_MODULES_AVAILABLE = False

# Setup basic logging if Logger is not available
if INTERNAL_MODULES_AVAILABLE:
    logger = Logger.get_logger(__name__)
else:
    logging.basicConfig(
        format='[%(asctime)s] %(levelname)s in %(name)s: %(message)s',
        level=logging.INFO
    )
    logger = logging.getLogger(__name__)

# Environment constants
ENV_DEVELOPMENT = "development"
ENV_TESTING = "testing"
ENV_STAGING = "staging"
ENV_PRODUCTION = "production"
ENV_DR_RECOVERY = "dr-recovery"
ENV_CI = "ci"

# Define environment hierarchy (from least to most restrictive)
ENV_HIERARCHY = [ENV_DEVELOPMENT, ENV_TESTING, ENV_CI, ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY]

# List of allowed environments
ALLOWED_ENVIRONMENTS = {ENV_DEVELOPMENT, ENV_TESTING, ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY, ENV_CI}

# Environments with strict security requirements
SECURE_ENVIRONMENTS = {ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY}

# Default paths
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ENV_DIR = PROJECT_ROOT / "config" / "env"
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"

# Pattern for sensitive values that should be masked in logs
SENSITIVE_PATTERN = re.compile(
    r'(password|secret|key|token|credential|auth|private|cert)',
    re.IGNORECASE
)


class EnvironmentError(Exception):
    """Exception raised for environment-related errors."""
    pass


class Environment:
    """
    Main class for managing environment variables and settings.

    This class provides methods to load, validate, and access environment
    variables across different runtime environments.
    """

    _instance = None
    _initialized = False
    _vars = {}
    _current_env = None

    def __new__(cls, *args, **kwargs):
        """Implement singleton pattern to ensure consistent environment state."""
        if cls._instance is None:
            cls._instance = super(Environment, cls).__new__(cls)
        return cls._instance

    def __init__(self, env_name: Optional[str] = None, env_file: Optional[str] = None):
        """
        Initialize the environment manager.

        Args:
            env_name: Optional environment name (development, staging, production)
            env_file: Optional path to environment file
        """
        if self._initialized:
            return

        self._vars = {}
        self._env_file = env_file or os.environ.get("ENV_FILE")
        self._current_env = env_name or self._detect_environment()

        # Validate environment name
        if self._current_env not in ALLOWED_ENVIRONMENTS:
            logger.warning(f"Unknown environment: {self._current_env}, defaulting to {ENV_DEVELOPMENT}")
            self._current_env = ENV_DEVELOPMENT

        # Initialize empty environment if not loading from file
        if not self._env_file:
            logger.debug("No environment file specified, using system environment")
            self._load_from_system_env()
        else:
            self.load(self._env_file)

        self._initialized = True
        logger.debug(f"Environment initialized: {self._current_env}")

    def load(self, env_file: Optional[str] = None) -> bool:
        """
        Load environment variables from file and system environment.

        Args:
            env_file: Path to environment file (.env)

        Returns:
            True if successful, False otherwise
        """
        if env_file:
            self._env_file = env_file

        # Load from file if specified
        if self._env_file:
            file_path = Path(self._env_file)
            if not file_path.exists():
                logger.warning(f"Environment file not found: {self._env_file}")
                return False

            try:
                self._load_from_file(self._env_file)
                logger.debug(f"Loaded environment from {self._env_file}")
            except Exception as e:
                logger.error(f"Failed to load environment file {self._env_file}: {str(e)}")
                return False

        # Always load from system environment (takes precedence)
        self._load_from_system_env()

        # Validate required variables for secure environments
        if self.is_secure_environment() and not self._validate_secure_requirements():
            logger.warning("Secure environment is missing required variables")

        return True

    def _load_from_file(self, file_path: str) -> None:
        """
        Load environment variables from file.

        Args:
            file_path: Path to environment file
        """
        path = Path(file_path)

        # Handle different file formats based on extension
        if path.suffix in ['.env', '']:
            self._load_dotenv_file(path)
        elif path.suffix == '.json':
            self._load_json_file(path)
        elif path.suffix in ['.yaml', '.yml']:
            self._load_yaml_file(path)
        else:
            logger.warning(f"Unsupported environment file format: {path.suffix}")

    def _load_dotenv_file(self, file_path: Path) -> None:
        """
        Load variables from .env file format.

        Args:
            file_path: Path to .env file
        """
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Parse key-value pair
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]

                    self._vars[key] = value

    def _load_json_file(self, file_path: Path) -> None:
        """
        Load variables from JSON file.

        Args:
            file_path: Path to JSON file
        """
        with open(file_path, 'r') as f:
            data = json.load(f)

        # Flatten nested structure for environment variables
        self._flatten_dict(data)

    def _load_yaml_file(self, file_path: Path) -> None:
        """
        Load variables from YAML file.

        Args:
            file_path: Path to YAML file
        """
        try:
            import yaml
        except ImportError:
            logger.error("YAML support requires PyYAML; pip install pyyaml")
            return

        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)

        # Flatten nested structure for environment variables
        self._flatten_dict(data)

    def _flatten_dict(self, data: Dict[str, Any], prefix: str = "") -> None:
        """
        Flatten a nested dictionary structure.

        Args:
            data: Dictionary to flatten
            prefix: Prefix for nested keys
        """
        for key, value in data.items():
            flat_key = f"{prefix}_{key}" if prefix else key

            if isinstance(value, dict):
                self._flatten_dict(value, flat_key)
            else:
                self._vars[flat_key] = str(value)

    def _load_from_system_env(self) -> None:
        """Load variables from system environment."""
        # System environment takes precedence over file
        for key, value in os.environ.items():
            self._vars[key] = value

    def _detect_environment(self) -> str:
        """
        Detect the current environment based on various signals.

        Returns:
            Environment name (development, testing, staging, production, etc.)
        """
        # Check for explicit environment variable
        if 'ENVIRONMENT' in os.environ:
            return os.environ['ENVIRONMENT']

        if 'FLASK_ENV' in os.environ:
            return os.environ['FLASK_ENV']

        # Check CI/CD systems
        if any(var in os.environ for var in ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'JENKINS_URL']):
            return ENV_CI

        # Check hostname for environment hints
        hostname = socket.gethostname().lower()

        if any(hint in hostname for hint in ['prod', 'production']):
            return ENV_PRODUCTION
        elif any(hint in hostname for hint in ['staging', 'stage', 'stg']):
            return ENV_STAGING
        elif any(hint in hostname for hint in ['test']):
            return ENV_TESTING
        elif any(hint in hostname for hint in ['dev', 'development']):
            return ENV_DEVELOPMENT
        elif any(hint in hostname for hint in ['dr', 'disaster', 'recovery']):
            return ENV_DR_RECOVERY

        # Default to development
        return ENV_DEVELOPMENT

    def _validate_secure_requirements(self) -> bool:
        """
        Validate that all required variables for secure environments are set.

        Returns:
            True if all required variables are set, False otherwise
        """
        # Basic security requirements for production/staging environments
        required_vars = [
            'SECRET_KEY',
            'SESSION_KEY',
            'DATABASE_URL',
            'CSRF_SECRET_KEY'
        ]

        missing = [var for var in required_vars if not self.get(var)]

        if missing:
            logger.warning(f"Missing required secure environment variables: {', '.join(missing)}")
            return False

        return True

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get an environment variable value.

        Args:
            key: Variable name
            default: Default value if not found

        Returns:
            Variable value or default
        """
        return self._vars.get(key, default)

    def get_int(self, key: str, default: int = 0) -> int:
        """
        Get an environment variable as integer.

        Args:
            key: Variable name
            default: Default value if not found or not convertible

        Returns:
            Variable value as integer
        """
        value = self.get(key)
        if value is None:
            return default

        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning(f"Cannot convert environment variable {key}={value} to int, using default")
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Get an environment variable as boolean.

        Args:
            key: Variable name
            default: Default value if not found

        Returns:
            Variable value as boolean
        """
        value = self.get(key)
        if value is None:
            return default

        true_values = ('true', 'yes', '1', 'on')
        false_values = ('false', 'no', '0', 'off')

        if isinstance(value, str):
            if value.lower() in true_values:
                return True
            elif value.lower() in false_values:
                return False

        # Try to evaluate as boolean
        try:
            return bool(value)
        except (ValueError, TypeError):
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        """
        Get an environment variable as float.

        Args:
            key: Variable name
            default: Default value if not found or not convertible

        Returns:
            Variable value as float
        """
        value = self.get(key)
        if value is None:
            return default

        try:
            return float(value)
        except (ValueError, TypeError):
            logger.warning(f"Cannot convert environment variable {key}={value} to float, using default")
            return default

    def get_list(self, key: str, separator: str = ',', default: List = None) -> List:
        """
        Get an environment variable as list.

        Args:
            key: Variable name
            separator: List item separator
            default: Default value if not found

        Returns:
            Variable value as list
        """
        if default is None:
            default = []

        value = self.get(key)
        if not value:
            return default

        if isinstance(value, str):
            return [item.strip() for item in value.split(separator)]

        if isinstance(value, (list, tuple)):
            return list(value)

        return [value]

    def set(self, key: str, value: Any) -> None:
        """
        Set an environment variable.

        Args:
            key: Variable name
            value: Variable value
        """
        self._vars[key] = str(value)

        # Also set in os.environ for child processes
        os.environ[key] = str(value)

    def unset(self, key: str) -> None:
        """
        Unset an environment variable.

        Args:
            key: Variable name
        """
        if key in self._vars:
            del self._vars[key]

        # Also remove from os.environ
        if key in os.environ:
            del os.environ[key]

    def get_current_environment(self) -> str:
        """
        Get the current environment name.

        Returns:
            Current environment name
        """
        return self._current_env

    def set_current_environment(self, env_name: str) -> bool:
        """
        Set the current environment name.

        Args:
            env_name: New environment name

        Returns:
            True if valid environment, False otherwise
        """
        if env_name in ALLOWED_ENVIRONMENTS:
            self._current_env = env_name
            os.environ['ENVIRONMENT'] = env_name
            logger.info(f"Environment changed to: {env_name}")
            return True
        else:
            logger.warning(f"Invalid environment name: {env_name}")
            return False

    def is_production(self) -> bool:
        """Check if current environment is production."""
        return self._current_env == ENV_PRODUCTION

    def is_staging(self) -> bool:
        """Check if current environment is staging."""
        return self._current_env == ENV_STAGING

    def is_development(self) -> bool:
        """Check if current environment is development."""
        return self._current_env == ENV_DEVELOPMENT

    def is_testing(self) -> bool:
        """Check if current environment is testing."""
        return self._current_env == ENV_TESTING

    def is_dr_recovery(self) -> bool:
        """Check if current environment is disaster recovery."""
        return self._current_env == ENV_DR_RECOVERY

    def is_ci(self) -> bool:
        """Check if current environment is CI."""
        return self._current_env == ENV_CI

    def is_secure_environment(self) -> bool:
        """Check if current environment requires strict security."""
        return self._current_env in SECURE_ENVIRONMENTS

    def compare_environments(self, env_name: str) -> int:
        """
        Compare environment strictness.

        Returns:
            -1 if current environment is less strict than env_name
             0 if current environment is equal to env_name
             1 if current environment is more strict than env_name
        """
        if self._current_env == env_name:
            return 0

        try:
            current_idx = ENV_HIERARCHY.index(self._current_env)
            target_idx = ENV_HIERARCHY.index(env_name)

            return -1 if current_idx < target_idx else 1
        except ValueError:
            logger.warning(f"Cannot compare environments: {self._current_env} vs {env_name}")
            return 0

    def get_all(self, include_sensitive: bool = False) -> Dict[str, str]:
        """
        Get all environment variables.

        Args:
            include_sensitive: Whether to include sensitive values

        Returns:
            Dictionary of all variables
        """
        if include_sensitive:
            return self._vars.copy()

        # Mask sensitive values
        masked = {}
        for key, value in self._vars.items():
            if SENSITIVE_PATTERN.search(key.lower()):
                masked[key] = "********"
            else:
                masked[key] = value

        return masked

    def save(self, file_path: str) -> bool:
        """
        Save environment variables to file.

        Args:
            file_path: Path to environment file

        Returns:
            True if successful, False otherwise
        """
        try:
            path = Path(file_path)

            # Create directory if it doesn't exist
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                # Add header
                f.write(f"# Environment configuration for: {self._current_env}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                # Add each variable
                for key in sorted(self._vars.keys()):
                    # Skip sensitive values unless in development
                    if self.is_secure_environment() and SENSITIVE_PATTERN.search(key.lower()):
                        continue

                    value = self._vars[key]

                    # Quote values with spaces
                    if ' ' in value or '\n' in value:
                        value = f'"{value}"'

                    f.write(f"{key}={value}\n")

            logger.info(f"Environment saved to {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save environment to {file_path}: {str(e)}")
            return False

    def load_environment_file(self, environment: str) -> bool:
        """
        Load environment-specific configuration file.

        Args:
            environment: Environment name

        Returns:
            True if successful, False otherwise
        """
        # Try to find environment file in the standard locations
        possible_paths = [
            DEFAULT_ENV_DIR / f"{environment}.env",
            PROJECT_ROOT / f".env.{environment}",
            PROJECT_ROOT / "config" / "env" / f"{environment}.env",
            PROJECT_ROOT / "deployment" / "environments" / f"{environment}.env"
        ]

        for path in possible_paths:
            if path.exists():
                logger.debug(f"Loading environment file for {environment}: {path}")
                return self.load(str(path))

        logger.warning(f"No environment file found for {environment}")
        return False

    def setup_derived_values(self) -> None:
        """Set up derived environment values based on current settings."""
        # Set up standard environment variables if not already set
        if not self.get('ENVIRONMENT'):
            self.set('ENVIRONMENT', self._current_env)

        if not self.get('FLASK_ENV') and self.get('ENVIRONMENT'):
            self.set('FLASK_ENV', self.get('ENVIRONMENT'))

        # Set up log level if not specified
        if not self.get('LOG_LEVEL'):
            if self.is_development() or self.is_testing():
                self.set('LOG_LEVEL', 'DEBUG')
            elif self.is_staging():
                self.set('LOG_LEVEL', 'INFO')
            else:
                self.set('LOG_LEVEL', 'WARNING')


# Singleton instance for global access
_env_instance = None


def get_environment() -> Environment:
    """
    Get the global environment instance.

    Returns:
        Environment instance
    """
    global _env_instance
    if _env_instance is None:
        _env_instance = Environment()
    return _env_instance


def load_env(env_file: Optional[str] = None, environment: Optional[str] = None) -> Environment:
    """
    Load environment from file and return instance.

    Args:
        env_file: Path to environment file
        environment: Optional environment name

    Returns:
        Environment instance
    """
    env = get_environment()

    if environment:
        env.set_current_environment(environment)

    if env_file:
        env.load(env_file)
    elif environment:
        env.load_environment_file(environment)

    return env


def get_current_environment() -> str:
    """
    Get current environment name.

    Returns:
        Environment name
    """
    return get_environment().get_current_environment()


def is_production() -> bool:
    """Check if current environment is production."""
    return get_environment().is_production()


def is_development() -> bool:
    """Check if current environment is development."""
    return get_environment().is_development()


def is_secure_environment() -> bool:
    """Check if current environment requires strict security."""
    return get_environment().is_secure_environment()


def get_env(key: str, default: Any = None) -> Any:
    """
    Get environment variable.

    Args:
        key: Variable name
        default: Default value if not found

    Returns:
        Variable value or default
    """
    return get_environment().get(key, default)


def set_env(key: str, value: Any) -> None:
    """
    Set environment variable.

    Args:
        key: Variable name
        value: Variable value
    """
    get_environment().set(key, value)


def detect_environment() -> str:
    """
    Detect the current environment.

    Returns:
        Detected environment name
    """
    return Environment()._detect_environment()


# Module initialization
if __name__ != "__main__":
    # Initialize environment from system when imported
    get_environment()


# Standalone test function
def main():
    """Simple test function when script is run directly."""
    import argparse
    from datetime import datetime

    parser = argparse.ArgumentParser(
        description="Environment Manager Test",
        epilog="Example: python environment.py -e production -f .env"
    )

    parser.add_argument(
        "-e", "--environment",
        dest="environment",
        default=None,
        help="Environment (development, staging, production)"
    )
    parser.add_argument(
        "-f", "--file",
        dest="env_file",
        default=None,
        help="Path to environment file"
    )
    parser.add_argument(
        "-s", "--save",
        dest="save_file",
        default=None,
        help="Path to save environment"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        if INTERNAL_MODULES_AVAILABLE:
            Logger.setup_root_logger(level="DEBUG")
        else:
            logging.basicConfig(level=logging.DEBUG)

    try:
        # Initialize environment
        env = Environment(args.environment, args.env_file)

        print(f"Current environment: {env.get_current_environment()}")
        print(f"Is production: {env.is_production()}")
        print(f"Is development: {env.is_development()}")
        print(f"Is secure environment: {env.is_secure_environment()}")

        # Print all environment variables (excluding sensitive)
        print("\nEnvironment Variables:")
        for key, value in sorted(env.get_all().items()):
            print(f"  {key}={value}")

        # Save if requested
        if args.save_file:
            env.save(args.save_file)
            print(f"\nEnvironment saved to {args.save_file}")

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
