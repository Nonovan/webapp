#!/usr/bin/env python3
# filepath: scripts/core/env_manager.py
"""
Environment Manager for Cloud Infrastructure Platform Scripts

This module provides a wrapper around core.environment functionality for script usage,
adding script-specific environment management features while maintaining compatibility
with the core environment module. It enables scripts to interact with the main
application's environment system while adding specialized functionality for
automation and CI/CD operations.

Key features:
- Integration with core.environment module
- Script-specific environment detection and management
- Environment variable validation for scripts
- Environment file creation and manipulation
- Environment comparison and transition utilities
- Secure credential handling for automation scripts
"""

import os
import sys
import re
import json
import logging
import tempfile
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Set, Tuple, cast

# Ensure the project root is in path for imports
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

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

# Import config loader if available for additional configuration
try:
    from scripts.core.config_loader import load_config, ConfigLoader
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    CONFIG_LOADER_AVAILABLE = False
    logger.debug("Config loader not available, using basic environment functionality")

# Try to import core environment module
try:
    from core.environment import (
        Environment, get_environment, load_env, get_current_environment,
        is_production, is_development, is_secure_environment,
        get_env, set_env, detect_environment,
        ENV_DEVELOPMENT, ENV_TESTING, ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY, ENV_CI,
        ALLOWED_ENVIRONMENTS, SECURE_ENVIRONMENTS
    )
    CORE_ENV_AVAILABLE = True
except ImportError:
    logger.warning("Core environment module not available, using fallback implementation")
    CORE_ENV_AVAILABLE = False

    # Define fallback constants if core module not available
    ENV_DEVELOPMENT = "development"
    ENV_TESTING = "testing"
    ENV_STAGING = "staging"
    ENV_PRODUCTION = "production"
    ENV_DR_RECOVERY = "dr-recovery"
    ENV_CI = "ci"
    ALLOWED_ENVIRONMENTS = {ENV_DEVELOPMENT, ENV_TESTING, ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY, ENV_CI}
    SECURE_ENVIRONMENTS = {ENV_STAGING, ENV_PRODUCTION, ENV_DR_RECOVERY}

# Constants
DEFAULT_ENV_DIR = PROJECT_ROOT / "config" / "env"
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
SCRIPT_ENV_DIR = PROJECT_ROOT / "scripts" / "config" / "env"

# Pattern for sensitive values that should be masked in logs
SENSITIVE_PATTERN = re.compile(
    r'(password|secret|key|token|credential|auth|private|cert)',
    re.IGNORECASE
)

# Script-specific environment variables
SCRIPT_ENV_VARS = {
    "SCRIPT_LOG_LEVEL": "INFO",
    "SCRIPT_TIMEOUT": "3600",  # Default timeout in seconds
    "SCRIPT_DRY_RUN": "false",
    "SCRIPT_VERBOSE": "false",
    "SCRIPT_FORCE": "false",
}


class EnvironmentError(Exception):
    """Exception raised for environment-related errors."""
    pass


class EnvironmentManager:
    """
    Script-specific environment manager that wraps core.environment functionality.

    This class provides an interface to the core environment module with additional
    functionality specific to automation scripts, CI/CD pipelines, and system operations.
    """

    def __init__(self,
                env_name: Optional[str] = None,
                env_file: Optional[str] = None,
                script_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the environment manager.

        Args:
            env_name: Optional environment name
            env_file: Optional path to environment file
            script_config: Optional script-specific configuration
        """
        self.script_config = script_config or {}

        # Initialize core environment if available
        if CORE_ENV_AVAILABLE:
            self.env = get_environment()
            if env_name:
                self.env.set_current_environment(env_name)
            if env_file:
                self.env.load(env_file)
        else:
            # Fallback implementation if core environment not available
            self._implement_fallback(env_name, env_file)

        # Set script-specific defaults
        self._set_script_defaults()
        logger.debug(f"Script environment manager initialized for {self.get_current_environment()}")

    def _implement_fallback(self, env_name: Optional[str], env_file: Optional[str]) -> None:
        """
        Implement fallback environment functionality when core module is unavailable.

        Args:
            env_name: Environment name
            env_file: Path to environment file
        """
        self._vars = {}
        self._current_env = env_name or self._detect_environment_fallback()

        # Load environment variables
        if env_file:
            self._load_from_file_fallback(env_file)

        # Always load system environment variables
        for key, value in os.environ.items():
            self._vars[key] = value

    def _detect_environment_fallback(self) -> str:
        """
        Fallback method to detect the current environment.

        Returns:
            Detected environment name
        """
        if 'ENVIRONMENT' in os.environ:
            return os.environ['ENVIRONMENT']
        elif 'FLASK_ENV' in os.environ:
            return os.environ['FLASK_ENV']
        elif any(var in os.environ for var in ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'JENKINS_URL']):
            return ENV_CI
        else:
            return ENV_DEVELOPMENT

    def _load_from_file_fallback(self, file_path: str) -> None:
        """
        Load environment variables from file in fallback mode.

        Args:
            file_path: Path to environment file
        """
        try:
            path = Path(file_path)
            if not path.exists():
                logger.warning(f"Environment file not found: {file_path}")
                return

            # Simple .env parser for fallback
            with open(path, 'r') as f:
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

        except Exception as e:
            logger.error(f"Failed to load environment file {file_path}: {str(e)}")

    def _set_script_defaults(self) -> None:
        """Set default values for script-specific environment variables."""
        for key, default_value in SCRIPT_ENV_VARS.items():
            # Only set if not already defined
            if not self.get(key):
                self.set(key, default_value)

        # Set appropriate log level based on environment if not explicitly set
        if not self.get('SCRIPT_LOG_LEVEL'):
            if self.is_development():
                self.set('SCRIPT_LOG_LEVEL', 'DEBUG')
            elif self.is_testing():
                self.set('SCRIPT_LOG_LEVEL', 'INFO')
            else:
                self.set('SCRIPT_LOG_LEVEL', 'WARNING')

    def get_current_environment(self) -> str:
        """
        Get the current environment name.

        Returns:
            Current environment name
        """
        if CORE_ENV_AVAILABLE:
            return self.env.get_current_environment()
        return self._current_env

    def set_current_environment(self, env_name: str) -> bool:
        """
        Set the current environment name.

        Args:
            env_name: New environment name

        Returns:
            True if valid environment, False otherwise
        """
        if CORE_ENV_AVAILABLE:
            return self.env.set_current_environment(env_name)

        if env_name in ALLOWED_ENVIRONMENTS:
            self._current_env = env_name
            os.environ['ENVIRONMENT'] = env_name
            logger.info(f"Environment changed to: {env_name}")
            return True
        else:
            logger.warning(f"Invalid environment name: {env_name}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get an environment variable value.

        Args:
            key: Variable name
            default: Default value if not found

        Returns:
            Variable value or default
        """
        if CORE_ENV_AVAILABLE:
            return self.env.get(key, default)
        return self._vars.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set an environment variable.

        Args:
            key: Variable name
            value: Variable value
        """
        if CORE_ENV_AVAILABLE:
            self.env.set(key, value)
        else:
            self._vars[key] = str(value)
            os.environ[key] = str(value)

    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Get an environment variable as boolean.

        Args:
            key: Variable name
            default: Default value if not found

        Returns:
            Variable value as boolean
        """
        if CORE_ENV_AVAILABLE:
            return self.env.get_bool(key, default)

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

        try:
            return bool(value)
        except (ValueError, TypeError):
            return default

    def get_int(self, key: str, default: int = 0) -> int:
        """
        Get an environment variable as integer.

        Args:
            key: Variable name
            default: Default value if not found or not convertible

        Returns:
            Variable value as integer
        """
        if CORE_ENV_AVAILABLE:
            return self.env.get_int(key, default)

        value = self.get(key)
        if value is None:
            return default

        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning(f"Cannot convert environment variable {key}={value} to int, using default")
            return default

    def get_list(self, key: str, separator: str = ',', default: Optional[List] = None) -> List:
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

        if CORE_ENV_AVAILABLE:
            return self.env.get_list(key, separator, default)

        value = self.get(key)
        if not value:
            return default

        if isinstance(value, str):
            return [item.strip() for item in value.split(separator)]

        if isinstance(value, (list, tuple)):
            return list(value)

        return [value]

    def is_production(self) -> bool:
        """Check if current environment is production."""
        if CORE_ENV_AVAILABLE:
            return self.env.is_production()
        return self.get_current_environment() == ENV_PRODUCTION

    def is_development(self) -> bool:
        """Check if current environment is development."""
        if CORE_ENV_AVAILABLE:
            return self.env.is_development()
        return self.get_current_environment() == ENV_DEVELOPMENT

    def is_testing(self) -> bool:
        """Check if current environment is testing."""
        if CORE_ENV_AVAILABLE:
            return self.env.is_testing()
        return self.get_current_environment() == ENV_TESTING

    def is_secure_environment(self) -> bool:
        """Check if current environment requires strict security."""
        if CORE_ENV_AVAILABLE:
            return self.env.is_secure_environment()
        return self.get_current_environment() in SECURE_ENVIRONMENTS

    def save(self, file_path: str, include_sensitive: bool = False) -> bool:
        """
        Save environment variables to file.

        Args:
            file_path: Path to environment file
            include_sensitive: Whether to include sensitive values

        Returns:
            True if successful, False otherwise
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                # Add header
                f.write(f"# Environment configuration for: {self.get_current_environment()}\n")
                f.write(f"# Generated by scripts/core/env_manager.py\n\n")

                # Add environment type
                f.write(f"ENVIRONMENT={self.get_current_environment()}\n\n")

                # Get variables to write
                if CORE_ENV_AVAILABLE:
                    vars_to_write = self.env.get_all(include_sensitive=include_sensitive)
                else:
                    vars_to_write = self._get_masked_vars(include_sensitive)

                # Write variables
                for key, value in sorted(vars_to_write.items()):
                    # Skip environment already written above
                    if key == "ENVIRONMENT":
                        continue

                    # Quote values with spaces
                    if isinstance(value, str) and (' ' in value or '\n' in value):
                        value = f'"{value}"'

                    f.write(f"{key}={value}\n")

            logger.info(f"Environment saved to {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save environment to {file_path}: {str(e)}")
            return False

    def _get_masked_vars(self, include_sensitive: bool) -> Dict[str, str]:
        """
        Get environment variables with sensitive values optionally masked.

        Args:
            include_sensitive: Whether to include sensitive values

        Returns:
            Dictionary of variables
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

    def load_from_config(self, config_name: str, environment: Optional[str] = None) -> bool:
        """
        Load environment from a named configuration.

        Args:
            config_name: Configuration name (e.g., 'database', 'security')
            environment: Optional environment override

        Returns:
            True if successful, False otherwise
        """
        if not CONFIG_LOADER_AVAILABLE:
            logger.error("Config loader not available, cannot load from config")
            return False

        try:
            # Determine environment
            env = environment or self.get_current_environment()

            # Load configuration
            config = load_config(f"{config_name}.yaml", environment=env)
            if not config:
                logger.warning(f"No configuration found for {config_name}")
                return False

            # Extract environment variables section if available
            env_vars = config.get("environment_variables", {})
            if not env_vars:
                logger.debug(f"No environment variables defined in {config_name}")
                return False

            # Set environment variables
            for key, value in env_vars.items():
                self.set(key, value)

            logger.info(f"Loaded environment from {config_name} configuration")
            return True

        except Exception as e:
            logger.error(f"Failed to load environment from config {config_name}: {str(e)}")
            return False

    def create_temp_env_file(self, include_sensitive: bool = False) -> str:
        """
        Create a temporary environment file.

        Args:
            include_sensitive: Whether to include sensitive values

        Returns:
            Path to temporary file
        """
        temp_file = tempfile.mktemp(suffix=".env")

        if self.save(temp_file, include_sensitive):
            return temp_file

        raise EnvironmentError("Failed to create temporary environment file")

    def is_dry_run(self) -> bool:
        """Check if script is in dry run mode."""
        return self.get_bool('SCRIPT_DRY_RUN', False)

    def is_verbose(self) -> bool:
        """Check if script is in verbose mode."""
        return self.get_bool('SCRIPT_VERBOSE', False)

    def is_force(self) -> bool:
        """Check if script is in force mode."""
        return self.get_bool('SCRIPT_FORCE', False)

    def get_script_timeout(self) -> int:
        """Get script execution timeout in seconds."""
        return self.get_int('SCRIPT_TIMEOUT', 3600)

    def get_script_log_level(self) -> str:
        """Get script log level."""
        return self.get('SCRIPT_LOG_LEVEL', 'INFO')

    def find_environment_file(self, environment: Optional[str] = None) -> Optional[str]:
        """
        Find environment file for the specified environment.

        Args:
            environment: Environment name (defaults to current environment)

        Returns:
            Path to environment file if found, None otherwise
        """
        env = environment or self.get_current_environment()

        # Check standard locations
        possible_paths = [
            DEFAULT_ENV_DIR / f"{env}.env",
            PROJECT_ROOT / f".env.{env}",
            PROJECT_ROOT / "config" / "env" / f"{env}.env",
            PROJECT_ROOT / "deployment" / "environments" / f"{env}.env",
            SCRIPT_ENV_DIR / f"{env}.env"
        ]

        for path in possible_paths:
            if path.exists():
                logger.debug(f"Found environment file: {path}")
                return str(path)

        logger.debug(f"No environment file found for {env}")
        return None

    def validate_required_vars(self, required_vars: List[str]) -> Tuple[bool, List[str]]:
        """
        Validate that required environment variables are set.

        Args:
            required_vars: List of required variable names

        Returns:
            Tuple of (success, missing_vars)
        """
        missing = [var for var in required_vars if not self.get(var)]

        if missing:
            logger.warning(f"Missing required environment variables: {', '.join(missing)}")
            return False, missing

        return True, []


# Module-level functions for convenience

_manager_instance = None

def get_manager() -> EnvironmentManager:
    """
    Get the global environment manager instance.

    Returns:
        Environment manager instance
    """
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = EnvironmentManager()
    return _manager_instance

def initialize_environment(env_file: Optional[str] = None,
                         environment: Optional[str] = None) -> EnvironmentManager:
    """
    Initialize environment manager with file and/or environment name.

    Args:
        env_file: Path to environment file
        environment: Environment name

    Returns:
        Environment manager instance
    """
    manager = get_manager()

    if environment:
        manager.set_current_environment(environment)

    if env_file:
        if CORE_ENV_AVAILABLE:
            load_env(env_file=env_file)
        else:
            # Use fallback loading in manager
            manager._load_from_file_fallback(env_file)
    elif environment and not env_file:
        # Try to find and load environment file for the specified environment
        env_file = manager.find_environment_file(environment)
        if env_file:
            if CORE_ENV_AVAILABLE:
                load_env(env_file=env_file)
            else:
                # Use fallback loading in manager
                manager._load_from_file_fallback(env_file)

    return manager

def is_production() -> bool:
    """
    Check if current environment is production.

    Returns:
        True if production environment
    """
    return get_manager().is_production()

def is_development() -> bool:
    """
    Check if current environment is development.

    Returns:
        True if development environment
    """
    return get_manager().is_development()

def is_secure_environment() -> bool:
    """
    Check if current environment requires strict security.

    Returns:
        True if secure environment
    """
    return get_manager().is_secure_environment()

def get_current_environment() -> str:
    """
    Get current environment name.

    Returns:
        Current environment name
    """
    return get_manager().get_current_environment()

def get_env_value(key: str, default: Any = None) -> Any:
    """
    Get environment variable value.

    Args:
        key: Variable name
        default: Default value if not found

    Returns:
        Variable value or default
    """
    return get_manager().get(key, default)

def set_env_value(key: str, value: Any) -> None:
    """
    Set environment variable value.

    Args:
        key: Variable name
        value: Variable value
    """
    get_manager().set(key, value)

def create_environment_file(variables: Dict[str, Any], file_path: str) -> bool:
    """
    Create a new environment file with specified variables.

    Args:
        variables: Dictionary of variables to include
        file_path: Path to create file at

    Returns:
        True if successful, False otherwise
    """
    try:
        manager = get_manager()

        # Add each variable
        for key, value in variables.items():
            manager.set(key, value)

        # Save to file
        return manager.save(file_path)

    except Exception as e:
        logger.error(f"Failed to create environment file: {str(e)}")
        return False

def validate_environment(env_name: str) -> bool:
    """
    Validate environment name.

    Args:
        env_name: Environment name to validate

    Returns:
        True if valid environment name
    """
    return env_name in ALLOWED_ENVIRONMENTS


def setup_script_environment(config_name: Optional[str] = None,
                            env_file: Optional[str] = None,
                            environment: Optional[str] = None) -> EnvironmentManager:
    """
    Set up script environment with configuration, environment file, and environment name.

    Args:
        config_name: Optional configuration name to load
        env_file: Optional path to environment file
        environment: Optional environment name

    Returns:
        Environment manager instance
    """
    # Initialize environment
    manager = initialize_environment(env_file, environment)

    # Apply environment-specific script settings
    if manager.is_development() or manager.is_testing():
        manager.set('SCRIPT_LOG_LEVEL', 'DEBUG')
    elif manager.is_production():
        manager.set('SCRIPT_LOG_LEVEL', 'WARNING')

    # Load configuration if specified
    if config_name and CONFIG_LOADER_AVAILABLE:
        manager.load_from_config(config_name)

    return manager


def main() -> int:
    """Main function when run directly."""
    parser = argparse.ArgumentParser(
        description="Environment Manager",
        epilog="Use this tool to manage environment variables for scripts"
    )

    parser.add_argument(
        "-e", "--environment",
        dest="environment",
        help="Environment name (development, staging, production)"
    )
    parser.add_argument(
        "-f", "--file",
        dest="env_file",
        help="Path to environment file"
    )
    parser.add_argument(
        "-s", "--save",
        dest="save_file",
        help="Save environment to file"
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show environment variables (excluding sensitive)"
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all environment variables (including sensitive)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show environment status"
    )

    args = parser.parse_args()

    try:
        # Setup logging
        if args.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        # Initialize environment
        manager = initialize_environment(args.env_file, args.environment)

        if args.status:
            print(f"Environment: {manager.get_current_environment()}")
            print(f"Core module available: {CORE_ENV_AVAILABLE}")
            print(f"Config loader available: {CONFIG_LOADER_AVAILABLE}")
            print(f"Is production: {manager.is_production()}")
            print(f"Is development: {manager.is_development()}")
            print(f"Is secure environment: {manager.is_secure_environment()}")
            print(f"Script log level: {manager.get_script_log_level()}")
            print(f"Script timeout: {manager.get_script_timeout()} seconds")

        if args.show or args.show_all:
            include_sensitive = args.show_all
            if CORE_ENV_AVAILABLE:
                variables = manager.env.get_all(include_sensitive=include_sensitive)
            else:
                variables = manager._get_masked_vars(include_sensitive)

            print("\nEnvironment Variables:")
            for key in sorted(variables.keys()):
                print(f"  {key}={variables[key]}")

        if args.save_file:
            success = manager.save(args.save_file)
            if success:
                print(f"Environment saved to {args.save_file}")
            else:
                print(f"Failed to save environment to {args.save_file}")
                return 1

        return 0

    except Exception as e:
        print(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
