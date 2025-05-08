"""
Configuration Package for Cloud Infrastructure Platform.

This package provides configuration management for different environments
(development, testing, staging, production, CI, DR recovery), component-specific
settings, and utility functions for loading and validating configuration.

The configuration system supports environment-specific overrides, secure
file integrity monitoring, and schema validation.
"""

import os
import logging
import redis
import yaml
from typing import Dict, Any, Optional, List, Tuple, Union, Type
from functools import lru_cache
from flask import Flask, current_app
from datetime import datetime, timezone
import sys
import importlib

# Initialize logger
logger = logging.getLogger(__name__)

# Import configuration constants
from .config_constants import (
    # Environment constants
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_CI,
    ENVIRONMENT_DR_RECOVERY,
    ALLOWED_ENVIRONMENTS,
    SECURE_ENVIRONMENTS,

    # Security configuration constants
    DEFAULT_SECURITY_CONFIG,
    DEFAULT_SECURITY_HEADERS,
    DEFAULT_CSRF_CONFIG,
    DEFAULT_JWT_CONFIG,
    DEFAULT_FILE_SECURITY_CONFIG,
    DEFAULT_FILE_INTEGRITY_CONFIG,
    FILE_INTEGRITY_SEVERITY_MAPPING,
    SENSITIVE_FIELDS,

    # Monitoring/Rate limiting constants
    DEFAULT_RATE_LIMIT_CONFIG,
    DEFAULT_MONITORING_CONFIG,
    DEFAULT_AUDIT_CONFIG,

    # Required variables
    REQUIRED_ENV_VARS,
    REQUIRED_PROD_ENV_VARS,

    # Default configuration values
    DEFAULT_ENV_VALUES,
    DEFAULT_DB_CONFIG,
    DEFAULT_CACHE_CONFIG,
    DEFAULT_ICS_CONFIG,
    DEFAULT_CLOUD_CONFIG,
    DEFAULT_CSP_CONFIG,
    DEFAULT_FEATURE_FLAGS,
    DEFAULT_DR_CONFIG,

    # Environment overrides
    DEV_OVERRIDES,
    TEST_OVERRIDES,
    DR_OVERRIDES,
    CI_OVERRIDES,

    # File integrity constants
    FILE_INTEGRITY_MONITORED_PATTERNS,
    FILE_INTEGRITY_BASELINE_CONFIG,
    SMALL_FILE_THRESHOLD,
    DEFAULT_HASH_ALGORITHM
)

# Import configuration classes
from .base import Config
from .development import DevelopmentConfig
from .testing import TestingConfig
from .staging import StagingConfig
from .production import ProductionConfig
from .ci import CIConfig
from .dr_recovery import DRRecoveryConfig

# Configuration registry mapping environment names to config classes
CONFIG_REGISTRY = {
    ENVIRONMENT_DEVELOPMENT: DevelopmentConfig,
    ENVIRONMENT_TESTING: TestingConfig,
    ENVIRONMENT_STAGING: StagingConfig,
    ENVIRONMENT_PRODUCTION: ProductionConfig,
    ENVIRONMENT_CI: CIConfig,
    ENVIRONMENT_DR_RECOVERY: DRRecoveryConfig
}

@lru_cache(maxsize=8)
def get_config(env_name: str = None) -> Type[Config]:
    """
    Get the configuration class for the specified environment.

    This function retrieves the appropriate configuration class based on
    the environment name. It caches results for better performance.

    Args:
        env_name: Environment name (development, testing, production, etc.)
                 If None, uses the environment variable ENVIRONMENT or
                 defaults to 'development'

    Returns:
        Config class appropriate for the specified environment
    """
    env_name = env_name or detect_environment()

    # Normalize the name to handle various formats
    if isinstance(env_name, str):
        env_name = env_name.lower().replace('-', '_')

    # Match the normalized name to the registry
    config_class = CONFIG_REGISTRY.get(env_name)
    if not config_class:
        # Fallback to development config if an unknown environment is specified
        logger.warning(f"Unknown environment name: {env_name}, using development config")
        config_class = DevelopmentConfig

    return config_class

def get_config_instance(env_name: str = None) -> Config:
    """
    Create a configuration instance for the specified environment.

    Args:
        env_name: Environment name (development, testing, production, etc.)
                 If None, uses the environment variable ENVIRONMENT

    Returns:
        Config instance appropriate for the specified environment
    """
    config_class = get_config(env_name)
    return config_class()

def detect_environment() -> str:
    """
    Detect the current environment from environment variables.

    Returns:
        String containing the environment name (e.g., 'development', 'production')
    """
    # Check the most specific environment variable first
    environment = os.environ.get('ENVIRONMENT')

    # Alternative environment variables for compatibility
    if environment is None:
        environment = os.environ.get('FLASK_ENV') or os.environ.get('ENV')

    # Default to development if not specified
    if environment not in ALLOWED_ENVIRONMENTS:
        environment = ENVIRONMENT_DEVELOPMENT
        if os.environ.get('ENVIRONMENT') not in (None, ENVIRONMENT_DEVELOPMENT):
            logger.warning(
                f"Unknown environment '{os.environ.get('ENVIRONMENT')}', "
                f"falling back to {environment}"
            )

    return environment

def load_component_config(component_name: str, environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Load component-specific configuration based on the environment.

    This function loads configuration settings for a specific component
    (e.g., 'database', 'api', 'cache') from the components directory.
    It supports JSON, YAML, and INI formats.

    Args:
        component_name: Name of the component (e.g., 'database', 'api')
        environment: Optional environment name (defaults to detected environment)

    Returns:
        Dictionary containing component configuration settings

    Raises:
        ValueError: If the component name is invalid or the component configuration
                   cannot be loaded
    """
    from pathlib import Path
    import json
    import configparser

    if not component_name or not isinstance(component_name, str):
        raise ValueError("Component name must be a non-empty string")

    # Sanitize component name to prevent directory traversal
    component_name = os.path.basename(component_name)
    if not component_name:
        raise ValueError("Invalid component name")

    # Determine environment if not provided
    environment = environment or detect_environment()

    # Define search paths in order of precedence
    base_paths = [
        Path(__file__).parent / 'components',
        Path(__file__).parent / 'environments' / environment.lower()
    ]

    # Check supported file formats in order of precedence
    extensions = ['.json', '.ini', '.yaml', '.yml']
    component_config = {}

    # Try to load component configuration
    for base_path in base_paths:
        for ext in extensions:
            config_path = base_path / f"{component_name}{ext}"

            if config_path.exists():
                try:
                    if ext == '.json':
                        with open(config_path, 'r') as f:
                            config_data = json.load(f)
                            component_config.update(config_data)
                    elif ext == '.ini':
                        config = configparser.ConfigParser()
                        config.read(config_path)
                        # Convert ConfigParser object to dictionary
                        config_data = {
                            section: dict(config.items(section))
                            for section in config.sections()
                        }
                        component_config.update(config_data)
                    elif ext in ('.yaml', '.yml'):
                        try:
                            with open(config_path, 'r') as f:
                                config_data = yaml.safe_load(f)
                                component_config.update(config_data)
                        except ImportError:
                            logger.warning("YAML support requires PyYAML package")
                except Exception as e:
                    logger.error(f"Error loading {config_path}: {str(e)}")

    return component_config

def update_file_integrity_baseline(
        app=None,
        baseline_path=None,
        updates=None,
        remove_missing=False,
        auto_update_limit: int = 10) -> Tuple[bool, str]:
    """
    Update the file integrity baseline with new hash values.

    This function is a wrapper that forwards to the core implementation in
    core.security.cs_file_integrity, providing a convenient access point
    from the config package.

    Args:
        app: Flask application instance
        baseline_path: Path to the baseline file (uses app config if None)
        updates: List of change dictionaries to incorporate into baseline
        remove_missing: Whether to remove entries for files that no longer exist
        auto_update_limit: Maximum number of files to auto-update (safety limit)

    Returns:
        tuple: (success_bool, message_string)
    """
    # Get the app instance if not provided
    if app is None:
        app = current_app

    # Check for DR mode restrictions
    if app.config.get('DR_MODE', False) and app.config.get('DR_BASELINE_FROZEN', True):
        logger.warning("Baseline update attempted in DR mode - operation restricted")
        return False, "Baseline updates are restricted in DR recovery mode"

    # First try the implementation from core security module
    try:
        from core.security.cs_file_integrity import update_file_integrity_baseline as core_update
        return core_update(app, baseline_path, updates, remove_missing, auto_update_limit)
    except ImportError:
        logger.warning("Could not import update_file_integrity_baseline from core.security.cs_file_integrity")

    # Try to import from core utils as fallback
    try:
        from core.utils import update_file_integrity_baseline as utils_update
        return utils_update(app, baseline_path, updates, remove_missing)
    except ImportError:
        logger.warning("Could not import update_file_integrity_baseline from core.utils")

    # Fall back to the Config class implementation
    try:
        from .base import Config
        return Config.update_file_integrity_baseline(app, baseline_path, updates, remove_missing, auto_update_limit)
    except (ImportError, AttributeError):
        logger.error("No file integrity baseline update implementation available")
        return False, "File integrity functions not available"

def validate_baseline_integrity(app=None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Validate the current file integrity baseline.

    Checks whether the file integrity baseline is valid and identifies any
    violations without modifying the baseline.

    Args:
        app: Flask application instance (uses current_app if None)

    Returns:
        Tuple[bool, List[Dict]]: (integrity_status, violation_list)
    """
    # Get the app instance if not provided
    if app is None:
        app = current_app

    # Try the implementation from core security module
    try:
        from core.security.cs_file_integrity import check_critical_file_integrity
        return check_critical_file_integrity(app)
    except ImportError:
        logger.warning("Could not import check_critical_file_integrity from core.security.cs_file_integrity")

    # Try to import from security service as fallback
    try:
        from services import check_integrity
        return check_integrity()
    except ImportError:
        logger.warning("Could not import check_integrity from services")

    # Try to import from api.security as last resort
    try:
        from api.security import validate_baseline_integrity as api_validate
        return api_validate()
    except ImportError:
        logger.warning("No file integrity validation implementation available")
        return False, []

def initialize_file_monitoring(app: Flask) -> bool:
    """
    Initialize file integrity monitoring for the application.

    Sets up the baseline, monitoring intervals, and related configuration
    for tracking integrity of critical files.

    Args:
        app: Flask application instance

    Returns:
        bool: True if initialization successful, False otherwise
    """
    try:
        # Try to use the core security implementation
        from core.security.cs_file_integrity import initialize_file_monitoring as core_init

        basedir = app.root_path
        patterns = app.config.get('CRITICAL_FILES_PATTERN')
        interval = app.config.get('FILE_INTEGRITY_CHECK_INTERVAL', 3600)

        return core_init(app, basedir, patterns, interval)
    except ImportError:
        logger.warning("Could not import initialize_file_monitoring from core.security.cs_file_integrity")

        # Fall back to basic file integrity initialization
        try:
            from .base import Config
            app.config = Config.initialize_file_hashes(app.config, app.root_path)
            logger.info("Basic file integrity monitoring initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize file integrity monitoring: {e}")
            return False

def is_dr_mode_active(app=None) -> bool:
    """
    Check if the application is running in disaster recovery mode.

    Args:
        app: Flask application instance (uses current_app if None)

    Returns:
        bool: True if DR mode is active, False otherwise
    """
    if app is None:
        try:
            app = current_app
        except RuntimeError:
            # Handle case when there's no application context
            return os.environ.get('ENVIRONMENT') == ENVIRONMENT_DR_RECOVERY

    # Check explicit DR mode setting
    return (app.config.get('DR_MODE', False) or
            app.config.get('ENV') == ENVIRONMENT_DR_RECOVERY or
            app.config.get('ENVIRONMENT') == ENVIRONMENT_DR_RECOVERY)

def verify_dr_recovery_setup(app=None) -> Tuple[bool, List[str]]:
    """
    Verify that the DR recovery environment is properly configured.

    Args:
        app: Flask application instance (uses current_app if None)

    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_issues)
    """
    if app is None:
        app = current_app

    issues = []

    # Check required DR settings
    if not app.config.get('DR_MODE', False):
        issues.append("DR_MODE should be enabled")

    # Check if recovery mode is set
    if not app.config.get('RECOVERY_MODE', False):
        issues.append("RECOVERY_MODE should be enabled")

    # Check if DR coordinator email is configured
    if not app.config.get('DR_COORDINATOR_EMAIL'):
        issues.append("DR_COORDINATOR_EMAIL is not configured")

    # Check DR log path
    dr_log_path = app.config.get('DR_LOG_PATH')
    if dr_log_path:
        try:
            log_dir = os.path.dirname(dr_log_path)
            if not os.path.exists(log_dir):
                issues.append(f"DR log directory does not exist: {log_dir}")
            elif not os.access(log_dir, os.W_OK):
                issues.append(f"DR log directory is not writable: {log_dir}")
        except Exception as e:
            issues.append(f"Error checking DR log path: {str(e)}")

    # Verify file integrity monitoring is active
    if not app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
        issues.append("File integrity monitoring should be enabled in DR mode")

    return len(issues) == 0, issues

# Version information
__version__ = '0.1.1'

# Define public exports
__all__ = [
    # Core configuration classes
    'Config',
    'DevelopmentConfig',
    'ProductionConfig',
    'TestingConfig',
    'StagingConfig',
    'CIConfig',
    'DRRecoveryConfig',

    # Configuration utility functions
    'get_config',
    'get_config_instance',
    'detect_environment',
    'load_component_config',
    'update_file_integrity_baseline',
    'validate_baseline_integrity',
    'initialize_file_monitoring',
    'is_dr_mode_active',
    'verify_dr_recovery_setup',
    'CONFIG_REGISTRY',

    # Environment constants
    'ENVIRONMENT_DEVELOPMENT',
    'ENVIRONMENT_TESTING',
    'ENVIRONMENT_STAGING',
    'ENVIRONMENT_PRODUCTION',
    'ENVIRONMENT_DR_RECOVERY',
    'ENVIRONMENT_CI',
    'ALLOWED_ENVIRONMENTS',
    'SECURE_ENVIRONMENTS',

    # Security configuration constants
    'DEFAULT_SECURITY_CONFIG',
    'DEFAULT_SECURITY_HEADERS',
    'DEFAULT_CSRF_CONFIG',
    'DEFAULT_JWT_CONFIG',
    'DEFAULT_FILE_SECURITY_CONFIG',
    'DEFAULT_FILE_INTEGRITY_CONFIG',
    'FILE_INTEGRITY_SEVERITY_MAPPING',
    'SENSITIVE_FIELDS',

    # Required variables
    'REQUIRED_ENV_VARS',
    'REQUIRED_PROD_ENV_VARS',

    # Default configurations
    'DEFAULT_ENV_VALUES',
    'DEFAULT_DB_CONFIG',
    'DEFAULT_SECURITY_CONFIG',
    'DEFAULT_SECURITY_HEADERS',
    'DEFAULT_CSRF_CONFIG',
    'DEFAULT_RATE_LIMIT_CONFIG',
    'DEFAULT_JWT_CONFIG',
    'DEFAULT_CACHE_CONFIG',
    'DEFAULT_ICS_CONFIG',
    'DEFAULT_CLOUD_CONFIG',
    'DEFAULT_MONITORING_CONFIG',
    'DEFAULT_FILE_SECURITY_CONFIG',
    'DEFAULT_FILE_INTEGRITY_CONFIG',
    'DEFAULT_CSP_CONFIG',
    'DEFAULT_AUDIT_CONFIG',
    'DEFAULT_FEATURE_FLAGS',
    'DEFAULT_DR_CONFIG',

    # Environment overrides
    'DEV_OVERRIDES',
    'TEST_OVERRIDES',
    'DR_OVERRIDES',
    'CI_OVERRIDES',
    'PROD_SECURITY_REQUIREMENTS',

    # File integrity monitoring
    'FILE_INTEGRITY_MONITORED_PATTERNS',
    'FILE_INTEGRITY_BASELINE_CONFIG',
    'FILE_INTEGRITY_SEVERITY_MAPPING',
    'SENSITIVE_FIELDS',
    'SMALL_FILE_THRESHOLD',
    'DEFAULT_HASH_ALGORITHM',

    # Version
    '__version__'
]
