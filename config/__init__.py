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
from typing import Dict, Any, Optional, List, Tuple, Union
from functools import lru_cache
from flask import Flask, current_app

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
def get_config(env_name: str = None) -> type:
    """
    Get the configuration class for the specified environment.

    Args:
        env_name: Environment name (development, testing, staging, production, ci, dr-recovery)

    Returns:
        Configuration class

    Raises:
        ValueError: If the environment name is invalid
    """
    if env_name is None:
        env_name = detect_environment()

    env_name = env_name.lower()
    if env_name not in CONFIG_REGISTRY:
        valid_envs = ", ".join(sorted(CONFIG_REGISTRY.keys()))
        raise ValueError(f"Invalid environment: '{env_name}'. Must be one of: {valid_envs}")

    return CONFIG_REGISTRY[env_name]

def get_config_instance(env_name: str = None) -> Config:
    """
    Get a configuration class instance for the specified environment.

    Args:
        env_name: Environment name (development, testing, staging, production, ci, dr-recovery)

    Returns:
        Configuration class instance
    """
    config_class = get_config(env_name)
    return config_class()

def detect_environment() -> str:
    """
    Detect the current environment from environment variables.

    The function checks for FLASK_ENV, ENVIRONMENT, or APP_ENV environment variables
    in that order. If none are found, it defaults to development.

    Returns:
        Environment name (development, testing, staging, production, ci, dr-recovery)
    """
    # Check various environment variables
    for env_var in ['FLASK_ENV', 'ENVIRONMENT', 'APP_ENV']:
        env = os.environ.get(env_var)
        if env:
            if env.lower() in ALLOWED_ENVIRONMENTS:
                return env.lower()
            logger.warning(f"Unknown environment '{env}' specified in {env_var}")

    # Default to development if no environment is specified
    return ENVIRONMENT_DEVELOPMENT

def load_component_config(component_name: str, environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration for a specific component.

    Args:
        component_name: Name of the component (e.g. 'database', 'api', 'security')
        environment: Environment name (defaults to the current environment)

    Returns:
        Component configuration dictionary
    """
    if environment is None:
        environment = detect_environment()

    # First try environment-specific component config
    config_path = os.path.join(
        os.path.dirname(__file__),
        'components',
        'environments',
        environment,
        f'{component_name}.ini'
    )

    if not os.path.exists(config_path):
        # Fall back to default component config
        config_path = os.path.join(
            os.path.dirname(__file__),
            'components',
            f'{component_name}.ini'
        )

    if not os.path.exists(config_path):
        logger.warning(f"No configuration file found for component '{component_name}'")
        return {}

    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(config_path)

        # Convert to dictionary
        result = {}
        for section in config.sections():
            result[section] = {}
            for key, value in config.items(section):
                result[section][key] = value

        return result
    except Exception as e:
        logger.error(f"Error loading component configuration '{component_name}': {e}")
        return {}

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
    # Try the implementation from core security module
    try:
        from core.security.cs_file_integrity import check_critical_file_integrity
        return check_critical_file_integrity(app or current_app)
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
    Check if the application is running in Disaster Recovery mode.

    Args:
        app: Flask application instance (uses current_app if None)

    Returns:
        bool: True if DR mode is active
    """
    if app is None:
        try:
            app = current_app
        except RuntimeError:
            # Outside of app context, check environment
            return detect_environment() == ENVIRONMENT_DR_RECOVERY

    # Check if DR_MODE is explicitly set to True
    return app.config.get('DR_MODE', False) is True

def verify_dr_recovery_setup(app=None) -> Tuple[bool, List[str]]:
    """
    Verify disaster recovery configuration is properly set up.

    Checks critical DR settings and ensures necessary components are
    configured correctly for disaster recovery.

    Args:
        app: Flask application instance (uses current_app if None)

    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_issues)
    """
    issues = []

    if app is None:
        try:
            app = current_app
        except RuntimeError:
            return False, ["No application context available for verification"]

    # Verify essential DR settings
    if not app.config.get('DR_MODE', False):
        issues.append("DR_MODE not enabled")

    if not app.config.get('DR_COORDINATOR_EMAIL'):
        issues.append("DR_COORDINATOR_EMAIL not configured")

    if not app.config.get('DR_LOG_PATH'):
        issues.append("DR_LOG_PATH not configured")

    if app.config.get('AUTO_UPDATE_BASELINE', False):
        issues.append("AUTO_UPDATE_BASELINE should be disabled in DR mode")

    # Verify DR log directory exists and is writable
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
