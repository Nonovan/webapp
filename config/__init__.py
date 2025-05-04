"""
Configuration package for Cloud Infrastructure Platform.

This package centralizes configuration management with environment-specific
settings and proper handling of sensitive information. It provides a unified
interface for accessing configuration based on the current environment.
"""

import os
from typing import Optional, Type, Dict, Any

from .base import Config
from .environments import (
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    StagingConfig,
    CIConfig,
    detect_environment,
    get_environment_config
)

# Import key constants from config_constants module
from .config_constants import (
    # Environment constants
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY,
    ENVIRONMENT_CI,
    ALLOWED_ENVIRONMENTS,
    SECURE_ENVIRONMENTS,

    # Required variables
    REQUIRED_ENV_VARS,
    REQUIRED_PROD_ENV_VARS,

    # Default configurations
    DEFAULT_ENV_VALUES,
    DEFAULT_DB_CONFIG,
    DEFAULT_SECURITY_CONFIG,
    DEFAULT_SECURITY_HEADERS,
    DEFAULT_CSRF_CONFIG,
    DEFAULT_RATE_LIMIT_CONFIG,
    DEFAULT_JWT_CONFIG,
    DEFAULT_CACHE_CONFIG,
    DEFAULT_ICS_CONFIG,
    DEFAULT_CLOUD_CONFIG,
    DEFAULT_MONITORING_CONFIG,
    DEFAULT_FILE_SECURITY_CONFIG,
    DEFAULT_FILE_INTEGRITY_CONFIG,
    DEFAULT_CSP_CONFIG,
    DEFAULT_AUDIT_CONFIG,
    DEFAULT_FEATURE_FLAGS,

    # Environment-specific overrides
    DEV_OVERRIDES,
    TEST_OVERRIDES,
    PROD_SECURITY_REQUIREMENTS,

    # File integrity monitoring
    FILE_INTEGRITY_MONITORED_PATTERNS,
    FILE_INTEGRITY_BASELINE_CONFIG,
    FILE_INTEGRITY_SEVERITY_MAPPING,
    SENSITIVE_FIELDS,
    SMALL_FILE_THRESHOLD,
    DEFAULT_HASH_ALGORITHM
)

# Configuration registry
CONFIG_REGISTRY = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'ci': CIConfig,
    'default': DevelopmentConfig
}

def get_config(environment: Optional[str] = None) -> Type[Config]:
    """
    Get the appropriate configuration class for the specified environment.

    This function returns the configuration class appropriate for the requested
    environment. If no environment is specified, it will attempt to detect the
    environment from the APP_ENV or FLASK_ENV environment variable, falling back
    to 'default' if neither is set.

    Args:
        environment: The environment name (development, production, testing, staging, ci)

    Returns:
        The corresponding configuration class (not an instance)

    Example:
        config_class = get_config('production')
        app.config.from_object(config_class)
    """
    if not environment:
        environment = os.environ.get('APP_ENV') or os.environ.get('FLASK_ENV', 'default')

    return CONFIG_REGISTRY.get(environment.lower(), CONFIG_REGISTRY['default'])


def get_config_instance(environment: Optional[str] = None) -> Config:
    """
    Get an instantiated configuration object for the specified environment.

    This function returns a configuration instance for the requested environment.
    If no environment is specified, it will attempt to detect the current environment.

    Args:
        environment: The environment name (development, production, testing, staging, ci)

    Returns:
        An instance of the corresponding configuration class

    Example:
        config = get_config_instance()
        app.config.update(config.__dict__)
    """
    return get_environment_config(environment)


def load_component_config(component_name: str, environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration for a specific component with optional environment override.

    This function loads and merges component configuration from the components directory,
    applying any environment-specific overrides.

    Args:
        component_name: The name of the component (e.g., 'logging', 'security', 'database')
        environment: Optional environment name to load environment-specific overrides

    Returns:
        A dictionary containing the merged configuration

    Example:
        logging_config = load_component_config('logging', 'production')
        setup_logging(logging_config)
    """
    # Import here to avoid circular imports
    from .components import load_component_config as _load_component

    if not environment:
        environment = detect_environment()

    return _load_component(component_name, environment)


def update_file_integrity_baseline(
        app=None,
        baseline_path=None,
        updates=None,
        remove_missing=False) -> bool:
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

    Returns:
        bool: True if the baseline was successfully updated, False otherwise
    """
    # Import the actual implementation from core security module
    try:
        from core.security.cs_file_integrity import update_file_integrity_baseline as core_update
        return core_update(app, baseline_path, updates, remove_missing)
    except ImportError:
        import logging
        logging.warning("Could not import update_file_integrity_baseline from core.security.cs_file_integrity")
        return False


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

    # Configuration utility functions
    'get_config',
    'get_config_instance',
    'detect_environment',
    'load_component_config',
    'update_file_integrity_baseline',
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

    # Environment-specific overrides
    'DEV_OVERRIDES',
    'TEST_OVERRIDES',
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
