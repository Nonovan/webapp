"""
Configuration package for Cloud Infrastructure Platform.

This package centralizes configuration management with environment-specific
settings and proper handling of sensitive information. It provides a unified
interface for accessing configuration based on the current environment.
"""

import os
from typing import Optional, Type

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


# Version information
__version__ = '1.2.0'

# Define public exports
__all__ = [
    'Config',
    'DevelopmentConfig',
    'ProductionConfig',
    'TestingConfig',
    'StagingConfig',
    'CIConfig',
    'get_config',
    'get_config_instance',
    'detect_environment',
    'CONFIG_REGISTRY'
]
