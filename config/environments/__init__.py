"""
Environment configuration management for Cloud Infrastructure Platform.

This module handles environment detection, configuration loading,
and exposes the appropriate configuration classes for different
environments (development, staging, production, etc).
"""

import os
import sys
import socket
from typing import Optional, Dict, Any, List

# Import the configuration classes
from config.base import Config
from config.development import DevelopmentConfig
from config.staging import StagingConfig
from config.production import ProductionConfig
from config.testing import TestingConfig
from config.ci import CIConfig

# Configuration registry
CONFIG_REGISTRY = {
    'development': DevelopmentConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'ci': CIConfig,
    'default': DevelopmentConfig
}

# Environment detection constants
ENVIRONMENT_VAR = 'APP_ENV'
FLASK_ENVIRONMENT_VAR = 'FLASK_ENV'
DEFAULT_ENVIRONMENT = 'development'

# Environment-specific host patterns - used for automatic detection
HOST_PATTERNS = {
    'production': ['prod', 'production', 'prd'],
    'staging': ['staging', 'stage', 'stg'],
    'testing': ['test', 'testing', 'tst'],
    'ci': ['ci', 'continuous-integration'],
    'development': ['dev', 'development', 'local']
}


def detect_environment() -> str:
    """
    Detect the current environment based on environment variables,
    hostname patterns, or other system indicators.

    The detection follows this order of precedence:
    1. APP_ENV environment variable
    2. FLASK_ENV environment variable
    3. Hostname pattern matching
    4. Default to 'development'

    Returns:
        str: The detected environment name
    """
    # Check environment variables in order of precedence
    env = os.environ.get(ENVIRONMENT_VAR) or os.environ.get(FLASK_ENVIRONMENT_VAR)
    if env and env in CONFIG_REGISTRY:
        return env

    # Check hostname for environment indicators
    hostname = socket.gethostname().lower()

    for env_name, patterns in HOST_PATTERNS.items():
        for pattern in patterns:
            if pattern in hostname:
                return env_name

    # Check for other indicators (e.g., CI system environment variables)
    if os.environ.get('CI') == 'true' or os.environ.get('CONTINUOUS_INTEGRATION') == 'true':
        return 'ci'

    # Default to development
    return DEFAULT_ENVIRONMENT


def get_environment(environment: Optional[str] = None) -> str:
    """
    Get the current environment name, with an option to override.

    Args:
        environment: Optional environment name to override auto-detection

    Returns:
        str: The environment name to use
    """
    if environment and environment in CONFIG_REGISTRY:
        return environment

    return detect_environment()


def get_environment_config(environment: Optional[str] = None) -> Config:
    """
    Get the configuration class for the specified environment.

    Args:
        environment: Optional environment name (development, production, etc.)

    Returns:
        Config: The corresponding configuration class instance
    """
    env_name = get_environment(environment)
    config_class = CONFIG_REGISTRY.get(env_name, CONFIG_REGISTRY['default'])
    return config_class()


# Export configuration classes
__all__ = [
    'DevelopmentConfig',
    'StagingConfig',
    'ProductionConfig',
    'TestingConfig',
    'CIConfig',
    'detect_environment',
    'get_environment',
    'get_environment_config'
]
