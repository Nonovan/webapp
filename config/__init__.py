"""
Configuration package for Cloud Infrastructure Platform.

This package centralizes configuration management with environment-specific
settings and proper handling of sensitive information.
"""

from .base import Config
from .development import DevelopmentConfig 
from .production import ProductionConfig
from .testing import TestingConfig
from .staging import StagingConfig

# Configuration registry
config_registry = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'default': DevelopmentConfig
}

def get_config(environment=None):
    """
    Get the appropriate configuration class for the specified environment.
    
    Args:
        environment: The environment name (development, production, testing, staging)
        
    Returns:
        The corresponding configuration class
    """
    if not environment:
        import os
        environment = os.environ.get('FLASK_ENV', 'default')
    
    return config_registry.get(environment, config_registry['default'])

__all__ = [
    'Config', 
    'DevelopmentConfig', 
    'ProductionConfig', 
    'TestingConfig', 
    'StagingConfig',
    'get_config'
]
