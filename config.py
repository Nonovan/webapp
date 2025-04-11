"""
Configuration management module for myproject.

This module defines configuration classes for different application environments,
extending the core configuration system with environment-specific settings.
It centralizes all configuration logic to ensure consistent settings across
the application and proper separation of concerns.

The module implements a hierarchical configuration approach:
1. Core base configuration from core.config.Config
2. Environment-specific overrides (development, production, testing, etc.)
3. Instance-specific settings loaded from environment variables

This structure ensures secure configuration handling, environment-specific
behavior, and flexible deployment options without hard-coding sensitive values.
"""

import os
from core.config import Config as CoreConfig

class BaseConfig(CoreConfig):
    """
    Extended configuration with environment-specific settings.

    This class extends the core configuration with additional environment-specific
    settings and provides methods to load the appropriate configuration based on
    the current environment (development, production, testing, etc.).

    The class ensures that sensitive configuration values come from environment
    variables rather than being hard-coded, improving security and enabling
    different settings in different deployment environments.

    Attributes:
        Inherits all attributes from core.config.Config
    """

    @classmethod
    def load(cls, env='development'):
        """
        Load configuration with environment-specific overrides.

        This method retrieves the base configuration from the parent class and
        then applies environment-specific overrides based on the specified
        environment name. It provides a complete configuration dictionary
        suitable for the target environment.

        Args:
            env (str): Environment name to load configuration for
                       (development, production, testing, staging, ci)
                       Defaults to 'development'.

        Returns:
            dict: Complete configuration dictionary with environment-specific settings

        Example:
            # Load production configuration
            config = BaseConfig.load('production')
            app.config.update(config)
        """
        # Get base config
        base_configuration = super().load()

        # Add environment-specific overrides
        env_config = {
            'development': {
                'DEBUG': True,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DEV_DATABASE_URL')
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL')
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
            },
            'staging': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'CACHE_TYPE': 'redis',
                'SQLALCHEMY_DATABASE_URI': os.getenv('STAGING_DATABASE_URL'),
                'CELERY_BROKER_URL': os.getenv('STAGING_REDIS_URL'),
                'SENTRY_ENVIRONMENT': 'staging'
            },
            'ci': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'CACHE_TYPE': 'simple',
                'CELERY_ALWAYS_EAGER': True,
                'SQLALCHEMY_DATABASE_URI': 'postgresql://ci:ci@localhost/ci_test'
            }
        }

        # Update base config with environment settings
        base_configuration.update(env_config.get(env, env_config['development']))
        return base_configuration

config = BaseConfig
"""
Configuration object for easy import.

This provides a convenient shorthand for importing the configuration class.

Example:
    from config import config
    app_config = config.load('production')
"""
