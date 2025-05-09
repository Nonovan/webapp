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
from datetime import timedelta
from typing import Dict, Any, Optional
from pathlib import Path
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

        # File integrity monitoring settings (common across environments)
        file_integrity_config = {
            'ENABLE_FILE_INTEGRITY_MONITORING': True,
            'FILE_HASH_ALGORITHM': 'sha256',
            'FILE_INTEGRITY_CHECK_INTERVAL': 3600,  # 1 hour
            'BASELINE_BACKUP_ENABLED': True,
            'BASELINE_PATH_TEMPLATE': 'instance/security/baseline_{environment}.json',
            'BASELINE_BACKUP_PATH_TEMPLATE': 'instance/security/baseline_backups/{timestamp}_{environment}.json',
            'BASELINE_UPDATE_MAX_FILES': 50,
            'BASELINE_UPDATE_CRITICAL_THRESHOLD': 5,
            'BASELINE_UPDATE_RETENTION': 5
        }

        # Add file integrity settings to base config
        base_configuration.update(file_integrity_config)

        # Add environment-specific overrides
        env_config = {
            'development': {
                'DEBUG': True,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DEV_DATABASE_URL'),
                # Development-specific file integrity settings
                'AUTO_UPDATE_BASELINE': True,  # Auto-update in development only
                'FILE_INTEGRITY_DEBUG': True,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': False,
                'CRITICAL_FILES_PATTERN': [
                    "*.py",                  # Python source files
                    "config/*.py",           # Configuration files
                    "config/*.ini",          # INI configuration files
                    "core/security/*.py"     # Core security components
                ]
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL'),
                # Production-specific file integrity settings
                'AUTO_UPDATE_BASELINE': False,  # Disabled in production for security
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
                'CHECK_FILE_SIGNATURES': True,
                'CRITICAL_FILES_PATTERN': [
                    "*.py",                    # All Python files
                    "config/*.py",             # Configuration files
                    "config/*.ini",            # INI configuration files
                    "config/*.json",           # JSON configuration files
                    "core/security/*.py",      # Security components
                    "core/middleware.py",      # Security middleware
                    "app.py",                  # Main application entry point
                    "models/security/*.py",    # Security models
                    "services/security*.py",   # Security services
                    "api/security/*.py",       # Security API endpoints
                ]
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
                # Testing-specific file integrity settings
                'ENABLE_FILE_INTEGRITY_MONITORING': False,  # Disabled for faster tests
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_BACKUP_ENABLED': False,
                'FILE_HASH_ALGORITHM': 'sha256',
                'SMALL_FILE_THRESHOLD': 1024  # Smaller threshold for testing
            },
            'staging': {
                'DEBUG': False,
                'TESTING': False,
                'SESSION_COOKIE_SECURE': True,
                'CACHE_TYPE': 'redis',
                'SQLALCHEMY_DATABASE_URI': os.getenv('STAGING_DATABASE_URL'),
                'CELERY_BROKER_URL': os.getenv('STAGING_REDIS_URL'),
                'SENTRY_ENVIRONMENT': 'staging',
                # Staging-specific file integrity settings
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
                'CRITICAL_FILES_PATTERN': [
                    "*.py",                    # All Python files
                    "config/*.py",             # Configuration files
                    "core/security/*.py",      # Security components
                    "app.py"                   # Main application entry point
                ]
            },
            'ci': {
                'DEBUG': False,
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'CACHE_TYPE': 'simple',
                'CELERY_ALWAYS_EAGER': True,
                'SQLALCHEMY_DATABASE_URI': 'postgresql://ci:ci@localhost/ci_test',
                # CI-specific file integrity settings
                'ENABLE_FILE_INTEGRITY_MONITORING': False,
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_BACKUP_ENABLED': False,
                'CI_SKIP_INTEGRITY_CHECK': True,
                'CRITICAL_FILES_PATTERN': [
                    "app.py",
                    "core/security/*.py",
                    "config/*.py"
                ]
            },
            'dr-recovery': {
                'DEBUG': False,
                'TESTING': False,
                'DR_MODE': True,
                'RECOVERY_MODE': True,
                'DR_ENHANCED_LOGGING': True,
                'DR_BASELINE_FROZEN': True,  # Prevent baseline changes during DR recovery
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
                'SESSION_COOKIE_SECURE': True,
                'SQLALCHEMY_DATABASE_URI': os.getenv('DR_DATABASE_URL')
            }
        }

        # Update base config with environment settings
        base_configuration.update(env_config.get(env, env_config['development']))

        # Set up file baseline path
        if base_configuration.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            if 'FILE_BASELINE_PATH' not in base_configuration or not base_configuration['FILE_BASELINE_PATH']:
                baseline_path_template = base_configuration.get('BASELINE_PATH_TEMPLATE',
                                                             'instance/security/baseline_{environment}.json')
                base_configuration['FILE_BASELINE_PATH'] = baseline_path_template.format(environment=env)

        # Session security settings (override any environment-specific configurations)
        base_configuration.update({
            'SESSION_COOKIE_SECURE': True if env != 'development' and env != 'testing' else False,
            'SESSION_COOKIE_HTTPONLY': True,  # Prevent JavaScript access to cookies
            'SESSION_COOKIE_SAMESITE': 'Lax',  # Restrict cross-site requests
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=1)  # Default session lifetime
        })

        return base_configuration

    @classmethod
    def update_file_integrity_baseline(
        cls,
        app=None,
        baseline_path: Optional[str] = None,
        updates: Optional[Dict[str, Any]] = None,
        remove_missing: bool = False,
        auto_update_limit: int = 10
    ):
        """
        Forward to the file integrity baseline update function in core config.

        This is a convenience method that delegates to the implementation in
        the core configuration package.

        Args:
            app: Flask application instance
            baseline_path: Path to the baseline file
            updates: Dictionary of file paths and their current hashes
            remove_missing: Whether to remove entries for files that no longer exist
            auto_update_limit: Maximum number of files to auto-update

        Returns:
            tuple: (success_bool, message_string)
        """
        from config import update_file_integrity_baseline as core_update
        return core_update(app, baseline_path, updates, remove_missing, auto_update_limit)


config = BaseConfig
"""
Configuration object for easy import.

This provides a convenient shorthand for importing the configuration class.

Example:
    from config import config
    app_config = config.load('production')
"""
