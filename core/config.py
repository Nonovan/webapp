"""
Configuration management module for the myproject application.

This module handles the loading, validation, and access of configuration settings
from environment variables and configuration files. It provides a centralized
configuration system that ensures all required settings are available before
the application starts and provides sensible defaults for optional settings.

The Config class implements a flexible configuration system that supports
different environments (development, testing, production) and ensures
security-critical variables are properly set. It validates configuration
before the application starts to prevent runtime failures due to missing
or invalid configuration.

Configuration priorities:
1. Environment variables (highest priority)
2. Environment-specific settings
3. Default values (lowest priority)
"""

from datetime import timedelta
from typing import Dict, Any, List
import os
import secrets

class Config:
    """
    Configuration management class for the application.

    This class handles loading application configuration from environment
    variables, validating required settings, and providing default values
    for optional settings. It ensures all critical configuration is available
    before the application starts.

    Class Attributes:
        REQUIRED_VARS (List[str]): List of required environment variables
        ENV_DEFAULTS (Dict[str, Any]): Default values for environment settings
    """

    # Required environment variables
    REQUIRED_VARS: List[str] = [
        'SECRET_KEY',
        'DATABASE_URL',
        'JWT_SECRET_KEY',
        'CSRF_SECRET_KEY',
        'SESSION_KEY'
    ]

    # Environment defaults
    ENV_DEFAULTS: Dict[str, Any] = {
        'ENVIRONMENT': 'development',
        'DEBUG': False,
        'TESTING': False,
        'LOG_LEVEL': 'INFO'
    }

    # Security monitoring defaults
    SECURITY_DEFAULTS: Dict[str, Any] = {
        'ENABLE_AUTO_COUNTERMEASURES': False,
        'SECURITY_ALERT_THRESHOLD': 7,
        'CRITICAL_ALERT_THRESHOLD': 9,
        'LOGIN_ATTEMPT_LIMIT': 5,
        'ACCOUNT_LOCKOUT_DURATION': 30,  # minutes
        'ALLOWED_ORIGINS': '*',
        'HSTS_AGE': 31536000,  # 1 year in seconds
        'PASSWORD_HASH_ALGORITHM': 'argon2',
        'PASSWORD_MIN_LENGTH': 12,
        'PASSWORD_REUSE_PREVENTION': 5,  # Remember last N passwords
        'SESSION_TIMEOUT': 3600,  # 1 hour in seconds
        'API_RATE_LIMIT': '60/minute',
        'AUDIT_LOG_RETENTION': 90,  # days
        'PASSWORD_EXPIRY': 90,  # days
        'MFA_ENABLED': False
    }

    @classmethod
    def load(cls) -> Dict[str, Any]:
        """
        Load and validate configuration from environment variables.

        This method retrieves configuration from environment variables,
        validates that all required variables are present, and returns
        a complete configuration dictionary with appropriate defaults
        for missing optional values.

        Returns:
            Dict[str, Any]: Complete application configuration dictionary

        Raises:
            RuntimeError: If any required configuration variables are missing

        Example:
            config = Config.load()
            app.config.update(config)
        """
        # Validate required variables
        missing = [var for var in cls.REQUIRED_VARS if not os.getenv(var)]
        if missing:
            raise RuntimeError(f"Missing required config vars: {', '.join(missing)}")

        return {
            # Environment
            'ENVIRONMENT': os.getenv('ENVIRONMENT', cls.ENV_DEFAULTS['ENVIRONMENT']),
            'DEBUG': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
            'TESTING': cls.ENV_DEFAULTS['TESTING'],
            'VERSION': os.getenv('APP_VERSION', '1.0.0'),

            # Security
            'SECRET_KEY': os.getenv('SECRET_KEY'),
            'WTF_CSRF_SECRET_KEY': os.getenv('CSRF_SECRET_KEY'),
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
            'PERMANENT_SESSION_LIFETIME': timedelta(days=int(os.getenv('SESSION_DAYS', '1'))),

            # Database
            'SQLALCHEMY_DATABASE_URI': os.getenv('DATABASE_URL'),
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'SQLALCHEMY_POOL_SIZE': int(os.getenv('DB_POOL_SIZE', '5')),
            'SQLALCHEMY_POOL_TIMEOUT': int(os.getenv('DB_POOL_TIMEOUT', '30')),

            # Cache
            'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379'),
            'CACHE_TYPE': 'redis',
            'CACHE_DEFAULT_TIMEOUT': int(os.getenv('CACHE_TIMEOUT', '300')),

            # Logging and Monitoring
            'LOG_LEVEL': os.getenv('LOG_LEVEL', cls.ENV_DEFAULTS['LOG_LEVEL']),
            'SENTRY_DSN': os.getenv('SENTRY_DSN'),
            'SENTRY_TRACES_SAMPLE_RATE': float(os.getenv('SENTRY_TRACES_SAMPLE_RATE', '0.1')),
            'SENTRY_SEND_PII': os.getenv('SENTRY_SEND_PII', 'False').lower() == 'true',
            'METRICS_ENABLED': os.getenv('METRICS_ENABLED', 'True').lower() == 'true',
            'STATSD_HOST': os.getenv('STATSD_HOST', 'localhost'),
            'STATSD_PORT': int(os.getenv('STATSD_PORT', '8125')),
            
            # Security monitoring
            'ENABLE_AUTO_COUNTERMEASURES': os.getenv('ENABLE_AUTO_COUNTERMEASURES', 'False').lower() == 'true',
            'SECURITY_ALERT_THRESHOLD': int(os.getenv('SECURITY_ALERT_THRESHOLD', str(cls.SECURITY_DEFAULTS['SECURITY_ALERT_THRESHOLD']))),
            'CRITICAL_ALERT_THRESHOLD': int(os.getenv('CRITICAL_ALERT_THRESHOLD', str(cls.SECURITY_DEFAULTS['CRITICAL_ALERT_THRESHOLD']))),
            'LOGIN_ATTEMPT_LIMIT': int(os.getenv('LOGIN_ATTEMPT_LIMIT', str(cls.SECURITY_DEFAULTS['LOGIN_ATTEMPT_LIMIT']))),
            'ACCOUNT_LOCKOUT_DURATION': int(os.getenv('ACCOUNT_LOCKOUT_DURATION', str(cls.SECURITY_DEFAULTS['ACCOUNT_LOCKOUT_DURATION']))),
            'ALLOWED_ORIGINS': os.getenv('ALLOWED_ORIGINS', cls.SECURITY_DEFAULTS['ALLOWED_ORIGINS']),
            'HSTS_AGE': int(os.getenv('HSTS_AGE', str(cls.SECURITY_DEFAULTS['HSTS_AGE']))),
            'PASSWORD_HASH_ALGORITHM': os.getenv('PASSWORD_HASH_ALGORITHM', cls.SECURITY_DEFAULTS['PASSWORD_HASH_ALGORITHM']),
            'PASSWORD_MIN_LENGTH': int(os.getenv('PASSWORD_MIN_LENGTH', str(cls.SECURITY_DEFAULTS['PASSWORD_MIN_LENGTH']))),
            'PASSWORD_REUSE_PREVENTION': int(os.getenv('PASSWORD_REUSE_PREVENTION', str(cls.SECURITY_DEFAULTS['PASSWORD_REUSE_PREVENTION']))),
            'SESSION_TIMEOUT': int(os.getenv('SESSION_TIMEOUT', str(cls.SECURITY_DEFAULTS['SESSION_TIMEOUT']))),
            'API_RATE_LIMIT': os.getenv('API_RATE_LIMIT', cls.SECURITY_DEFAULTS['API_RATE_LIMIT']),
            'AUDIT_LOG_RETENTION': int(os.getenv('AUDIT_LOG_RETENTION', str(cls.SECURITY_DEFAULTS['AUDIT_LOG_RETENTION']))),
            'PASSWORD_EXPIRY': int(os.getenv('PASSWORD_EXPIRY', str(cls.SECURITY_DEFAULTS['PASSWORD_EXPIRY']))),
            'MFA_ENABLED': os.getenv('MFA_ENABLED', 'False').lower() == 'true',
            
            # Security notification
            'SECURITY_TEAM_EMAILS': os.getenv('SECURITY_TEAM_EMAILS', '').split(',') if os.getenv('SECURITY_TEAM_EMAILS') else [],
            'SECURITY_NOTIFICATION_CHANNEL': os.getenv('SECURITY_NOTIFICATION_CHANNEL', 'email'),

            # File integrity monitoring
            'ENABLE_FILE_INTEGRITY_MONITORING': os.getenv('ENABLE_FILE_INTEGRITY_MONITORING', 'True').lower() == 'true',
            'FILE_INTEGRITY_CHECK_INTERVAL': int(os.getenv('FILE_INTEGRITY_CHECK_INTERVAL', '3600')),  # 1 hour in seconds
            'CONFIG_FILE_HASHES': {},  # Populated at startup by file integrity system
            'CRITICAL_FILE_HASHES': {},  # Populated at startup by file integrity system
            
            # CSP Nonce generation
            'CSP_NONCE_LENGTH': int(os.getenv('CSP_NONCE_LENGTH', '32')),
            
            # SRI hash settings 
            'SRI_ALGORITHM': os.getenv('SRI_ALGORITHM', 'sha384'),
            
            # API security
            'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_MINUTES', '15'))),
            'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES_DAYS', '7'))),
            'JWT_BLACKLIST_ENABLED': True,
            
            # Additional security headers
            'REFERRER_POLICY': os.getenv('REFERRER_POLICY', 'strict-origin-when-cross-origin'),
            'PERMISSIONS_POLICY': os.getenv('PERMISSIONS_POLICY', 'geolocation=(), camera=(), microphone=(), payment=()'),
        }

    @staticmethod
    def load_from_name(name: str) -> Dict[str, Any]:
        """
        Load configuration by environment name.

        This method provides predefined configuration sets for common
        environments (development, production, testing), allowing for
        quick configuration switching.

        Args:
            name (str): Environment name ('development', 'production', 'testing')

        Returns:
            Dict[str, Any]: Environment-specific configuration dictionary

        Raises:
            ValueError: If the specified environment name is not recognized

        Example:
            test_config = Config.load_from_name('testing')
            app.config.update(test_config)
        """
        configs = {
            'development': {
                'DEBUG': True,
                'TESTING': False,
                'ENABLE_AUTO_COUNTERMEASURES': False,
                'SESSION_COOKIE_SECURE': False,
                'SESSION_COOKIE_HTTPONLY': True,
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'ENABLE_AUTO_COUNTERMEASURES': True,
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SAMESITE': 'Lax',
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'ENABLE_AUTO_COUNTERMEASURES': False,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
            }
        }

        if name not in configs:
            raise ValueError(f"Unknown configuration name: {name}")

        return configs[name]
    
    @staticmethod
    def generate_csp_nonce() -> str:
        """
        Generate a cryptographically secure nonce for CSP.
        
        Returns:
            str: Generated nonce as a URL-safe base64 string
        """
        return secrets.token_urlsafe(16)
    
    @classmethod
    def initialize_file_hashes(cls, config: Dict[str, Any], app_root: str) -> Dict[str, Any]:
        """
        Initialize file integrity hashes for critical files.
        
        This method computes hash values for security-critical files to enable
        integrity monitoring during application runtime.
        
        Args:
            config: Current application configuration dictionary
            app_root: Application root directory path
            
        Returns:
            Dict[str, Any]: Updated configuration with file hashes
        """
        from core.utils import calculate_file_hash
        
        # Only compute hashes if file integrity monitoring is enabled
        if not config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            return config
            
        # Define critical configuration files
        config_files = [
            os.path.join(app_root, 'config.py'),
            os.path.join(app_root, '.env'),
            os.path.join(app_root, 'app.py')
        ]
        
        # Define critical application files
        critical_files = [
            os.path.join(app_root, 'app.py'),
            os.path.join(app_root, 'wsgi.py'),
            os.path.join(app_root, 'core', 'security.py'),
            os.path.join(app_root, 'core', 'auth.py'),
            os.path.join(app_root, 'extensions.py')
        ]
        
        # Compute hashes for config files
        config_hashes = {}
        for file_path in config_files:
            if os.path.exists(file_path):
                try:
                    config_hashes[file_path] = calculate_file_hash(file_path)
                except (IOError, OSError):
                    pass
                    
        # Compute hashes for critical files
        critical_hashes = {}
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    critical_hashes[file_path] = calculate_file_hash(file_path)
                except (IOError, OSError):
                    pass
        
        # Update configuration
        config['CONFIG_FILE_HASHES'] = config_hashes
        config['CRITICAL_FILE_HASHES'] = critical_hashes
        
        return config