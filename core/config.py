"""
Configuration management for the Cloud Infrastructure Platform.

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

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import socket
from typing import Dict, Any, List, Optional, Union, Set, Callable, TypeVar, cast
import subprocess
from pathlib import Path
from flask import Flask

# Type definitions
ConfigDict = Dict[str, Any]
T = TypeVar('T')

# Constants
DEFAULT_HASH_ALGORITHM = 'sha256'
SMALL_FILE_THRESHOLD = 10240  # 10KB


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
        DEV_OVERRIDES (Dict[str, Any]): Development environment overrides
        TEST_OVERRIDES (Dict[str, Any]): Test environment overrides
        PROD_REQUIREMENTS (List[str]): Required settings for production
    """

    # Required environment variables - must be set for application to run
    REQUIRED_VARS: List[str] = [
        'SECRET_KEY',
        'DATABASE_URL',
        'JWT_SECRET_KEY',
        'CSRF_SECRET_KEY',
        'SESSION_KEY'
    ]

    # Environment defaults - used if not overridden
    ENV_DEFAULTS: Dict[str, Any] = {
        'ENVIRONMENT': 'development',
        'DEBUG': False,
        'TESTING': False,
        'SERVER_NAME': None,
        'APPLICATION_ROOT': '/',
        'PREFERRED_URL_SCHEME': 'https',

        # Database configuration
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_recycle': 280,
            'pool_pre_ping': True,
            'pool_size': 10,
            'max_overflow': 20
        },

        # Security settings
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'PERMANENT_SESSION_LIFETIME': timedelta(days=1),
        'REMEMBER_COOKIE_DURATION': timedelta(days=14),
        'REMEMBER_COOKIE_SECURE': True,
        'REMEMBER_COOKIE_HTTPONLY': True,
        'REMEMBER_COOKIE_SAMESITE': 'Lax',

        # Security headers
        'SECURITY_HEADERS_ENABLED': True,
        'SECURITY_CSP_REPORT_URI': None,
        'SECURITY_HSTS_MAX_AGE': 31536000,  # 1 year
        'SECURITY_INCLUDE_SUBDOMAINS': True,
        'SECURITY_PRELOAD': True,

        # CSRF protection
        'WTF_CSRF_ENABLED': True,
        'WTF_CSRF_TIME_LIMIT': 3600,  # 1 hour

        # Rate limiting
        'RATELIMIT_DEFAULT': '200 per day, 50 per hour',
        'RATELIMIT_STORAGE_URL': 'memory://',
        'RATELIMIT_HEADERS_ENABLED': True,
        'RATELIMIT_STRATEGY': 'fixed-window',

        # JWT settings
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=15),
        'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30),
        'JWT_BLACKLIST_ENABLED': True,
        'JWT_BLACKLIST_TOKEN_CHECKS': ['access', 'refresh'],

        # Cache settings
        'CACHE_TYPE': 'SimpleCache',
        'CACHE_DEFAULT_TIMEOUT': 300,

        # ICS system settings
        'ICS_ENABLED': False,
        'ICS_RESTRICTED_IPS': [],
        'ICS_MONITOR_INTERVAL': 60,  # seconds
        'ICS_ALERT_THRESHOLD': 0.8,  # 80%

        # Cloud settings
        'CLOUD_PROVIDERS': ['aws', 'azure', 'gcp'],
        'CLOUD_METRICS_INTERVAL': 300,  # 5 minutes
        'CLOUD_RESOURCES_CACHE_TTL': 600,  # 10 minutes

        # Monitoring settings
        'METRICS_ENABLED': True,
        'SENTRY_TRACES_SAMPLE_RATE': 0.2,
        'LOG_LEVEL': 'INFO',
        'SECURITY_LOG_LEVEL': 'WARNING',

        # File security settings
        'SECURITY_CHECK_FILE_INTEGRITY': True,
        'SECURITY_CRITICAL_FILES': [
            'app.py',
            'config.py',
            'core/security_utils.py',
            'core/middleware.py'
        ],
        'ALLOWED_EXTENSIONS': {'pdf', 'png', 'jpg', 'jpeg', 'csv', 'xlsx'},
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16 MB

        # Feature flags
        'FEATURE_DARK_MODE': True,
        'FEATURE_ICS_CONTROL': True,
        'FEATURE_CLOUD_MANAGEMENT': True,
        'FEATURE_MFA': True,

        # Content security policy settings
        'CSP_DEFAULT_SRC': ["'self'"],
        'CSP_SCRIPT_SRC': ["'self'", "'unsafe-inline'"],
        'CSP_STYLE_SRC': ["'self'", "'unsafe-inline'"],
        'CSP_IMG_SRC': ["'self'", "data:"],
        'CSP_CONNECT_SRC': ["'self'"],
        'CSP_FONT_SRC': ["'self'"],
        'CSP_OBJECT_SRC': ["'none'"],
        'CSP_MEDIA_SRC': ["'self'"],
        'CSP_FRAME_SRC': ["'self'"],
        'CSP_FRAME_ANCESTORS': ["'self'"],
        'CSP_FORM_ACTION': ["'self'"],
        'CSP_BASE_URI': ["'self'"],
        'CSP_REPORT_TO': "default",

        # Security audit logging
        'AUDIT_LOG_ENABLED': True,
        'AUDIT_LOG_EVENTS': ['authentication', 'authorization', 'data_access', 'configuration_change'],
        'AUDIT_LOG_RETENTION_DAYS': 90,

        # File integrity monitoring
        'ENABLE_FILE_INTEGRITY_MONITORING': True,
        'FILE_HASH_ALGORITHM': 'sha256',
        'FILE_INTEGRITY_CHECK_INTERVAL': 3600,  # 1 hour
        'AUTO_UPDATE_BASELINE': False,  # Don't auto-update baseline by default
        'CRITICAL_FILES_PATTERN': [
            "*.py",                 # Python source files
            "config/*.ini",         # Configuration files
            "config/*.json",        # JSON configuration
            "config/*.yaml",        # YAML configuration
            "config/*.yml",         # YAML configuration (alt)
        ],
        'CHECK_FILE_SIGNATURES': True,  # Verify file signatures where applicable
        'FILE_BASELINE_PATH': None,    # Set dynamically in _setup_derived_values

        # API security settings
        'API_RATE_LIMIT_ENABLED': True,
        'API_RATE_LIMIT_DEFAULT': '100/hour',
        'API_REQUIRE_HTTPS': True
    }

    # Development-specific overrides
    DEV_OVERRIDES: Dict[str, Any] = {
        'DEBUG': True,
        'SESSION_COOKIE_SECURE': False,
        'REMEMBER_COOKIE_SECURE': False,
        'WTF_CSRF_ENABLED': True,
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
        'SECURITY_HEADERS_ENABLED': True,
        'METRICS_ENABLED': True,
        'LOG_LEVEL': 'DEBUG',
        'API_REQUIRE_HTTPS': False,  # Allow HTTP in dev for easier testing
        'AUTO_UPDATE_BASELINE': True,  # Auto-update baseline in dev
    }

    # Test-specific overrides
    TEST_OVERRIDES: Dict[str, Any] = {
        'TESTING': True,
        'DEBUG': False,
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost',
        'METRICS_ENABLED': False,
        'SECURITY_CHECK_FILE_INTEGRITY': False,
        'AUDIT_LOG_ENABLED': False,  # Disable audit logging in tests
    }

    # Production-specific security requirements
    PROD_REQUIREMENTS: List[str] = [
        'SESSION_COOKIE_SECURE',
        'SESSION_COOKIE_HTTPONLY',
        'REMEMBER_COOKIE_SECURE',
        'REMEMBER_COOKIE_HTTPONLY',
        'WTF_CSRF_ENABLED',
        'SECURITY_HEADERS_ENABLED',
        'API_REQUIRE_HTTPS',
        'JWT_BLACKLIST_ENABLED',
        'AUDIT_LOG_ENABLED'
    ]

    # Constants
    ALLOWED_ENVIRONMENTS = {'development', 'testing', 'staging', 'production'}
    SECURE_ENVIRONMENTS = {'staging', 'production'}

    # Loggers
    logger = logging.getLogger(__name__)
    security_logger = logging.getLogger('security')

    @classmethod
    def init_app(cls, app: Flask) -> None:
        """
        Initialize the application with configuration settings.

        This method configures a Flask application with appropriate settings based on
        the current environment, loading configuration from environment variables,
        validating security requirements, and setting up derived values.

        Args:
            app: Flask application instance to configure

        Raises:
            ValueError: If required environment variables are missing in production
                       or if security settings are inappropriately configured
            RuntimeError: If the environment is not valid
        """
        # Get environment from environment variable or default to development
        environment = os.environ.get('ENVIRONMENT', 'development').lower()

        # Validate environment value
        if environment not in cls.ALLOWED_ENVIRONMENTS:
            raise RuntimeError(f"Invalid environment: {environment}. Allowed values are: {', '.join(cls.ALLOWED_ENVIRONMENTS)}")

        app.config['ENVIRONMENT'] = environment
        cls.logger.info(f"Initializing application in {environment} environment")

        # Load default configuration
        for key, value in cls.ENV_DEFAULTS.items():
            app.config[key] = value

        # Apply environment-specific overrides
        if environment == 'development':
            for key, value in cls.DEV_OVERRIDES.items():
                app.config[key] = value
        elif environment == 'testing':
            for key, value in cls.TEST_OVERRIDES.items():
                app.config[key] = value

        # Load settings from environment variables (highest priority)
        cls._load_from_environment(app)

        # Validate configuration
        cls._validate_configuration(app)

        # Setup derived values and special cases
        cls._setup_derived_values(app)

        # Register config values to be accessible in the app context
        cls._register_template_context(app)

        # Initialize file integrity monitoring if enabled
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            try:
                # Try to use the improved cs_file_integrity module
                from core.security.cs_file_integrity import initialize_file_monitoring

                # Initialize file monitoring with appropriate patterns and interval
                basedir = app.root_path
                patterns = app.config.get('CRITICAL_FILES_PATTERN')
                interval = app.config.get('FILE_INTEGRITY_CHECK_INTERVAL', 3600)

                initialize_file_monitoring(app, basedir, patterns, interval)
                cls.logger.info("File integrity monitoring initialized")

            except ImportError:
                # Fall back to basic file integrity checks
                app.config = cls.initialize_file_hashes(app.config, app.root_path)
                cls.logger.info("Basic file integrity monitoring initialized (cs_file_integrity not available)")

        # Log initialization complete with security-relevant info
        cls.security_logger.info(
            "Application configuration initialized",
            extra={
                "environment": environment,
                "security_headers_enabled": app.config.get('SECURITY_HEADERS_ENABLED'),
                "file_integrity_monitoring": app.config.get('ENABLE_FILE_INTEGRITY_MONITORING'),
                "audit_logging_enabled": app.config.get('AUDIT_LOG_ENABLED')
            }
        )

    @classmethod
    def _register_template_context(cls, app: Flask) -> None:
        """
        Register configuration values to be available in templates.

        Args:
            app: Flask application instance
        """
        @app.context_processor
        def inject_config() -> Dict[str, Dict[str, Any]]:
            """Make selected config values available in templates."""
            return {
                'config': {
                    'VERSION': app.config.get('VERSION', '1.0.0'),
                    'ENVIRONMENT': app.config.get('ENVIRONMENT', 'development'),
                    'FEATURE_DARK_MODE': app.config.get('FEATURE_DARK_MODE', True),
                    'FEATURE_ICS_CONTROL': app.config.get('FEATURE_ICS_CONTROL', True),
                    'FEATURE_CLOUD_MANAGEMENT': app.config.get('FEATURE_CLOUD_MANAGEMENT', True),
                    'FEATURE_MFA': app.config.get('FEATURE_MFA', True),
                    'CSP_NONCE': cls.generate_csp_nonce(),
                }
            }

    @classmethod
    def _load_from_environment(cls, app: Flask) -> None:
        """
        Load configuration from environment variables.

        Environment variables take precedence over other settings.
        The function handles type conversions for common data types.

        Args:
            app: Flask application instance
        """
        # Directly set Flask configuration from environment variables with prefix
        for key, value in os.environ.items():
            if key.startswith('FLASK_'):
                app_key = key[6:]  # Remove FLASK_ prefix
                app.config[app_key] = cls._convert_env_value(value)

        # Set required variables and overrides
        for var in cls.REQUIRED_VARS:
            if var in os.environ:
                app.config[var] = os.environ[var]

        # Set database URL
        if 'DATABASE_URL' in os.environ:
            app.config['SQLALCHEMY_DATABASE_URI'] = cls._sanitize_database_url(os.environ['DATABASE_URL'])

        # Handle ICS restricted IPs - parse as valid IP addresses
        cls._load_ips_from_environment(app)

        # Load file integrity monitoring configuration
        cls._load_integrity_config_from_environment(app)

    @staticmethod
    def _convert_env_value(value: str) -> Any:
        """
        Convert environment variable string to appropriate Python type.

        Args:
            value: String value from environment variable

        Returns:
            The converted value with appropriate type
        """
        # Handle boolean values
        if value.lower() in ('true', 'yes', '1'):
            return True
        elif value.lower() in ('false', 'no', '0'):
            return False
        # Handle integer values
        elif value.isdigit():
            return int(value)
        # Handle float values
        elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
            return float(value)
        # Return as string for other values
        return value

    @classmethod
    def _load_ips_from_environment(cls, app: Flask) -> None:
        """
        Load and validate IP addresses from the environment variable.

        Args:
            app: Flask application instance
        """
        if 'ICS_RESTRICTED_IPS' in os.environ:
            try:
                ips_str = os.environ['ICS_RESTRICTED_IPS']
                ip_list = []

                for ip_str in ips_str.split(','):
                    ip_str = ip_str.strip()
                    if ip_str:  # Skip empty strings
                        try:
                            # Validate IP address or CIDR
                            ipaddress.ip_network(ip_str, strict=False)
                            ip_list.append(ip_str)
                        except ValueError:
                            cls.logger.warning(f"Invalid IP address or CIDR in ICS_RESTRICTED_IPS: {ip_str}")

                app.config['ICS_RESTRICTED_IPS'] = ip_list
                cls.logger.info(f"Loaded {len(ip_list)} restricted IPs for ICS access")
            except ValueError as e:
                cls.logger.error(f"Error parsing ICS_RESTRICTED_IPS: {str(e)}")

    @classmethod
    def _load_integrity_config_from_environment(cls, app: Flask) -> None:
        """
        Load file integrity monitoring configuration from environment variables.

        Args:
            app: Flask application instance
        """
        # File integrity monitoring enabled/disabled
        if 'ENABLE_FILE_INTEGRITY_MONITORING' in os.environ:
            app.config['ENABLE_FILE_INTEGRITY_MONITORING'] = cls._convert_env_value(
                os.environ['ENABLE_FILE_INTEGRITY_MONITORING']
            )

        # File integrity check interval
        if 'FILE_INTEGRITY_CHECK_INTERVAL' in os.environ:
            try:
                interval = int(os.environ['FILE_INTEGRITY_CHECK_INTERVAL'])
                # Enforce minimum interval to prevent performance issues
                if interval < 300:  # 5 minutes minimum
                    interval = 300
                    cls.logger.warning("FILE_INTEGRITY_CHECK_INTERVAL too low, setting to 300 seconds minimum")
                app.config['FILE_INTEGRITY_CHECK_INTERVAL'] = interval
            except ValueError:
                cls.logger.warning("Invalid FILE_INTEGRITY_CHECK_INTERVAL value, using default")

        # Auto-update baseline setting
        if 'AUTO_UPDATE_BASELINE' in os.environ:
            app.config['AUTO_UPDATE_BASELINE'] = cls._convert_env_value(
                os.environ['AUTO_UPDATE_BASELINE']
            )

        # Check file signatures setting
        if 'CHECK_FILE_SIGNATURES' in os.environ:
            app.config['CHECK_FILE_SIGNATURES'] = cls._convert_env_value(
                os.environ['CHECK_FILE_SIGNATURES']
            )

        # Critical file patterns
        if 'CRITICAL_FILES_PATTERN' in os.environ:
            try:
                patterns = json.loads(os.environ['CRITICAL_FILES_PATTERN'])
                if isinstance(patterns, list):
                    app.config['CRITICAL_FILES_PATTERN'] = patterns
                else:
                    cls.logger.warning("CRITICAL_FILES_PATTERN should be a JSON array, using default")
            except json.JSONDecodeError:
                # Try comma-separated list
                patterns = [p.strip() for p in os.environ['CRITICAL_FILES_PATTERN'].split(',') if p.strip()]
                if patterns:
                    app.config['CRITICAL_FILES_PATTERN'] = patterns

    @staticmethod
    def _sanitize_database_url(url: str) -> str:
        """
        Sanitize database URL to ensure it's properly formatted and secure.

        Args:
            url: Database URL string

        Returns:
            Sanitized database URL

        Raises:
            ValueError: If the database URL is malformed
        """
        # Validate that the URL starts with a known database protocol
        valid_prefixes = ['postgresql://', 'mysql://', 'sqlite:///', 'oracle://',
                          'mssql://', 'postgresql+psycopg2://', 'mysql+pymysql://']

        if not any(url.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(f"Invalid database URL. Must start with one of: {', '.join(valid_prefixes)}")

        return url

    @classmethod
    def _validate_configuration(cls, app: Flask) -> None:
        """
        Validate that all required configuration is present and properly formatted.

        This method checks that all required environment variables are set and
        that production security requirements are met in production environments.

        Args:
            app: Flask application instance

        Raises:
            ValueError: If configuration validation fails
        """
        environment = app.config.get('ENVIRONMENT', 'development')

        # Skip strict validation for development and testing
        if environment not in cls.SECURE_ENVIRONMENTS:
            return

        # Check required variables in production
        missing_vars = [var for var in cls.REQUIRED_VARS
                       if var not in app.config or not app.config[var]]

        if missing_vars:
            cls.security_logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # Check security settings in production
        insecure_settings = [setting for setting in cls.PROD_REQUIREMENTS
                            if setting in app.config and not app.config[setting]]

        if insecure_settings:
            cls.security_logger.error(f"Insecure settings in production: {', '.join(insecure_settings)}")
            raise ValueError(f"Insecure settings in production: {', '.join(insecure_settings)}")

        # Check for development SECRET_KEY in production
        if app.config.get('SECRET_KEY') in ('dev', 'development', 'secret', 'changeme'):
            cls.security_logger.error("Development SECRET_KEY used in production environment")
            raise ValueError("Development SECRET_KEY used in production environment")

        # Check for minimum password requirements
        if app.config.get('PASSWORD_MIN_LENGTH', 0) < 12:
            cls.security_logger.warning("PASSWORD_MIN_LENGTH should be at least 12 characters")

        # Check session lifetime
        if app.config.get('PERMANENT_SESSION_LIFETIME', timedelta(days=31)) > timedelta(days=30):
            cls.security_logger.warning("PERMANENT_SESSION_LIFETIME exceeds recommended 30 days")

        # Check if file integrity monitoring is disabled in production
        if not app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            cls.security_logger.warning("File integrity monitoring disabled in production environment")

        # Check auto-update baseline in production (should be false)
        if app.config.get('AUTO_UPDATE_BASELINE', False):
            cls.security_logger.warning("AUTO_UPDATE_BASELINE should be disabled in production")

        # Check if audit logging is properly configured
        if app.config.get('AUDIT_LOG_ENABLED', True) and app.config.get('AUDIT_LOG_RETENTION_DAYS', 90) < 30:
            cls.security_logger.warning("AUDIT_LOG_RETENTION_DAYS should be at least 30 days in production")

    @classmethod
    def _setup_derived_values(cls, app: Flask) -> None:
        """
        Set up derived configuration values based on other settings.

        This sets up configuration values that are derived from or depend
        on other configuration settings, including:
        - Redis URL for caching when available
        - Debug settings for development
        - File paths based on application root

        Args:
            app: Flask application instance
        """
        # Set up Redis for cache if REDIS_URL is provided
        if 'REDIS_URL' in os.environ:
            app.config['CACHE_TYPE'] = 'RedisCache'
            app.config['CACHE_REDIS_URL'] = os.environ['REDIS_URL']
            app.config['RATELIMIT_STORAGE_URL'] = os.environ['REDIS_URL']

            # Also use Redis for session storage if available
            app.config['SESSION_TYPE'] = 'redis'
            app.config['SESSION_REDIS'] = redis.from_url(os.environ['REDIS_URL'])
        else:
            # Default to SimpleCache
            app.config['CACHE_TYPE'] = 'SimpleCache'
            app.config['SESSION_TYPE'] = 'filesystem'

        # Set up upload folder
        uploads_path = os.path.join(app.root_path, 'uploads')
        app.config['UPLOAD_FOLDER'] = uploads_path

        # Create upload directory with secure permissions if it doesn't exist
        try:
            if not os.path.exists(uploads_path):
                # Create with restricted permissions (0o750 = rwxr-x---)
                os.makedirs(uploads_path, mode=0o750, exist_ok=True)
                cls.logger.info(f"Created upload directory: {uploads_path}")
        except (IOError, OSError) as e:
            cls.logger.error(f"Failed to create upload directory {uploads_path}: {str(e)}")

        # Generate a self-identification string for logs/metrics
        hostname = socket.gethostname()
        app.config['INSTANCE_IDENTIFIER'] = f"{hostname}-{os.getpid()}"

        # Set application version (try to get from Git if available)
        if 'VERSION' not in app.config:
            app.config['VERSION'] = cls._get_application_version()

        # Set build timestamp
        app.config.setdefault('BUILD_TIMESTAMP', cls.format_timestamp())

        # Set log directory with proper permissions
        log_dir = os.path.join(app.root_path, 'logs')
        try:
            if not os.path.exists(log_dir):
                # Create with restricted permissions (0o750 = rwxr-x---)
                os.makedirs(log_dir, mode=0o750, exist_ok=True)
                cls.logger.info(f"Created log directory: {log_dir}")
        except (IOError, OSError) as e:
            cls.logger.error(f"Failed to create log directory {log_dir}: {str(e)}")

        # Setup absolute paths for security-critical directories
        app.config['LOG_DIR'] = log_dir
        app.config['TEMP_DIR'] = os.path.join(app.root_path, 'tmp')

        # Create temp directory if needed
        try:
            os.makedirs(app.config['TEMP_DIR'], mode=0o750, exist_ok=True)
        except (IOError, OSError) as e:
            cls.logger.error(f"Failed to create temp directory: {str(e)}")

        # Set up file baseline path if file integrity monitoring is enabled
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            if 'FILE_BASELINE_PATH' not in app.config or not app.config['FILE_BASELINE_PATH']:
                # Set baseline path in instance directory
                app.config['FILE_BASELINE_PATH'] = os.path.join(app.instance_path, 'file_baseline.json')

            # Ensure instance directory exists
            try:
                os.makedirs(os.path.dirname(app.config['FILE_BASELINE_PATH']), exist_ok=True)
            except OSError as e:
                cls.logger.error(f"Failed to create baseline directory: {str(e)}")

    @classmethod
    def _get_application_version(cls) -> str:
        """
        Get the application version from git tags or default to a fixed version.

        Returns:
            The application version string
        """
        try:
            result = subprocess.run(
                ['git', 'describe', '--tags', '--always'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=2  # Timeout after 2 seconds
            )
            return result.stdout.decode('utf-8').strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            cls.logger.debug(f"Could not determine version from git: {str(e)}")
            return '1.0.0'

    @classmethod
    def get_config(cls, name: str) -> ConfigDict:
        """
        Load configuration by environment name.

        This method provides predefined configuration sets for common
        environments (development, production, testing), allowing for
        quick configuration switching.

        Args:
            name: Environment name ('development', 'production', 'testing')

        Returns:
            Environment-specific configuration dictionary

        Raises:
            ValueError: If the specified environment name is not recognized

        Example:
            test_config = Config.get_config('testing')
            app.config.update(test_config)
        """
        configs = {
            'development': {
                'DEBUG': True,
                'TESTING': False,
                'ENABLE_AUTO_COUNTERMEASURES': False,
                'SESSION_COOKIE_SECURE': False,
                'SESSION_COOKIE_HTTPONLY': True,
                'AUTO_UPDATE_BASELINE': True,
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'ENABLE_AUTO_COUNTERMEASURES': True,
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SAMESITE': 'Lax',
                'AUTO_UPDATE_BASELINE': False,
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'ENABLE_AUTO_COUNTERMEASURES': False,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
                'ENABLE_FILE_INTEGRITY_MONITORING': False,
            },
            'staging': {
                'DEBUG': False,
                'TESTING': False,
                'ENABLE_AUTO_COUNTERMEASURES': True,
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SAMESITE': 'Lax',
                'AUTO_UPDATE_BASELINE': False,
            }
        }

        name = name.lower()
        if name not in configs:
            cls.logger.error(f"Unknown configuration name: {name}")
            raise ValueError(f"Unknown configuration name: {name}")

        return configs[name]

    @staticmethod
    def generate_csp_nonce() -> str:
        """
        Generate a cryptographically secure nonce for CSP.

        Returns:
            Generated nonce as a URL-safe base64 string
        """
        return secrets.token_urlsafe(16)

    @classmethod
    def initialize_file_hashes(cls, config: ConfigDict, app_root: str) -> ConfigDict:
        """
        Initialize file integrity hashes for critical files.

        This method computes hash values for security-critical files to enable
        integrity monitoring during application runtime. It uses the specified
        algorithm for hashing, with SHA-256 as a fallback for larger files.

        Args:
            config: Current application configuration dictionary
            app_root: Application root directory path

        Returns:
            Updated configuration with file hashes

        Example:
            app.config = Config.initialize_file_hashes(app.config, app_root_path)
        """
        # If file integrity monitoring is disabled, return early
        if not config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            return config

        # Define critical configuration files
        config_files = [
            os.path.join(app_root, 'config.py'),
            os.path.join(app_root, '.env'),
            os.path.join(app_root, 'app.py'),
            os.path.join(app_root, 'core', 'config.py'),
            os.path.join(app_root, 'core', 'factory.py'),
            os.path.join(app_root, 'core', 'middleware.py')
        ]

        # Define critical application files
        critical_files = [
            os.path.join(app_root, 'app.py'),
            os.path.join(app_root, 'wsgi.py'),
            os.path.join(app_root, 'core', 'utils.py'),
            os.path.join(app_root, 'core', 'security_utils.py'),
            os.path.join(app_root, 'core', 'auth.py'),
            os.path.join(app_root, 'extensions.py'),
            os.path.join(app_root, 'blueprints', 'monitoring', 'routes.py'),
            os.path.join(app_root, 'models', 'audit_log.py'),
            os.path.join(app_root, 'models', 'security_incident.py'),
            os.path.join(app_root, 'models', 'user.py')
        ]

        # Include security module files
        security_dir = os.path.join(app_root, 'core', 'security')
        if os.path.exists(security_dir):
            security_files = [
                os.path.join(security_dir, 'cs_constants.py'),
                os.path.join(security_dir, 'cs_utils.py'),
                os.path.join(security_dir, 'cs_file_integrity.py'),
                os.path.join(security_dir, 'cs_audit.py'),
                os.path.join(security_dir, 'cs_authentication.py'),
                os.path.join(security_dir, 'cs_authorization.py'),
                os.path.join(security_dir, 'cs_crypto.py'),
            ]
            critical_files.extend([f for f in security_files if os.path.exists(f)])

        # Compute hashes for config files
        config_hashes = cls._compute_file_hashes(
            config_files,
            config.get('FILE_HASH_ALGORITHM', DEFAULT_HASH_ALGORITHM)
        )

        # Compute hashes for critical files
        critical_hashes = cls._compute_file_hashes(
            critical_files,
            config.get('FILE_HASH_ALGORITHM', DEFAULT_HASH_ALGORITHM)
        )

        # Add monitored directories (these will be checked for unexpected files)
        monitored_directories = [
            os.path.join(app_root, 'core'),
            os.path.join(app_root, 'models'),
            os.path.join(app_root, 'blueprints', 'auth'),
            os.path.join(app_root, 'blueprints', 'monitoring'),
            os.path.join(app_root, 'core', 'security')
        ]

        # Update configuration
        config['MONITORED_DIRECTORIES'] = monitored_directories
        config['CONFIG_FILE_HASHES'] = config_hashes
        config['CRITICAL_FILE_HASHES'] = critical_hashes
        config['FILE_HASH_TIMESTAMP'] = cls.format_timestamp()

        cls.logger.info(f"Computed file hashes for {len(config_hashes)} config files and {len(critical_hashes)} critical files")
        return config

    @classmethod
    def _compute_file_hashes(cls, file_paths: List[str], default_algorithm: str) -> Dict[str, str]:
        """
        Compute hashes for a list of files.

        Args:
            file_paths: List of file paths to hash
            default_algorithm: Default hashing algorithm to use

        Returns:
            Dictionary mapping file paths to their hash values
        """
        hashes = {}

        for file_path in file_paths:
            if os.path.exists(file_path):
                try:
                    file_size = os.path.getsize(file_path)
                    algorithm = default_algorithm

                    # For large files, always use SHA-256 for performance
                    if file_size > SMALL_FILE_THRESHOLD:
                        algorithm = 'sha256'

                    hashes[file_path] = cls._calculate_file_hash(file_path, algorithm)
                except (IOError, OSError) as e:
                    cls.logger.warning(f"Could not hash file {file_path}: {str(e)}")
            else:
                cls.logger.debug(f"File not found for hash computation: {file_path}")

        return hashes

    @staticmethod
    def _calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash for a file.

        Args:
            file_path: Path to the file
            algorithm: Hashing algorithm to use (default: sha256)

        Returns:
            File hash as a hex string

        Raises:
            IOError: If the file cannot be read
            ValueError: If the algorithm is not supported
        """
        hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }

        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        hasher = hash_algorithms[algorithm]()

        with open(file_path, 'rb') as f:
            # Read and update hash in chunks for memory efficiency
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)

        return hasher.hexdigest()

    @staticmethod
    def format_timestamp() -> str:
        """
        Format current datetime as ISO 8601 string with timezone information.

        Returns:
            Current datetime as ISO 8601 formatted string
        """
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def get(cls, key: str, default: T = None) -> Union[Any, T]:
        """
        Get a configuration value from the current Flask application.

        This provides a convenient way to access configuration values
        without directly accessing the Flask application instance.

        Args:
            key: Configuration key to retrieve
            default: Default value if key is not found

        Returns:
            The configuration value or default if not found

        Example:
            debug_mode = Config.get('DEBUG', False)
        """
        from flask import current_app

        try:
            return current_app.config.get(key, default)
        except RuntimeError:
            # If outside Flask application context
            cls.logger.warning(f"Attempted to access config key '{key}' outside application context")
            return default

    @classmethod
    def verify_integrity(cls) -> Dict[str, bool]:
        """
        Verify the integrity of monitored files.

        Returns:
            Dictionary reporting integrity status for each monitored file
        """
        from flask import current_app

        try:
            app = current_app

            # Try to use the integrated cs_file_integrity module first
            try:
                from core.security.cs_file_integrity import check_critical_file_integrity

                status, changes = check_critical_file_integrity(app)

                # If successful, format the result in the expected format
                integrity_status = {}

                if changes:  # If there are changes (integrity violations)
                    for change in changes:
                        path = change.get('path')
                        if path:
                            integrity_status[path] = False

                            # Log the issue with appropriate severity
                            severity = change.get('severity', 'medium')
                            status = change.get('status', 'unknown')

                            if severity == 'critical':
                                cls.security_logger.critical(
                                    f"Critical integrity violation: {path} ({status})"
                                )
                            elif severity == 'high':
                                cls.security_logger.error(
                                    f"High severity integrity violation: {path} ({status})"
                                )
                            else:
                                cls.security_logger.warning(
                                    f"Integrity violation: {path} ({status})"
                                )

                # Mark files that were checked and not modified as valid
                for file_path in app.config.get('CRITICAL_FILE_HASHES', {}):
                    if file_path not in integrity_status:
                        integrity_status[file_path] = True

                return integrity_status

            except ImportError:
                # Fall back to the basic implementation
                cls.security_logger.debug("Using basic file integrity check")

            # Basic implementation (fallback)
            integrity_status = {}

            # Check config files
            config_hashes = app.config.get('CONFIG_FILE_HASHES', {})
            for file_path, expected_hash in config_hashes.items():
                try:
                    algorithm = app.config.get('FILE_HASH_ALGORITHM', DEFAULT_HASH_ALGORITHM)
                    if os.path.getsize(file_path) > SMALL_FILE_THRESHOLD:
                        algorithm = 'sha256'

                    current_hash = cls._calculate_file_hash(file_path, algorithm)
                    integrity_status[file_path] = current_hash == expected_hash

                    if current_hash != expected_hash:
                        cls.security_logger.warning(
                            f"Integrity check failed for {file_path}",
                            extra={
                                "expected_hash": expected_hash,
                                "current_hash": current_hash
                            }
                        )
                except (IOError, OSError) as e:
                    cls.logger.error(f"Failed to verify file integrity for {file_path}: {str(e)}")
                    integrity_status[file_path] = False

            # Check critical files
            critical_hashes = app.config.get('CRITICAL_FILE_HASHES', {})
            for file_path, expected_hash in critical_hashes.items():
                try:
                    algorithm = app.config.get('FILE_HASH_ALGORITHM', DEFAULT_HASH_ALGORITHM)
                    current_hash = cls._calculate_file_hash(file_path, algorithm)
                    integrity_status[file_path] = current_hash == expected_hash

                    if current_hash != expected_hash:
                        cls.security_logger.warning(
                            f"Integrity check failed for critical file {file_path}",
                            extra={
                                "expected_hash": expected_hash,
                                "current_hash": current_hash,
                                "severity": "high"
                            }
                        )
                except (IOError, OSError) as e:
                    cls.logger.error(f"Failed to verify file integrity for critical file {file_path}: {str(e)}")
                    integrity_status[file_path] = False

            return integrity_status
        except RuntimeError:
            cls.logger.warning("Attempted to verify integrity outside application context")
            return {}

    @classmethod
    def get_allowed_extensions(cls) -> Set[str]:
        """
        Get the set of allowed file extensions for uploads.

        Returns:
            Set of allowed file extensions
        """
        try:
            from flask import current_app
            return set(current_app.config.get('ALLOWED_EXTENSIONS', set()))
        except RuntimeError:
            # Default if not in application context
            return {'pdf', 'png', 'jpg', 'jpeg', 'csv', 'xlsx'}

    @classmethod
    def is_production(cls) -> bool:
        """
        Check if the application is running in a production environment.

        Returns:
            True if in production, False otherwise
        """
        try:
            from flask import current_app
            return current_app.config.get('ENVIRONMENT', 'development').lower() == 'production'
        except RuntimeError:
            # Default to False if not in application context
            return False


# Import after Config definition to avoid circular imports
try:
    import redis
except ImportError:
    # Redis support is optional
    pass
