"""
Base configuration class for Cloud Infrastructure Platform.
"""

from datetime import datetime, timedelta
import ipaddress
import json
import logging
import os
import secrets
import socket
from typing import Dict, Any, List, Optional, Tuple, Union
import subprocess

# Set up module logger
logger = logging.getLogger(__name__)

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
        'SECURITY_CRITICAL_FILES': [
            'app.py',
            'config.py',
            'core/security/*.py',
            'core/middleware.py'
        ],
        'ALLOWED_EXTENSIONS': {'pdf', 'png', 'jpg', 'jpeg', 'csv', 'xlsx'},
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16 MB

        # Feature flags
        'FEATURE_DARK_MODE': True,
        'FEATURE_ICS_CONTROL': True,
        'FEATURE_CLOUD_MANAGEMENT': True,
        'FEATURE_MFA': True,

        # Disaster Recovery settings
        'DR_MODE': False,
        'DR_ENHANCED_LOGGING': False,
        'DR_COORDINATOR_EMAIL': None,
        'DR_NOTIFICATION_ENABLED': False,
        'RECOVERY_MODE': False,
        'DR_BASELINE_FROZEN': True,  # Prevent baseline changes during DR
        'DR_RECOVERY_PRIORITIES': {
            'critical': ['authentication', 'authorization', 'core_services'],
            'high': ['data_access', 'api_endpoints', 'monitoring'],
            'medium': ['reporting', 'notifications', 'batch_jobs'],
            'low': ['ui_customization', 'analytics', 'non_critical_features']
        },

        # File Integrity Baseline settings
        'BASELINE_UPDATE_MAX_FILES': 50,
        'BASELINE_UPDATE_CRITICAL_THRESHOLD': 5,
        'BASELINE_BACKUP_ENABLED': True,
        'BASELINE_UPDATE_RETENTION': 5,
        'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
        'BASELINE_AUTO_UPDATE_PATTERN': [
            "*.css",
            "*.js",
            "static/*",
            "templates/*.html"
        ],
        'BASELINE_NEVER_AUTO_UPDATE': [
            "core/security/*.py",
            "app.py",
            "wsgi.py",
            "config/*.py"
        ],
        # Templates for baseline and backup paths
        'BASELINE_PATH_TEMPLATE': 'instance/security/baseline_{environment}.json',
        'BASELINE_BACKUP_PATH_TEMPLATE': 'instance/security/baseline_backups/{timestamp}_{environment}.json'
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
        'SECURITY_LOG_LEVEL': 'DEBUG',
        'API_REQUIRE_HTTPS': False,  # Allow HTTP in dev for easier testing
        'AUTO_UPDATE_BASELINE': True,  # Auto-update baseline in dev
        'BASELINE_UPDATE_APPROVAL_REQUIRED': False,  # No approval needed in dev
    }

    # Test-specific overrides
    TEST_OVERRIDES: Dict[str, Any] = {
        'TESTING': True,
        'DEBUG': False,
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost',
        'METRICS_ENABLED': False,
        'SECURITY_CHECK_FILE_INTEGRITY': False,
        'ENABLE_FILE_INTEGRITY_MONITORING': False,
        'AUDIT_LOG_ENABLED': False,  # Disable audit logging in tests
        'PRESERVE_CONTEXT_ON_EXCEPTION': False,
        'TRAP_HTTP_EXCEPTIONS': False,
    }

    # DR recovery-specific overrides
    DR_OVERRIDES: Dict[str, Any] = {
        'DEBUG': False,
        'LOG_LEVEL': 'WARNING',
        'AUTO_UPDATE_BASELINE': False,
        'DR_MODE': True,
        'DR_ENHANCED_LOGGING': True,
        'DR_BASELINE_FROZEN': True,
        'RECOVERY_MODE': True,
        'METRICS_DR_MODE': True,
        'SENTRY_ENVIRONMENT': 'dr-recovery',
        'SENTRY_TRACES_SAMPLE_RATE': 0.5,  # Higher sampling rate during DR
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'REMEMBER_COOKIE_SECURE': True,
        'REMEMBER_COOKIE_HTTPONLY': True,
        'API_REQUIRE_HTTPS': True,
        'SECURITY_CHECK_FILE_INTEGRITY': True,
        'ENABLE_FILE_INTEGRITY_MONITORING': True,
        'SECURITY_LOG_LEVEL': 'WARNING',
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
        'AUDIT_LOG_ENABLED',
    ]

    # Application settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY') or secrets.token_hex(32)
    SESSION_KEY = os.environ.get('SESSION_KEY') or secrets.token_hex(32)

    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///app.db')

    @classmethod
    def init_app(cls, app) -> None:
        """
        Initialize the application with configuration settings.

        Args:
            app: Flask application instance

        Raises:
            ValueError: If required environment variables are missing in production
        """
        # Load environment-specific configuration
        environment = os.environ.get('ENVIRONMENT', 'development').lower()

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
        elif environment == 'dr-recovery':
            for key, value in cls.DR_OVERRIDES.items():
                app.config[key] = value

        # Load settings from environment variables (highest priority)
        cls._load_from_environment(app)

        # Validate configuration
        cls._validate_configuration(app)

        # Setup derived values and special cases
        cls._setup_derived_values(app)

        # Configure extensions if method exists
        if hasattr(cls, '_configure_extensions') and callable(cls._configure_extensions):
            cls._configure_extensions(app)

        # Validate security settings if method exists
        if hasattr(cls, '_validate_security_settings') and callable(cls._validate_security_settings):
            cls._validate_security_settings(app)

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
                logger.info("File integrity monitoring initialized")

            except ImportError:
                # Fall back to basic file integrity checks
                app.config = cls.initialize_file_hashes(app.config, app.root_path)
                logger.info("Basic file integrity monitoring initialized (cs_file_integrity not available)")

        # Register config values to be accessible in the app context
        @app.context_processor
        def inject_config():
            """Make selected config values available in templates."""
            return {
                'config': {
                    'VERSION': app.config.get('VERSION', '1.0.0'),
                    'ENVIRONMENT': app.config.get('ENVIRONMENT', 'development'),
                    'FEATURE_DARK_MODE': app.config.get('FEATURE_DARK_MODE', True),
                    'FEATURE_ICS_CONTROL': app.config.get('FEATURE_ICS_CONTROL', True),
                    'FEATURE_CLOUD_MANAGEMENT': app.config.get('FEATURE_CLOUD_MANAGEMENT', True),
                    'FEATURE_MFA': app.config.get('FEATURE_MFA', True),
                    'DR_MODE': app.config.get('DR_MODE', False),
                    'RECOVERY_MODE': app.config.get('RECOVERY_MODE', False),
                }
            }

    @classmethod
    def _load_from_environment(cls, app) -> None:
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
            app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']

        # Handle ICS restricted IPs - parse as valid IP addresses
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
                            logger.warning(f"Invalid IP address or CIDR in ICS_RESTRICTED_IPS: {ip_str}")

                app.config['ICS_RESTRICTED_IPS'] = ip_list
            except ValueError as e:
                logger.error(f"Error parsing ICS_RESTRICTED_IPS: {str(e)}")

        # Load file integrity monitoring configuration
        cls._load_integrity_config_from_environment(app)

        # Load disaster recovery configuration
        cls._load_dr_config_from_environment(app)

    @classmethod
    def _load_integrity_config_from_environment(cls, app) -> None:
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
                    logger.warning("FILE_INTEGRITY_CHECK_INTERVAL too low, setting to 300 seconds minimum")
                app.config['FILE_INTEGRITY_CHECK_INTERVAL'] = interval
            except ValueError:
                logger.warning("Invalid FILE_INTEGRITY_CHECK_INTERVAL value, using default")

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
                    logger.warning("CRITICAL_FILES_PATTERN should be a JSON array, using default")
            except json.JSONDecodeError:
                # Try comma-separated list
                patterns = [p.strip() for p in os.environ['CRITICAL_FILES_PATTERN'].split(',') if p.strip()]
                if patterns:
                    app.config['CRITICAL_FILES_PATTERN'] = patterns

        # Baseline update configuration
        if 'BASELINE_UPDATE_MAX_FILES' in os.environ:
            try:
                app.config['BASELINE_UPDATE_MAX_FILES'] = int(os.environ['BASELINE_UPDATE_MAX_FILES'])
            except ValueError:
                logger.warning("Invalid BASELINE_UPDATE_MAX_FILES value, using default")

        if 'BASELINE_UPDATE_RETENTION' in os.environ:
            try:
                app.config['BASELINE_UPDATE_RETENTION'] = int(os.environ['BASELINE_UPDATE_RETENTION'])
            except ValueError:
                logger.warning("Invalid BASELINE_UPDATE_RETENTION value, using default")

        if 'BASELINE_UPDATE_APPROVAL_REQUIRED' in os.environ:
            app.config['BASELINE_UPDATE_APPROVAL_REQUIRED'] = cls._convert_env_value(
                os.environ['BASELINE_UPDATE_APPROVAL_REQUIRED']
            )

        if 'BASELINE_BACKUP_ENABLED' in os.environ:
            app.config['BASELINE_BACKUP_ENABLED'] = cls._convert_env_value(
                os.environ['BASELINE_BACKUP_ENABLED']
            )

        # Custom baseline paths
        if 'BASELINE_PATH_TEMPLATE' in os.environ:
            app.config['BASELINE_PATH_TEMPLATE'] = os.environ['BASELINE_PATH_TEMPLATE']

        if 'BASELINE_BACKUP_PATH_TEMPLATE' in os.environ:
            app.config['BASELINE_BACKUP_PATH_TEMPLATE'] = os.environ['BASELINE_BACKUP_PATH_TEMPLATE']

        # File hash algorithm
        if 'FILE_HASH_ALGORITHM' in os.environ:
            algorithm = os.environ['FILE_HASH_ALGORITHM'].lower()
            # Validate that it's a supported algorithm
            if algorithm in ('sha256', 'sha384', 'sha512', 'sha1', 'md5'):
                app.config['FILE_HASH_ALGORITHM'] = algorithm
                if algorithm in ('sha1', 'md5'):
                    logger.warning(f"Using weak hash algorithm {algorithm} - consider using SHA-256 or stronger")
            else:
                logger.warning(f"Unsupported hash algorithm {algorithm}, defaulting to SHA-256")

    @classmethod
    def _load_dr_config_from_environment(cls, app) -> None:
        """
        Load disaster recovery configuration from environment variables.

        Args:
            app: Flask application instance
        """
        # DR mode enabled/disabled
        if 'DR_MODE' in os.environ:
            app.config['DR_MODE'] = cls._convert_env_value(os.environ['DR_MODE'])

        # Recovery mode enabled/disabled
        if 'RECOVERY_MODE' in os.environ:
            app.config['RECOVERY_MODE'] = cls._convert_env_value(os.environ['RECOVERY_MODE'])

        # DR enhanced logging
        if 'DR_ENHANCED_LOGGING' in os.environ:
            app.config['DR_ENHANCED_LOGGING'] = cls._convert_env_value(os.environ['DR_ENHANCED_LOGGING'])

        # DR log path
        if 'DR_LOG_PATH' in os.environ:
            app.config['DR_LOG_PATH'] = os.environ['DR_LOG_PATH']

        # DR coordinator email
        if 'DR_COORDINATOR_EMAIL' in os.environ:
            app.config['DR_COORDINATOR_EMAIL'] = os.environ['DR_COORDINATOR_EMAIL']

        # DR notification enabled
        if 'DR_NOTIFICATION_ENABLED' in os.environ:
            app.config['DR_NOTIFICATION_ENABLED'] = cls._convert_env_value(os.environ['DR_NOTIFICATION_ENABLED'])

        # Metrics DR mode
        if 'METRICS_DR_MODE' in os.environ:
            app.config['METRICS_DR_MODE'] = cls._convert_env_value(os.environ['METRICS_DR_MODE'])

        # DR baseline frozen status - controls whether baseline updates are prohibited in DR mode
        if 'DR_BASELINE_FROZEN' in os.environ:
            app.config['DR_BASELINE_FROZEN'] = cls._convert_env_value(os.environ['DR_BASELINE_FROZEN'])

        # DR recovery priorities
        if 'DR_RECOVERY_PRIORITIES' in os.environ:
            try:
                priorities = json.loads(os.environ['DR_RECOVERY_PRIORITIES'])
                if isinstance(priorities, dict):
                    app.config['DR_RECOVERY_PRIORITIES'] = priorities
                else:
                    logger.warning("DR_RECOVERY_PRIORITIES should be a JSON object, using default")
            except json.JSONDecodeError:
                logger.warning("Invalid DR_RECOVERY_PRIORITIES value, using default")

    @staticmethod
    def _convert_env_value(value: str) -> Any:
        """
        Convert environment variable string to appropriate Python type.

        Args:
            value: String value from environment variable

        Returns:
            Value converted to appropriate type (bool, int, float, str)
        """
        if value.lower() in ('true', 'yes', '1'):
            return True
        elif value.lower() in ('false', 'no', '0'):
            return False
        elif value.isdigit():
            return int(value)
        elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
            return float(value)
        return value

    @classmethod
    def _validate_configuration(cls, app) -> None:
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
        if environment not in ('production', 'staging', 'dr-recovery'):
            return

        # Check required variables in production
        missing_vars = []
        for var in cls.REQUIRED_VARS:
            if var not in app.config or not app.config[var]:
                missing_vars.append(var)

        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # Check security settings in production and DR
        insecure_settings = []
        for setting in cls.PROD_REQUIREMENTS:
            if setting in app.config and not app.config[setting]:
                insecure_settings.append(setting)

        if insecure_settings:
            logger.error(f"Insecure settings in production: {', '.join(insecure_settings)}")
            raise ValueError(f"Insecure settings in production: {', '.join(insecure_settings)}")

        # Check for development SECRET_KEY in production
        if app.config.get('SECRET_KEY') in ('dev', 'development', 'secret', 'changeme'):
            logger.error("Development SECRET_KEY used in production environment")
            raise ValueError("Development SECRET_KEY used in production environment")

        # Check if file integrity monitoring is disabled in production
        if not app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            logger.warning("File integrity monitoring disabled in production environment")

        # Check auto-update baseline in production (should be false)
        if app.config.get('AUTO_UPDATE_BASELINE', False):
            logger.warning("AUTO_UPDATE_BASELINE should be disabled in production")

        # Check if audit logging is properly configured
        if app.config.get('AUDIT_LOG_ENABLED', True) and app.config.get('AUDIT_LOG_RETENTION_DAYS', 90) < 30:
            logger.warning("AUDIT_LOG_RETENTION_DAYS should be at least 30 days in production")

        # Validate DR-specific settings
        if environment == 'dr-recovery':
            if app.config.get('DR_MODE') is not True:
                logger.warning("DR_MODE should be True in dr-recovery environment")

            if not app.config.get('DR_LOG_PATH'):
                logger.warning("DR_LOG_PATH should be configured in dr-recovery environment")

            if not app.config.get('DR_COORDINATOR_EMAIL'):
                logger.warning("DR_COORDINATOR_EMAIL should be configured in dr-recovery environment")

            if app.config.get('AUTO_UPDATE_BASELINE', False):
                logger.error("AUTO_UPDATE_BASELINE must be disabled in dr-recovery environment")

            # Check if baseline is appropriately frozen in DR mode
            if not app.config.get('DR_BASELINE_FROZEN', True):
                logger.warning("DR_BASELINE_FROZEN should be enabled in dr-recovery environment")

            # Check DR recovery priorities are defined
            if not app.config.get('DR_RECOVERY_PRIORITIES'):
                logger.warning("DR_RECOVERY_PRIORITIES should be configured in dr-recovery environment")

    @classmethod
    def _setup_derived_values(cls, app) -> None:
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
            app.config['SESSION_REDIS'] = os.environ['REDIS_URL']
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
                logger.info(f"Created upload directory: {uploads_path}")
        except (IOError, OSError) as e:
            logger.error(f"Failed to create upload directory {uploads_path}: {str(e)}")

        # Generate a self-identification string for logs/metrics
        hostname = socket.gethostname()
        app.config['INSTANCE_IDENTIFIER'] = f"{hostname}-{os.getpid()}"

        # Set application version (try to get from Git if available)
        if 'VERSION' not in app.config:
            try:
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--always'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                app.config['VERSION'] = result.stdout.decode('utf-8').strip()
            except subprocess.CalledProcessError:
                app.config['VERSION'] = '1.0.0'

        # Set up file baseline path if file integrity monitoring is enabled
        if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
            env = app.config.get('ENVIRONMENT', 'development')

            # Set environment-specific baseline path
            if 'FILE_BASELINE_PATH' not in app.config or not app.config['FILE_BASELINE_PATH']:
                baseline_path_template = app.config.get('BASELINE_PATH_TEMPLATE',
                                                      'instance/security/baseline_{environment}.json')
                baseline_path = baseline_path_template.format(environment=env)
                app.config['FILE_BASELINE_PATH'] = os.path.join(app.root_path, baseline_path)

            # Ensure baseline directory exists
            try:
                os.makedirs(os.path.dirname(app.config['FILE_BASELINE_PATH']), exist_ok=True)
            except OSError as e:
                logger.error(f"Failed to create baseline directory: {str(e)}")

            # Set up baseline backup directory if backup enabled
            if app.config.get('BASELINE_BACKUP_ENABLED', True):
                backup_path_template = app.config.get('BASELINE_BACKUP_PATH_TEMPLATE',
                                                    'instance/security/baseline_backups/{timestamp}_{environment}.json')
                backup_dir = os.path.dirname(os.path.join(app.root_path,
                                                        backup_path_template.format(timestamp='', environment=env)))

                try:
                    if not os.path.exists(backup_dir):
                        os.makedirs(backup_dir, mode=0o750, exist_ok=True)
                        logger.info(f"Created baseline backup directory: {backup_dir}")
                except OSError as e:
                    logger.error(f"Failed to create baseline backup directory: {str(e)}")

            # Set up the default hash algorithm from config
            if 'FILE_HASH_ALGORITHM' not in app.config:
                app.config['FILE_HASH_ALGORITHM'] = 'sha256'

        # Set up DR log directory if in DR mode
        if app.config.get('DR_MODE', False) and app.config.get('DR_ENHANCED_LOGGING', False):
            dr_log_path = app.config.get('DR_LOG_PATH', '/var/log/cloud-platform/dr-events.log')
            try:
                log_dir = os.path.dirname(dr_log_path)
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir, mode=0o750, exist_ok=True)
                    logger.info(f"Created DR log directory: {log_dir}")
            except OSError as e:
                logger.error(f"Failed to create DR log directory: {str(e)}")

    @staticmethod
    def load_from_name(name: str) -> Dict[str, Any]:
        """
        Load configuration by environment name.

        This method provides predefined configuration sets for common
        environments (development, production, testing), allowing for
        quick configuration switching.

        Args:
            name (str): Environment name ('development', 'production', 'testing',
                       'dr-recovery')

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
                'AUTO_UPDATE_BASELINE': True,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': False,
            },
            'production': {
                'DEBUG': False,
                'TESTING': False,
                'ENABLE_AUTO_COUNTERMEASURES': True,
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SAMESITE': 'Lax',
                'AUTO_UPDATE_BASELINE': False,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
            },
            'testing': {
                'DEBUG': False,
                'TESTING': True,
                'ENABLE_AUTO_COUNTERMEASURES': False,
                'WTF_CSRF_ENABLED': False,
                'SESSION_COOKIE_SECURE': False,
                'ENABLE_FILE_INTEGRITY_MONITORING': False,
                'BASELINE_BACKUP_ENABLED': False,
            },
            'dr-recovery': {
                'DEBUG': False,
                'TESTING': False,
                'DR_MODE': True,
                'RECOVERY_MODE': True,
                'DR_ENHANCED_LOGGING': True,
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True,
                'AUTO_UPDATE_BASELINE': False,
                'DR_BASELINE_FROZEN': True,
                'LOG_LEVEL': 'WARNING',
                'METRICS_DR_MODE': True,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': True,
            },
            'ci': {
                'TESTING': True,
                'DEBUG': False,
                'METRICS_ENABLED': False,
                'ENABLE_FILE_INTEGRITY_MONITORING': False,
                'BASELINE_BACKUP_ENABLED': False,
                'BASELINE_UPDATE_APPROVAL_REQUIRED': False,
                'CI_SKIP_INTEGRITY_CHECK': True,
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
        integrity monitoring during application runtime. It uses the specified
        hash algorithm for files, with SHA-256 as the default for performance reasons.

        Args:
            config: Current application configuration dictionary
            app_root: Application root directory path

        Returns:
            Dict[str, Any]: Updated configuration with file hashes

        Example:
            app.config = Config.initialize_file_hashes(app.config, app_root_path)
        """
        try:
            from core.utils import calculate_file_hash
        except ImportError:
            logger.error("Could not import calculate_file_hash from core.utils")
            return config

        # Only compute hashes if file integrity monitoring is enabled
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
            os.path.join(app_root, 'core', 'security', '__init__.py'),
            os.path.join(app_root, 'core', 'security', 'cs_audit.py'),
            os.path.join(app_root, 'core', 'security', 'cs_file_integrity.py'),
            os.path.join(app_root, 'core', 'auth.py'),
            os.path.join(app_root, 'extensions.py'),
            os.path.join(app_root, 'blueprints', 'monitoring', 'routes.py'),
            os.path.join(app_root, 'models', 'audit_log.py'),
            os.path.join(app_root, 'models', 'security_incident.py'),
            os.path.join(app_root, 'models', 'user.py')
        ]

        # For DR environment, include DR-specific files
        if config.get('DR_MODE', False):
            critical_files.extend([
                os.path.join(app_root, 'config', 'dr_recovery.py'),
                os.path.join(app_root, 'services', 'dr_service.py'),
                os.path.join(app_root, 'scripts', 'dr', 'recovery_verification.py'),
            ])

        # Compute hashes for config files - use algorithm based on file size
        config_hashes = {}
        algorithm = config.get('FILE_HASH_ALGORITHM', 'sha256')
        small_file_threshold = config.get('SMALL_FILE_THRESHOLD', 10240)  # 10KB default

        for file_path in config_files:
            if os.path.exists(file_path):
                try:
                    file_size = os.path.getsize(file_path)
                    # For security-critical but small config files, we can use a stronger hash
                    if file_size < small_file_threshold:
                        config_hashes[file_path] = calculate_file_hash(file_path, algorithm)
                    else:
                        # For larger files, use SHA-256 for better performance
                        config_hashes[file_path] = calculate_file_hash(file_path, 'sha256')
                except (IOError, OSError) as e:
                    logger.warning(f"Could not hash config file {file_path}: {e}")

        # Compute hashes for critical files
        critical_hashes = {}
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    critical_hashes[file_path] = calculate_file_hash(file_path, algorithm)
                except (IOError, OSError) as e:
                    logger.warning(f"Could not hash critical file {file_path}: {e}")

        # Add monitored directories (these will be checked for unexpected files)
        monitored_directories = [
            os.path.join(app_root, 'core'),
            os.path.join(app_root, 'core', 'security'),
            os.path.join(app_root, 'models'),
            os.path.join(app_root, 'models', 'security'),
            os.path.join(app_root, 'blueprints', 'auth'),
            os.path.join(app_root, 'blueprints', 'monitoring'),
            os.path.join(app_root, 'config'),  # Monitor configuration directory
        ]

        # Add DR-specific directories if in DR mode
        if config.get('DR_MODE', False):
            monitored_directories.extend([
                os.path.join(app_root, 'scripts', 'dr'),
                os.path.join(app_root, 'services', 'recovery')
            ])

        config['MONITORED_DIRECTORIES'] = monitored_directories

        # Update configuration
        config['CONFIG_FILE_HASHES'] = config_hashes
        config['CRITICAL_FILE_HASHES'] = critical_hashes
        config['FILE_HASH_TIMESTAMP'] = cls.format_timestamp()

        return config

    @staticmethod
    def format_timestamp() -> str:
        """Format current datetime as ISO 8601 string."""
        return datetime.utcnow().isoformat()

    @classmethod
    def update_file_integrity_baseline(
            cls,
            app=None,
            baseline_path=None,
            updates=None,
            remove_missing=False,
            auto_update_limit: int = 10) -> Tuple[bool, str]:
        """
        Update the file integrity baseline with new hash values.

        This function imports the actual implementation from core.security.cs_file_integrity
        if available, or falls back to a basic implementation. It supports configurable
        auto-update limits and makes baseline backups before updates.

        Args:
            app: Flask application instance
            baseline_path: Path to baseline file (uses app config if None)
            updates: List of change dictionaries to incorporate into baseline
            remove_missing: Whether to remove entries for files that no longer exist
            auto_update_limit: Maximum number of files to auto-update (safety limit)

        Returns:
            tuple: (success_bool, message_string)
        """
        # Check for DR mode restrictions
        if app and app.config.get('DR_MODE', False) and app.config.get('DR_BASELINE_FROZEN', True):
            if not baseline_path:
                baseline_path = app.config.get('FILE_BASELINE_PATH', 'instance/file_baseline.json')
            logger.warning(f"Baseline update attempted in DR mode: {baseline_path}")
            return False, "Baseline updates are restricted in DR recovery mode"

        try:
            from core.security.cs_file_integrity import update_file_integrity_baseline as core_update
            return core_update(app, baseline_path, updates, remove_missing, auto_update_limit)
        except ImportError:
            logger.warning("Could not import update_file_integrity_baseline from core.security.cs_file_integrity")

            # Try fallback implementation
            try:
                from core.utils import update_file_integrity_baseline as utils_update
                return utils_update(app, baseline_path, updates, remove_missing)
            except ImportError:
                logger.error("No file integrity baseline update implementation available")

                # Try implementing baseline update as standalone functionality
                try:
                    return cls._update_baseline_fallback(app, baseline_path, updates, remove_missing, auto_update_limit)
                except Exception as e:
                    logger.error(f"Failed to update baseline with fallback implementation: {str(e)}")
                    return False, f"File integrity functions not available: {str(e)}"

    @classmethod
    def _update_baseline_fallback(
            cls,
            app=None,
            baseline_path=None,
            updates=None,
            remove_missing=False,
            auto_update_limit=10) -> Tuple[bool, str]:
        """
        Fallback implementation of baseline update when core utilities are unavailable.

        Args:
            app: Flask application instance
            baseline_path: Path to baseline file
            updates: List of update dictionaries
            remove_missing: Whether to remove missing files
            auto_update_limit: Maximum number of files to update

        Returns:
            tuple: (success_bool, message_string)
        """
        import json
        import os
        from datetime import datetime

        if not updates:
            return True, "No updates provided"

        # Enforce update limit for safety
        if len(updates) > auto_update_limit:
            logger.warning(f"Too many files to update: {len(updates)} exceeds limit of {auto_update_limit}")
            updates = updates[:auto_update_limit]

        # Determine baseline path
        if app and not baseline_path:
            baseline_path = app.config.get('FILE_BASELINE_PATH')
            if not baseline_path:
                return False, "Baseline path not configured"

        # Load existing baseline or create new one
        baseline = {}
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, 'r') as f:
                    baseline = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                return False, f"Failed to read baseline file: {e}"

        # Create backup of baseline
        try:
            backup_path = f"{baseline_path}.{int(datetime.now().timestamp())}.bak"
            with open(backup_path, 'w') as f:
                json.dump(baseline, f, indent=2)
                logger.info(f"Created baseline backup at {backup_path}")
        except (IOError, OSError) as e:
            logger.warning(f"Failed to create baseline backup: {e}")

        # Process updates
        changes_applied = 0
        for update in updates:
            if not isinstance(update, dict):
                continue

            path = update.get('path')
            current_hash = update.get('current_hash') or update.get('hash')

            if not path or not current_hash:
                continue

            # Handle absolute vs relative paths
            if app and not os.path.isabs(path):
                abs_path = os.path.normpath(os.path.join(os.path.dirname(app.root_path), path))
            else:
                abs_path = path

            # Only update if file exists (prevents poisoning baseline with non-existent files)
            if os.path.exists(abs_path):
                baseline[path] = current_hash
                changes_applied += 1
            else:
                logger.warning(f"Skipping non-existent file in baseline update: {path}")

        # Remove missing files if requested
        removed = 0
        if remove_missing:
            to_remove = []
            for path in baseline:
                # Handle absolute vs relative paths for checking existence
                if app and not os.path.isabs(path):
                    abs_path = os.path.normpath(os.path.join(os.path.dirname(app.root_path), path))
                else:
                    abs_path = path

                if not os.path.exists(abs_path):
                    to_remove.append(path)

            for path in to_remove:
                del baseline[path]
                removed += 1

        # Write updated baseline
        try:
            os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
            with open(baseline_path, 'w') as f:
                json.dump(baseline, f, indent=2)
        except (IOError, OSError) as e:
            return False, f"Failed to write baseline file: {e}"

        # Also update app config if provided
        if app:
            app.config['CRITICAL_FILE_HASHES'] = baseline
            app.config['FILE_HASH_TIMESTAMP'] = cls.format_timestamp()

        return True, f"Updated baseline: {changes_applied} changes applied, {removed} entries removed"

    @classmethod
    def baseline_status(cls, app=None, baseline_path=None) -> Dict[str, Any]:
        """
        Get the status of the file integrity baseline.

        Returns information about the baseline including last modification time,
        number of files monitored, and configuration details.

        Args:
            app: Flask application instance
            baseline_path: Path to baseline file (uses app config if None)

        Returns:
            Dict containing baseline status information
        """
        import os
        import time

        status = {
            'exists': False,
            'timestamp': None,
            'file_count': 0,
            'last_modified': None,
            'algorithm': 'sha256',
            'monitoring_enabled': False,
        }

        # Set baseline path
        if app and not baseline_path:
            baseline_path = app.config.get('FILE_BASELINE_PATH')
            if not baseline_path:
                status['error'] = "Baseline path not configured"
                return status

        # Update status from app config if available
        if app:
            status['monitoring_enabled'] = app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', False)
            status['algorithm'] = app.config.get('FILE_HASH_ALGORITHM', 'sha256')
            status['timestamp'] = app.config.get('FILE_HASH_TIMESTAMP')

            # If hashes are available in config, count them
            file_hashes = app.config.get('CRITICAL_FILE_HASHES', {})
            if file_hashes:
                status['file_count'] = len(file_hashes)
                status['exists'] = True

        # Check file system status
        if baseline_path and os.path.exists(baseline_path):
            status['exists'] = True
            status['last_modified'] = time.ctime(os.path.getmtime(baseline_path))

            # Try to get file count if not already set from config
            if status['file_count'] == 0:
                try:
                    import json
                    with open(baseline_path, 'r') as f:
                        baseline = json.load(f)
                    status['file_count'] = len(baseline)
                except (IOError, json.JSONDecodeError):
                    pass

        return status
