"""
Base configuration class for Cloud Infrastructure Platform.
"""

from datetime import timedelta
import ipaddress
import logging
import os
import secrets
import socket
from typing import Dict, Any, List
import subprocess

class Config:
    """Base configuration class with common settings."""
    
    # Required environment variables
    REQUIRED_VARS = [
        'SECRET_KEY',
        'DATABASE_URL',
        'JWT_SECRET_KEY',
        'CSRF_SECRET_KEY',
        'SESSION_KEY'
    ]
    
    # Default settings
    ENV_DEFAULTS = {
        'ENVIRONMENT': 'development',
        'DEBUG': False,
        'TESTING': False,
        'SERVER_NAME': None,
        # Add all your default settings here from both current config files
    }
    
    # Security validation for production environments
    PROD_REQUIREMENTS = [
        'SESSION_COOKIE_SECURE',
        'SESSION_COOKIE_HTTPONLY',
        'REMEMBER_COOKIE_SECURE',
        'REMEMBER_COOKIE_HTTPONLY',
        'WTF_CSRF_ENABLED',
        'SECURITY_HEADERS_ENABLED',
    ]
    
    @classmethod
    def init_app(cls, app):
        """Initialize application with configuration."""
        cls._load_from_environment(app)
        cls._setup_derived_values(app)
        cls._validate_security_settings(app)
        cls._configure_extensions(app)
        
        # Only calculate file hashes if security check is enabled
        if app.config.get('SECURITY_CHECK_FILE_INTEGRITY', False):
            cls.initialize_file_hashes(app.config, app.root_path)
        
        # Make selected config values available in templates
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
                }
            }
    
    # Application settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY') or secrets.token_hex(32)
    SESSION_KEY = os.environ.get('SESSION_KEY') or secrets.token_hex(32)
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 280,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20
    }
    
    # Security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    
    # Security headers
    SECURITY_HEADERS_ENABLED = True
    SECURITY_CSP_REPORT_URI = None
    SECURITY_HSTS_MAX_AGE = 31536000  # 1 year
    SECURITY_INCLUDE_SUBDOMAINS = True
    SECURITY_PRELOAD = True
    
    # CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Rate limiting
    RATELIMIT_DEFAULT = '200 per day, 50 per hour'
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STRATEGY = 'fixed-window'
    
    # Cache settings
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Logging settings
    LOG_LEVEL = 'INFO'
    SECURITY_LOG_LEVEL = 'WARNING'
    
    # File security settings
    SECURITY_CHECK_FILE_INTEGRITY = True
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'csv', 'xlsx'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    
    # Feature flags
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True
    
    # Cloud settings
    CLOUD_PROVIDERS = ['aws', 'azure', 'gcp']
    CLOUD_METRICS_INTERVAL = 300  # 5 minutes
    CLOUD_RESOURCES_CACHE_TTL = 600  # 10 minutes
    
    # ICS system settings
    ICS_ENABLED = False
    ICS_MONITOR_INTERVAL = 60  # seconds
    ICS_ALERT_THRESHOLD = 0.8  # 80%


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
        'FEATURE_MFA': True
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
    }

    # Test-specific overrides
    TEST_OVERRIDES: Dict[str, Any] = {
        'TESTING': True,
        'DEBUG': False,
        'WTF_CSRF_ENABLED': False,
        'SERVER_NAME': 'localhost',
        'METRICS_ENABLED': False,
        'SECURITY_CHECK_FILE_INTEGRITY': False,
    }

    # Production-specific security requirements
    PROD_REQUIREMENTS: List[str] = [
        'SESSION_COOKIE_SECURE',
        'SESSION_COOKIE_HTTPONLY',
        'REMEMBER_COOKIE_SECURE',
        'REMEMBER_COOKIE_HTTPONLY',
        'WTF_CSRF_ENABLED',
        'SECURITY_HEADERS_ENABLED',
    ]

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

        # Load settings from environment variables (highest priority)
        cls._load_from_environment(app)

        # Validate configuration
        cls._validate_configuration(app)

        # Setup derived values and special cases
        cls._setup_derived_values(app)

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

                # Handle boolean values
                if value.lower() in ('true', 'yes', '1'):
                    app.config[app_key] = True
                elif value.lower() in ('false', 'no', '0'):
                    app.config[app_key] = False
                # Handle integer values
                elif value.isdigit():
                    app.config[app_key] = int(value)
                # Handle float values
                elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                    app.config[app_key] = float(value)
                else:
                    app.config[app_key] = value

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
                            logging.warning("Invalid IP address or CIDR in ICS_RESTRICTED_IPS: %s", ip_str)

                app.config['ICS_RESTRICTED_IPS'] = ip_list
            except ValueError as e:
                logging.error("Error parsing ICS_RESTRICTED_IPS: %s", str(e))

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
        if environment not in ('production', 'staging'):
            return

        # Check required variables in production
        missing_vars = []
        for var in cls.REQUIRED_VARS:
            if var not in app.config or not app.config[var]:
                missing_vars.append(var)

        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # Check security settings in production
        insecure_settings = []
        for setting in cls.PROD_REQUIREMENTS:
            if setting in app.config and not app.config[setting]:
                insecure_settings.append(setting)

        if insecure_settings:
            raise ValueError(f"Insecure settings in production: {', '.join(insecure_settings)}")

        # Check for development SECRET_KEY in production
        if app.config.get('SECRET_KEY') == 'dev':
            raise ValueError("Development SECRET_KEY used in production environment")

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
        app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
        integrity monitoring during application runtime. It uses the Argon2 
        algorithm for advanced hashing security where appropriate, and falls
        back to SHA-256 for larger files for performance reasons.
        
        Args:
            config: Current application configuration dictionary
            app_root: Application root directory path
            
        Returns:
            Dict[str, Any]: Updated configuration with file hashes
            
        Example:
            app.config = Config.initialize_file_hashes(app.config, app_root_path)
        """
        from core.utils import calculate_file_hash

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
            os.path.join(app_root, 'core', 'security.py'),
            os.path.join(app_root, 'core', 'auth.py'),
            os.path.join(app_root, 'extensions.py'),
            os.path.join(app_root, 'blueprints', 'monitoring', 'routes.py'),
            os.path.join(app_root, 'models', 'audit_log.py'),
            os.path.join(app_root, 'models', 'security_incident.py'),
            os.path.join(app_root, 'models', 'user.py')
        ]

        # Compute hashes for config files - use algorithm based on file size
        config_hashes = {}
        algorithm = config.get('FILE_HASH_ALGORITHM', 'sha256')

        for file_path in config_files:
            if os.path.exists(file_path):
                try:
                    file_size = os.path.getsize(file_path)
                    # For security-critical but small config files, we can use a stronger hash
                    if file_size < 1024 * 10:  # 10KB or smaller
                        config_hashes[file_path] = calculate_file_hash(file_path, algorithm)
                    else:
                        # For larger files, use SHA-256 for better performance
                        config_hashes[file_path] = calculate_file_hash(file_path, 'sha256')
                except (IOError, OSError) as e:
                    logging.warning("Could not hash config file %s: %s", file_path, e)

        # Compute hashes for critical files
        critical_hashes = {}
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    critical_hashes[file_path] = calculate_file_hash(file_path, algorithm)
                except (IOError, OSError) as e:
                    logging.warning("Could not hash critical file %s: %s", file_path, e)

        # Add monitored directories (these will be checked for unexpected files)
        monitored_directories = [
            os.path.join(app_root, 'core'),
            os.path.join(app_root, 'models'),
            os.path.join(app_root, 'blueprints', 'auth'),
            os.path.join(app_root, 'blueprints', 'monitoring')
        ]
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
