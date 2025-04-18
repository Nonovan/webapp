# config/environments.py
"""
Environment-specific configurations for Cloud Infrastructure Platform.
"""

from .base import Config

class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    ENV = 'development'
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    DEBUG_TB_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    LOG_LEVEL = 'DEBUG'
    CACHE_TYPE = 'SimpleCache'
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = ['127.0.0.1']
    SECURITY_CHECK_FILE_INTEGRITY = False
    
class ProductionConfig(Config):
    """Production environment configuration."""
    ENV = 'production'
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    SECURITY_CHECK_FILE_INTEGRITY = True
    SECURITY_LOG_LEVEL = 'WARNING'
    # Add production-specific settings

class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SERVER_NAME = 'localhost'
    METRICS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

class StagingConfig(Config):
    """Staging environment configuration."""
    ENV = 'staging'
    DEBUG = False
    LOG_LEVEL = 'INFO'
    SECURITY_CHECK_FILE_INTEGRITY = True
    SENTRY_ENVIRONMENT = 'staging'
    SENTRY_TRACES_SAMPLE_RATE = 0.2
    # Add staging-specific settings

class CIConfig(Config):
    """CI environment configuration."""
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    ENV = 'ci'
    # Add CI-specific settings
