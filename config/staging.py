"""
Staging environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config

class StagingConfig(Config):
    """Configuration for staging environment."""
    
    DEBUG = False
    TESTING = False
    ENV = 'staging'
    
    # Security settings for staging (same as production)
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    
    # Staging-specific database
    SQLALCHEMY_DATABASE_URI = os.environ.get('STAGING_DATABASE_URL')
    
    # Redis for caching in staging
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('STAGING_REDIS_URL')
    RATELIMIT_STORAGE_URL = os.environ.get('STAGING_REDIS_URL')
    
    # Sentry error reporting for staging
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    SENTRY_ENVIRONMENT = 'staging'
    SENTRY_TRACES_SAMPLE_RATE = 0.2
    
    # Enable file integrity checking in staging
    SECURITY_CHECK_FILE_INTEGRITY = True