"""
Production environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config

class ProductionConfig(Config):
    """Configuration for production environment."""
    
    DEBUG = False
    TESTING = False
    ENV = 'production'
    
    # Strict security settings for production
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    
    # Production database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Redis for caching in production
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')
    
    # Rate limiting with Redis in production
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')
    
    # Sessions with Redis in production
    SESSION_TYPE = 'redis'
    
    # Sentry error reporting
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    SENTRY_ENVIRONMENT = 'production'
    SENTRY_TRACES_SAMPLE_RATE = 0.1
    
    # Enable strict file integrity checking in production
    SECURITY_CHECK_FILE_INTEGRITY = True
    
    # ICS security settings
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = os.environ.get('ICS_RESTRICTED_IPS', '').split(',')