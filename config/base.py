"""
Base configuration settings for Cloud Infrastructure Platform.

This module defines the base configuration class that all environment-specific
configurations inherit from, establishing common settings and defaults.
"""

import os
import secrets
from datetime import timedelta
from typing import Dict, Any, List

class Config:
    """
    Base configuration class with common settings.
    
    All environment-specific configurations should inherit from this class
    and override settings as needed.
    """
    
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