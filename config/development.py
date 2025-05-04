"""
Development environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config

class DevelopmentConfig(Config):
    """Configuration for development environment."""

    DEBUG = True
    TESTING = False
    ENV = 'development'

    # Security settings relaxed for development
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

    # Enable debug toolbar in development
    DEBUG_TB_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    # Development-specific logging
    LOG_LEVEL = 'DEBUG'

    # In-memory cache for development
    CACHE_TYPE = 'SimpleCache'

    # ICS development settings
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = ['127.0.0.1']

    # File integrity monitoring settings for development
    SECURITY_CHECK_FILE_INTEGRITY = False

    # Auto-update baseline for non-critical file changes in development
    AUTO_UPDATE_BASELINE = True

    # Allow HTTP in development for easier testing
    API_REQUIRE_HTTPS = False
