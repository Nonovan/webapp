"""
Testing environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config

class TestingConfig(Config):
    """Configuration for testing environment."""
    
    DEBUG = False
    TESTING = True
    ENV = 'testing'
    
    # Test database (in-memory SQLite by default)
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///:memory:')
    
    # Disable CSRF protection during testing
    WTF_CSRF_ENABLED = False
    
    # Disable security features that might interfere with tests
    SECURITY_HEADERS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False
    
    # Simple in-memory cache for testing
    CACHE_TYPE = 'SimpleCache'
    
    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False
    
    # Disable metrics in testing
    METRICS_ENABLED = False
    
    # Enable all features for testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True
    ICS_ENABLED = True