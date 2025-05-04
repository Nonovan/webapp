"""
Testing environment configuration for Cloud Infrastructure Platform.
"""

import os
from .base import Config
from .config_constants import ENVIRONMENT_TESTING

class TestingConfig(Config):
    """Configuration for testing environment."""

    DEBUG = False
    TESTING = True
    ENV = ENVIRONMENT_TESTING

    # Test database (in-memory SQLite by default)
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///:memory:')

    # Disable CSRF protection during testing
    WTF_CSRF_ENABLED = False

    # Disable security features that might interfere with tests
    SECURITY_HEADERS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False
    ENABLE_FILE_INTEGRITY_MONITORING = False

    # Simple in-memory cache for testing
    CACHE_TYPE = 'SimpleCache'

    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False

    # Disable metrics in testing
    METRICS_ENABLED = False

    # Disable audit logging in tests for cleaner test output
    AUDIT_LOG_ENABLED = False

    # Auto-update baseline should be disabled in test environment
    AUTO_UPDATE_BASELINE = False

    # Session and cookie security settings for testing
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

    # Allow HTTP in testing environment
    API_REQUIRE_HTTPS = False

    # Enable all features for testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True
    ICS_ENABLED = True

    # Testing-specific logging - minimize noise but capture errors
    LOG_LEVEL = 'ERROR'
