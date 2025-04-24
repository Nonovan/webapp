"""
CI environment configuration for Cloud Infrastructure Platform.

This module defines the configuration settings specifically for
the continuous integration environment. It disables certain features
that would interfere with automated testing while enabling others
that facilitate comprehensive test coverage.
"""

import os
from .base import Config

class CIConfig(Config):
    """Configuration for continuous integration environment.

    This configuration is optimized for automated testing in CI pipelines,
    with settings that promote test isolation, deterministic behavior,
    and comprehensive feature testing without external dependencies.
    """

    DEBUG = False
    TESTING = True
    ENV = 'ci'

    # Database settings - use in-memory SQLite for speed and isolation
    SQLALCHEMY_DATABASE_URI = os.environ.get('CI_DATABASE_URL', 'sqlite:///:memory:')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Disable security features that interfere with automated tests
    WTF_CSRF_ENABLED = False
    SECURITY_HEADERS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False

    # Disable session security requirements for testing
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

    # Simple in-memory cache for CI
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 60

    # Disable rate limiting to prevent test throttling
    RATELIMIT_ENABLED = False

    # Disable metrics collection to avoid side effects
    METRICS_ENABLED = False

    # Disable error reporting during tests
    SENTRY_DSN = None
    SENTRY_ENVIRONMENT = 'ci'

    # Enable all feature flags for comprehensive testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True

    # CI-specific logging - minimize noise but capture errors
    LOG_LEVEL = 'ERROR'

    # ICS settings for CI - disabled by default
    ICS_ENABLED = False

    # JWT settings optimized for testing
    JWT_ACCESS_TOKEN_EXPIRES = 300  # 5 minutes

    # Smaller file size limits for test uploads
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
