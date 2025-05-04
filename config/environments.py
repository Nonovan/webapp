"""
Environment-specific configurations for Cloud Infrastructure Platform.

This module defines configuration classes for different environments (development,
testing, staging, production, etc.) with appropriate settings for each context.
It also provides utility functions for environment detection and management.
"""

import os
from typing import Dict, Any, Optional, Type
from .base import Config

# Environment constants
ENVIRONMENT_DEVELOPMENT = 'development'
ENVIRONMENT_TESTING = 'testing'
ENVIRONMENT_STAGING = 'staging'
ENVIRONMENT_PRODUCTION = 'production'
ENVIRONMENT_CI = 'ci'
ENVIRONMENT_DR_RECOVERY = 'dr-recovery'

# Environment groups
ALLOWED_ENVIRONMENTS = {
    ENVIRONMENT_DEVELOPMENT,
    ENVIRONMENT_TESTING,
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_CI,
    ENVIRONMENT_DR_RECOVERY
}

# Environments with stricter security requirements
SECURE_ENVIRONMENTS = {
    ENVIRONMENT_STAGING,
    ENVIRONMENT_PRODUCTION,
    ENVIRONMENT_DR_RECOVERY
}


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    ENV = ENVIRONMENT_DEVELOPMENT
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    DEBUG_TB_ENABLED = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    LOG_LEVEL = 'DEBUG'
    CACHE_TYPE = 'SimpleCache'
    ICS_ENABLED = True
    ICS_RESTRICTED_IPS = ['127.0.0.1']
    SECURITY_CHECK_FILE_INTEGRITY = False
    # Enable auto-update baseline for development
    AUTO_UPDATE_BASELINE = True


class ProductionConfig(Config):
    """Production environment configuration."""
    ENV = ENVIRONMENT_PRODUCTION
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    SECURITY_CHECK_FILE_INTEGRITY = True
    SECURITY_LOG_LEVEL = 'WARNING'
    AUTO_UPDATE_BASELINE = False
    # Enforce secure cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    # Enable strict CSP
    SECURITY_HEADERS_ENABLED = True
    API_REQUIRE_HTTPS = True


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    ENV = ENVIRONMENT_TESTING
    DEBUG = False
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SERVER_NAME = 'localhost'
    METRICS_ENABLED = False
    SECURITY_CHECK_FILE_INTEGRITY = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    # Disable audit logging in tests
    AUDIT_LOG_ENABLED = False


class StagingConfig(Config):
    """Staging environment configuration."""
    ENV = ENVIRONMENT_STAGING
    DEBUG = False
    LOG_LEVEL = 'INFO'
    SECURITY_CHECK_FILE_INTEGRITY = True
    SENTRY_ENVIRONMENT = 'staging'
    SENTRY_TRACES_SAMPLE_RATE = 0.2
    # Enforce secure cookies but more verbose logging than production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    API_REQUIRE_HTTPS = True
    AUTO_UPDATE_BASELINE = False


class CIConfig(Config):
    """CI environment configuration."""
    ENV = ENVIRONMENT_CI
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    # Disable metrics and monitoring in CI
    METRICS_ENABLED = False
    # Enable all feature flags for comprehensive testing
    FEATURE_DARK_MODE = True
    FEATURE_ICS_CONTROL = True
    FEATURE_CLOUD_MANAGEMENT = True
    FEATURE_MFA = True
    # CI-specific logging - minimize noise but capture errors
    LOG_LEVEL = 'ERROR'
    # Disable security features that might interfere with tests
    SECURITY_CHECK_FILE_INTEGRITY = False


class DRRecoveryConfig(Config):
    """Disaster recovery environment configuration."""
    ENV = ENVIRONMENT_DR_RECOVERY
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    # Same security settings as production
    SECURITY_CHECK_FILE_INTEGRITY = True
    SECURITY_LOG_LEVEL = 'WARNING'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    API_REQUIRE_HTTPS = True
    AUTO_UPDATE_BASELINE = False


def detect_environment() -> str:
    """
    Detect current environment based on environment variables.

    Returns:
        str: The current environment name (development, production, etc.)
    """
    env = os.environ.get('ENVIRONMENT', os.environ.get('FLASK_ENV', ENVIRONMENT_DEVELOPMENT)).lower()
    if env not in ALLOWED_ENVIRONMENTS:
        return ENVIRONMENT_DEVELOPMENT
    return env


def get_environment_config(environment: Optional[str] = None) -> Type[Config]:
    """
    Get configuration class for a specific environment.

    Args:
        environment: The environment name (development, production, etc.)
                    If None, detect from environment variables

    Returns:
        Config: The environment-specific configuration class

    Raises:
        ValueError: If an invalid environment name is provided
    """
    if environment is None:
        environment = detect_environment()

    environment = environment.lower()

    config_classes = {
        ENVIRONMENT_DEVELOPMENT: DevelopmentConfig,
        ENVIRONMENT_PRODUCTION: ProductionConfig,
        ENVIRONMENT_TESTING: TestingConfig,
        ENVIRONMENT_STAGING: StagingConfig,
        ENVIRONMENT_CI: CIConfig,
        ENVIRONMENT_DR_RECOVERY: DRRecoveryConfig
    }

    if environment not in config_classes:
        raise ValueError(f"Unknown environment: {environment}. Allowed values are: {', '.join(ALLOWED_ENVIRONMENTS)}")

    return config_classes[environment]
