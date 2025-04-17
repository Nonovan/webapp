"""
Instance-specific configuration settings.

This file contains environment-specific settings that should not be
committed to version control. It overrides settings from the main
configuration files.
"""

# Database settings
SQLALCHEMY_DATABASE_URI = "postgresql://username:password@localhost/cloud_platform"

# Security keys (unique per instance)
SECRET_KEY = "your-secret-key-here"
JWT_SECRET_KEY = "your-jwt-secret-key-here"
CSRF_SECRET_KEY = "your-csrf-secret-key-here"

# External service credentials
AWS_ACCESS_KEY = "your-aws-access-key"
AWS_SECRET_KEY = "your-aws-secret-key"
AZURE_CONNECTION_STRING = "your-azure-connection-string"
GCP_CREDENTIALS_FILE = "gcp-credentials.json"

# Email settings
MAIL_SERVER = "smtp.example.com"
MAIL_PORT = 587
MAIL_USERNAME = "notifications@example.com"
MAIL_PASSWORD = "your-mail-password"
MAIL_USE_TLS = True

# Redis connection
REDIS_URL = "redis://localhost:6379/0"

# Sentry monitoring
SENTRY_DSN = "your-sentry-dsn"

# ICS security settings
ICS_RESTRICTED_IPS = ["192.168.1.1", "192.168.1.2"]