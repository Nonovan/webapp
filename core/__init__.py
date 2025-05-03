"""
Core package for the Cloud Infrastructure Platform.

This package contains fundamental components and utilities that provide the
foundation for the application, including security features, configuration
management, application factory, logging, metrics collection, and more.

The core package is designed to be imported by other modules and provides
a consistent, secure foundation for the entire system with these key features:
- Application factory pattern for creating Flask instances
- Configuration management with environment-specific settings
- Security features including file integrity monitoring
- Logging with proper formatting and security event tracking
- Health check mechanisms for system monitoring
- Utility functions for common operations
"""

from flask import Flask
import os
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

# Configure module logger
logger = logging.getLogger(__name__)

# Version information - should be updated with each significant change
__version__ = '1.0.0'

# Constants
DEFAULT_HASH_ALGORITHM = 'sha256'
SMALL_FILE_THRESHOLD = 10240  # 10KB

# Import core components for direct access
from .config import Config
from .factory import (
    create_app,
    configure_app,
    register_extensions,
    register_error_handlers
)
from .health import (
    healthcheck,
    register_health_endpoints,
    check_database_health,
    check_cache_health,
    check_redis_health
)
from .middleware import init_middleware
from .loggings import (
    setup_app_logging,
    get_logger,
    get_security_logger,
    log_security_event,
    get_audit_logger,
    log_file_integrity_event,
    initialize_module_logging
)

# Import utility functions - focusing on the most commonly used ones
from .utils import (
    # String utilities
    slugify,
    truncate,
    sanitize_html,
    strip_tags,

    # Security utilities
    generate_request_id,

    # Date/time utilities
    utcnow,
    format_datetime,
    format_timestamp,

    # File utilities
    compute_file_hash,
    sanitize_filename,
    ensure_directory_exists,

    # Collection utilities
    filter_none,
    deep_get,
    deep_set,
    merge_dicts
)

# Security imports (limited to most essential functions)
from .security import (
    check_critical_file_integrity,
    log_security_event,
    require_permission,
    detect_suspicious_activity,
    validate_request_security,
    generate_secure_token
)

# Initialize module logging when imported directly
initialize_module_logging()

# Track initialization for diagnostics
logger.debug(f"Core package initialized (version: {__version__})")

# Define explicitly what is available for import
__all__ = [
    # Version information
    '__version__',

    # Core components
    'Config',
    'create_app',
    'setup_app_logging',
    'register_extensions',
    'register_error_handlers',
    'init_middleware',

    # Health check utilities
    'healthcheck',
    'register_health_endpoints',
    'check_database_health',
    'check_cache_health',
    'check_redis_health',

    # Logging functions
    'get_logger',
    'get_security_logger',
    'get_audit_logger',
    'log_security_event',
    'log_file_integrity_event',

    # Common utility functions
    'generate_request_id',
    'generate_secure_token',
    'secure_compare',
    'format_datetime',
    'format_timestamp',
    'utcnow',
    'compute_file_hash',
    'sanitize_filename',
    'ensure_directory_exists',
    'deep_get',
    'deep_set',
    'merge_dicts',
    'obfuscate_sensitive_data',

    # Security functions
    'check_critical_file_integrity',
    'require_permission',
    'detect_suspicious_activity',
    'validate_request_security'
]
