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

import os
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

# Configure module logger
logger = logging.getLogger(__name__)

# Version information
__version__ = '0.1.1'

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
from .middleware import (
    init_middleware,
    generate_request_id  # Moved from utils.py to middleware.py
)
from .utils.logging_utils import (
    setup_app_logging,
    get_logger,
    get_security_logger,
    log_security_event,
    get_audit_logger,
    log_file_integrity_event,
    initialize_module_logging
)

# Import string manipulation utilities
from .utils.string import (
    slugify,
    truncate_text as truncate,
    strip_html_tags as strip_tags,
    sanitize_html
)

# Import date/time utilities
from .utils.date_time import (
    utcnow,
    format_datetime,
    format_timestamp
)

# Import file utilities
from .utils.file import (
    ensure_directory_exists,
    sanitize_filename,
    get_file_metadata
)

# Import collection utilities
from .utils.collection import (
    filter_none,
    deep_get,
    deep_set,
    merge_dicts,
    safe_json_serialize
)

# Import system utilities from new location
from .utils.system import (
    get_system_resources,
    get_process_info,
    get_request_context,
    measure_execution_time
)

# Import validation utilities from new module
from .utils.validation import (
    is_valid_email,
    is_valid_url,
    validate_with_schema,
    is_valid_ip_address,
    is_valid_uuid
)

# Import security utilities from their new specialized locations
from .security.cs_crypto import (
    compute_hash as compute_file_hash,
    generate_sri_hash,
    secure_compare,
    encrypt_sensitive_data,
    decrypt_sensitive_data
)

from .security.cs_utils import (
    sanitize_path,
    is_within_directory,
    is_safe_file_operation,
    obfuscate_sensitive_data,
    initialize_security_components,
    generate_csp_nonce
)

from .security.cs_authentication import (
    generate_secure_token,
    validate_password_strength,
    validate_url
)

from .security.cs_file_integrity import (
    check_critical_file_integrity,
    detect_file_changes,
    update_file_integrity_baseline,
    create_file_hash_baseline,
    get_last_integrity_status,
    log_file_integrity_event,
    _consider_baseline_update,
    verify_baseline_update
)

from .security import (
    require_permission,
    detect_suspicious_activity,
    validate_request_security,
    init_security
)

# Import seeder functions
from .seeder import (
    seed_database,
    seed_development_data,
    seed_test_data
)

# Initialize security components
init_security()

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
    'configure_app',
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
    'initialize_module_logging',

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
    'encrypt_sensitive_data',
    'decrypt_sensitive_data',

    # String utilities
    'slugify',
    'truncate',
    'sanitize_html',
    'strip_tags',

    # Collection utilities
    'filter_none',
    'safe_json_serialize',

    # System utilities
    'get_system_resources',
    'get_process_info',
    'get_request_context',
    'measure_execution_time',

    # File utilities
    'get_file_metadata',
    'sanitize_path',
    'is_within_directory',
    'is_safe_file_operation',

    # Validation utilities
    'is_valid_email',
    'is_valid_url',
    'validate_with_schema',
    'is_valid_ip_address',
    'is_valid_uuid',
    'validate_password_strength',
    'validate_url',

    # Security and cryptographic functions
    'generate_sri_hash',
    'check_critical_file_integrity',
    'detect_file_changes',
    'update_file_integrity_baseline',
    'create_file_hash_baseline',
    'get_last_integrity_status',
    'require_permission',
    'detect_suspicious_activity',
    'validate_request_security',
    'initialize_security_components',
    'generate_csp_nonce',
    '_consider_baseline_update',
    'init_security',
    'verify_baseline_update',

    # Database seeding functions
    'seed_database',
    'seed_development_data',
    'seed_test_data'
]
