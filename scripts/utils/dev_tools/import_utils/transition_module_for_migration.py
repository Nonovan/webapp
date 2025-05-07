"""
Transitional module for backward compatibility during migration.

This module provides backward compatibility for code that still imports from
old module locations. It re-exports functions, classes and constants from
their new specialized module locations, allowing for gradual migration of
import statements across the codebase.

DEPRECATED: This module is provided as a transitional solution only.
Code should be updated to import directly from the specialized modules.
"""

import warnings
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

# Setup logger
logger = logging.getLogger(__name__)

# Show deprecation warning when this module is imported
warnings.warn(
    "The transition_module_for_migration is deprecated and will be removed in future versions. "
    "Update your imports to reference the new module locations directly.",
    DeprecationWarning,
    stacklevel=2
)

# Track re-exported symbols for documentation
RE_EXPORTED_SYMBOLS = []

# Re-export functions from their new locations in core.utils modules
try:
    # File integrity and security functions from core.security modules
    from core.security.cs_file_integrity import (
        detect_file_changes,
        check_critical_file_integrity,
        check_critical_files,
        create_file_hash_baseline,
        update_file_integrity_baseline,
        verify_file_signature,
        log_file_integrity_event
    )
    RE_EXPORTED_SYMBOLS.extend([
        'detect_file_changes',
        'check_critical_file_integrity',
        'check_critical_files',
        'create_file_hash_baseline',
        'update_file_integrity_baseline',
        'verify_file_signature',
        'log_file_integrity_event'
    ])
except ImportError as e:
    logger.debug(f"Could not import file integrity functions: {e}")

try:
    # Security utility functions from core.security
    from core.security.cs_utils import (
        sanitize_path,
        is_within_directory,
        is_safe_file_operation,
        obfuscate_sensitive_data
    )
    RE_EXPORTED_SYMBOLS.extend([
        'sanitize_path',
        'is_within_directory',
        'is_safe_file_operation',
        'obfuscate_sensitive_data'
    ])
except ImportError as e:
    logger.debug(f"Could not import security utility functions: {e}")

try:
    # System utility functions from core.utils.system
    from core.utils.system import (
        get_redis_client,
        get_system_resources,
        get_process_info,
        get_request_context,
        measure_execution_time
    )
    RE_EXPORTED_SYMBOLS.extend([
        'get_redis_client',
        'get_system_resources',
        'get_process_info',
        'get_request_context',
        'measure_execution_time'
    ])
except ImportError as e:
    logger.debug(f"Could not import system utility functions: {e}")

try:
    # Crypto functions from core.security
    from core.security.cs_crypto import (
        calculate_file_hash,
        compute_file_hash,
        generate_sri_hash,
        secure_compare
    )
    RE_EXPORTED_SYMBOLS.extend([
        'calculate_file_hash',
        'compute_file_hash',
        'generate_sri_hash',
        'secure_compare'
    ])
except ImportError as e:
    logger.debug(f"Could not import crypto functions: {e}")

try:
    # Authentication functions from core.security
    from core.security.cs_authentication import (
        generate_secure_token
    )
    RE_EXPORTED_SYMBOLS.extend([
        'generate_secure_token'
    ])
except ImportError as e:
    logger.debug(f"Could not import authentication functions: {e}")

try:
    # File utility functions from core.utils.file
    from core.utils.file import (
        get_critical_file_hashes,
        get_file_metadata
    )
    RE_EXPORTED_SYMBOLS.extend([
        'get_critical_file_hashes',
        'get_file_metadata'
    ])
except ImportError as e:
    logger.debug(f"Could not import file utility functions: {e}")

try:
    # Logging functions from core.utils.logging_utils
    from core.utils.logging_utils import (
        setup_logging,
        log_critical,
        log_error,
        log_warning,
        log_info,
        log_debug
    )
    RE_EXPORTED_SYMBOLS.extend([
        'setup_logging',
        'log_critical',
        'log_error',
        'log_warning',
        'log_info',
        'log_debug'
    ])
except ImportError as e:
    logger.debug(f"Could not import logging functions: {e}")

try:
    # Date/time functions from core.utils.date_time
    from core.utils.date_time import (
        utcnow,
        format_timestamp
    )
    RE_EXPORTED_SYMBOLS.extend([
        'utcnow',
        'format_timestamp'
    ])
except ImportError as e:
    logger.debug(f"Could not import date/time functions: {e}")

try:
    # Collection functions from core.utils.collection
    from core.utils.collection import (
        safe_json_serialize
    )
    RE_EXPORTED_SYMBOLS.extend([
        'safe_json_serialize'
    ])
except ImportError as e:
    logger.debug(f"Could not import collection functions: {e}")

try:
    # Core module functions
    from core import (
        generate_request_id
    )
    RE_EXPORTED_SYMBOLS.extend([
        'generate_request_id'
    ])
except ImportError as e:
    logger.debug(f"Could not import core module functions: {e}")

# Provide stub functions for any symbols that couldn't be imported
# This ensures old code doesn't fail with attribute errors

def _create_stub_function(name):
    """
    Create a stub function that raises a NotImplementedError
    when called, with information about the new location.
    """
    def stub_function(*args, **kwargs):
        locations = {
            # File integrity functions
            'detect_file_changes': 'core.security.cs_file_integrity',
            'check_critical_file_integrity': 'core.security.cs_file_integrity',
            'check_critical_files': 'core.security.cs_file_integrity',
            'create_file_hash_baseline': 'core.security.cs_file_integrity',
            'update_file_integrity_baseline': 'core.security.cs_file_integrity',
            'verify_file_signature': 'core.security.cs_file_integrity',
            'log_file_integrity_event': 'core.security.cs_file_integrity',

            # Security utilities
            'sanitize_path': 'core.security.cs_utils',
            'is_within_directory': 'core.security.cs_utils',
            'is_safe_file_operation': 'core.security.cs_utils',
            'obfuscate_sensitive_data': 'core.security.cs_utils',

            # System utilities
            'get_redis_client': 'core.utils.system',
            'get_system_resources': 'core.utils.system',
            'get_process_info': 'core.utils.system',
            'get_request_context': 'core.utils.system',
            'measure_execution_time': 'core.utils.system',

            # Crypto functions
            'calculate_file_hash': 'core.security.cs_crypto',
            'compute_file_hash': 'core.security.cs_crypto',
            'generate_sri_hash': 'core.security.cs_crypto',
            'secure_compare': 'core.security.cs_crypto',

            # Authentication functions
            'generate_secure_token': 'core.security.cs_authentication',

            # File utilities
            'get_critical_file_hashes': 'core.utils.file',
            'get_file_metadata': 'core.utils.file',

            # Logging functions
            'setup_logging': 'core.utils.logging_utils',
            'log_critical': 'core.utils.logging_utils',
            'log_error': 'core.utils.logging_utils',
            'log_warning': 'core.utils.logging_utils',
            'log_info': 'core.utils.logging_utils',
            'log_debug': 'core.utils.logging_utils',

            # Date/time functions
            'utcnow': 'core.utils.date_time',
            'format_timestamp': 'core.utils.date_time',

            # Collection functions
            'safe_json_serialize': 'core.utils.collection',

            # Core module functions
            'generate_request_id': 'core'
        }

        module = locations.get(name, "appropriate specialized module")
        error_msg = f"Function {name} is not available. Import from {module} instead."
        warnings.warn(error_msg, DeprecationWarning, stacklevel=2)
        raise NotImplementedError(error_msg)

    return stub_function

# Create stubs for functions that may not have been imported
REQUIRED_FUNCTIONS = [
    # File integrity
    'detect_file_changes', 'check_critical_file_integrity', 'check_critical_files',
    'create_file_hash_baseline', 'update_file_integrity_baseline',
    'verify_file_signature', 'log_file_integrity_event',

    # Security utilities
    'sanitize_path', 'is_within_directory', 'is_safe_file_operation',
    'obfuscate_sensitive_data',

    # System utilities
    'get_redis_client', 'get_system_resources', 'get_process_info',
    'get_request_context', 'measure_execution_time',

    # Crypto functions
    'calculate_file_hash', 'compute_file_hash', 'generate_sri_hash', 'secure_compare',

    # Authentication functions
    'generate_secure_token',

    # File utilities
    'get_critical_file_hashes', 'get_file_metadata',

    # Logging functions
    'setup_logging', 'log_critical', 'log_error', 'log_warning', 'log_info', 'log_debug',

    # Date/time functions
    'utcnow', 'format_timestamp',

    # Collection functions
    'safe_json_serialize',

    # Core module functions
    'generate_request_id'
]

# Create stubs for any functions that weren't successfully imported
for func_name in REQUIRED_FUNCTIONS:
    if func_name not in globals():
        globals()[func_name] = _create_stub_function(func_name)
        # Add to re-exported symbols list for documentation
        RE_EXPORTED_SYMBOLS.append(func_name)

# Provide version information
__version__ = '1.0.0'
__deprecated__ = True

# Define what gets imported with "from transition_module_for_migration import *"
__all__ = RE_EXPORTED_SYMBOLS
