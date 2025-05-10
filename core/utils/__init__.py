"""
Core utility functions for the Cloud Infrastructure Platform.

This package provides common utility modules that can be reused across
different components of the application. It contains string manipulation,
file processing, format conversion, and other general-purpose utilities.

Key modules:
- string: Text manipulation, formatting, and conversion utilities
- date_time: Date and time handling with timezone support
- collection: Collection data structure operations
- file: File handling and path management
- validation: Input validation utilities
- logging_utils: Logging configuration and utility functions
- system: System resource and process information utilities

The utilities are designed to be imported individually or accessed via their
parent modules. Functions are organized by category for ease of discovery and use.
"""

# Import string manipulation utilities
from .string import (
    # Formatting and conversion
    slugify,
    truncate_text,
    strip_html_tags,
    sanitize_text,
    sanitize_html,
    snake_to_camel,
    camel_to_snake,
    snake_to_pascal,
    format_bytes,

    # String generation and manipulation
    generate_random_string,
    generate_excerpt,
    generate_secure_filename,
    join_with_oxford_comma,
    joinlines,

    # Validation and checking
    is_valid_email,
    is_valid_url,
    is_valid_slug,
    has_common_substring,
    contains_html,

    # Security
    mask_sensitive_data,
    escape_html,
    escape_quotes,

    # Text operations
    normalize_whitespace,
    pluralize,
    extract_domain,
    replace_urls_with_links,
    get_string_length_in_bytes,
    truncate_middle
)

# Import date and time utilities
from .date_time import (
    # Core datetime functions
    utcnow,
    now_with_timezone,
    format_datetime,
    parse_iso_datetime,
    format_timestamp,

    # Timezone operations
    get_timezone,
    convert_timezone,

    # Formatting and display
    format_relative_time,
    format_duration,

    # Time calculations and comparison
    calculate_time_difference,
    is_same_day,
    is_future_date,
    is_past_date,

    # Date ranges and manipulation
    date_range,
    add_time_interval,
    beginning_of_day,
    end_of_day,

    # Timestamp conversions
    to_timestamp,
    from_timestamp
)

# Import collection utilities
from .collection import (
    # Dictionary operations
    deep_get,
    deep_set,
    merge_dicts,
    flatten_dict,
    unflatten_dict,

    # List and array operations
    chunk_list,
    find_duplicates,
    group_by,
    unique_by,

    # Filtering operations
    filter_none,
    filter_empty,
    filter_dict_by_keys,

    # Transformation operations
    transform_keys,
    transform_values,

    # Advanced operations
    dict_transform,
    deep_filter,
    deep_update,
    partition,
    index_by,
    find_first,
    detect_cycles,
    safe_json_serialize
)

# Import file utilities
from .file import (
    # File operations
    read_file,
    write_file,
    append_to_file,
    ensure_directory_exists,

    # File security and integrity
    get_critical_file_hashes,
    is_path_safe,
    sanitize_filename,
    get_file_metadata,

    # File formats
    read_json_file,
    save_json_file,
    read_yaml_file,
    save_yaml_file
)

# Import validation utilities
from .validation import (
    # Schema validation
    validate_with_schema,
    validate_dict,
    validate_password_strength,

    # Input validation
    is_valid_ip_address,
    is_valid_hostname,
    is_valid_port,
    is_valid_uuid,

    # Resource validation functions - needed by API schemas
    validate_resource_id,
    validate_service_name,
    validate_region,

    # Range and constraint checking
    is_in_range,
    is_valid_length,
    is_valid_pattern,
    is_valid_choice,

    # Dictionary validation
    is_valid_dict_keys,

    # Type checking
    is_iterable,
    is_mapping,
    is_sequence,
    is_numeric,
    is_valid_numeric,
    normalize_boolean,

    # HTML sanitization
    sanitize_html,

    # Pattern constants
    EMAIL_REGEX,
    URL_REGEX,
    UUID_REGEX,
    HOSTNAME_REGEX,
    PORT_REGEX,
    AWS_RESOURCE_ID_PATTERN,
    AZURE_RESOURCE_ID_PATTERN,
    GCP_RESOURCE_ID_PATTERN,
    SERVICE_NAME_PATTERN,
    AWS_REGION_PATTERN,
    AZURE_REGION_PATTERN,
    GCP_REGION_PATTERN,
    ONPREM_REGION_PATTERN
)

# Import system utilities
from .system import (
    # System resources
    get_system_resources,
    get_process_info,
    get_request_context,
    get_redis_client,

    # Performance measurement
    measure_execution_time
)

# Import logging utilities
from .logging_utils import (
    # Logger setup
    setup_app_logging,
    setup_logging,
    setup_cli_logging,
    get_logger,
    get_security_logger,
    get_audit_logger,

    # Logging actions
    log_security_event,
    log_critical,
    log_error,
    log_warning,
    log_info,
    log_debug,
    log_file_integrity_event,

    # Logging utilities
    log_to_file,
    sanitize_log_message,
    obfuscate_sensitive_data,
    get_file_integrity_events,
    initialize_module_logging,

    # Formatter classes
    SecurityAwareJsonFormatter,
    FileIntegrityAwareHandler
)

# Import file integrity functions from security module
# These were migrated from utils.py to core.security.cs_file_integrity
try:
    from core.security.cs_file_integrity import (
        calculate_file_hash,
        check_critical_file_integrity,
        create_file_hash_baseline,
        detect_file_changes,
        update_file_integrity_baseline,
        verify_file_signature,
        get_last_integrity_status,
        log_file_integrity_event,
        _detect_file_changes,
        _check_for_permission_changes,
        _check_additional_critical_files,
        _consider_baseline_update,
        verify_baseline_update
    )
except ImportError:
    # Provide stubs if security module is not available
    import logging
    logger = logging.getLogger(__name__)
    logger.warning("File integrity functions from core.security.cs_file_integrity not available")

    def calculate_file_hash(*args, **kwargs):
        """Stub for calculate_file_hash (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def check_critical_file_integrity(*args, **kwargs):
        """Stub for check_critical_file_integrity (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def create_file_hash_baseline(*args, **kwargs):
        """Stub for create_file_hash_baseline (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def detect_file_changes(*args, **kwargs):
        """Stub for detect_file_changes (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def update_file_integrity_baseline(*args, **kwargs):
        """Stub for update_file_integrity_baseline (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def verify_file_signature(*args, **kwargs):
        """Stub for verify_file_signature (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def get_last_integrity_status(*args, **kwargs):
        """Stub for get_last_integrity_status (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def log_file_integrity_event(*args, **kwargs):
        """Stub for log_file_integrity_event (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def _detect_file_changes(*args, **kwargs):
        """Stub for _detect_file_changes (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def _check_for_permission_changes(*args, **kwargs):
        """Stub for _check_for_permission_changes (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def _check_additional_critical_files(*args, **kwargs):
        """Stub for _check_additional_critical_files (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def _consider_baseline_update(*args, **kwargs):
        """Stub for _consider_baseline_update (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

    def verify_baseline_update(*args, **kwargs):
        """Stub for verify_baseline_update (requires core.security.cs_file_integrity)"""
        raise NotImplementedError("File integrity functions require core.security module")

# Import path safety utilities from security module
try:
    from core.security.cs_utils import (
        sanitize_path,
        is_within_directory,
        is_safe_file_operation,
        obfuscate_sensitive_data
    )
except ImportError:
    # Provide stubs if security module is not available
    def sanitize_path(*args, **kwargs):
        """Stub for sanitize_path (requires core.security.cs_utils)"""
        raise NotImplementedError("Path safety functions require core.security module")

    def is_within_directory(*args, **kwargs):
        """Stub for is_within_directory (requires core.security.cs_utils)"""
        raise NotImplementedError("Path safety functions require core.security module")

    def is_safe_file_operation(*args, **kwargs):
        """Stub for is_safe_file_operation (requires core.security.cs_utils)"""
        raise NotImplementedError("Path safety functions require core.security module")

    def obfuscate_sensitive_data(*args, **kwargs):
        """Stub for obfuscate_sensitive_data (requires core.security.cs_utils)"""
        raise NotImplementedError("Security utilities require core.security module")

# Define exports for direct import from core.utils
__all__ = [
    # String utilities
    'slugify',
    'truncate_text',
    'strip_html_tags',
    'sanitize_text',
    'sanitize_html',
    'snake_to_camel',
    'camel_to_snake',
    'snake_to_pascal',
    'format_bytes',
    'generate_random_string',
    'generate_excerpt',
    'generate_secure_filename',
    'join_with_oxford_comma',
    'joinlines',
    'is_valid_email',
    'is_valid_url',
    'is_valid_slug',
    'has_common_substring',
    'contains_html',
    'mask_sensitive_data',
    'escape_html',
    'escape_quotes',
    'normalize_whitespace',
    'pluralize',
    'extract_domain',
    'replace_urls_with_links',
    'get_string_length_in_bytes',
    'truncate_middle',

    # Date and time utilities
    'utcnow',
    'now_with_timezone',
    'format_datetime',
    'parse_iso_datetime',
    'get_timezone',
    'convert_timezone',
    'format_relative_time',
    'format_duration',
    'calculate_time_difference',
    'is_same_day',
    'is_future_date',
    'is_past_date',
    'date_range',
    'add_time_interval',
    'beginning_of_day',
    'end_of_day',
    'to_timestamp',
    'from_timestamp',
    'format_timestamp',

    # Collection utilities - dictionary operations
    'deep_get',
    'deep_set',
    'merge_dicts',
    'flatten_dict',
    'unflatten_dict',
    'deep_filter',
    'deep_update',
    'dict_transform',
    'safe_json_serialize',

    # Collection utilities - list operations
    'chunk_list',
    'find_duplicates',
    'group_by',
    'unique_by',
    'partition',
    'index_by',
    'find_first',
    'detect_cycles',

    # Collection utilities - filtering and transformation
    'filter_none',
    'filter_empty',
    'filter_dict_by_keys',
    'transform_keys',
    'transform_values',

    # File utilities - operations
    'read_file',
    'write_file',
    'append_to_file',
    'ensure_directory_exists',
    'get_critical_file_hashes',
    'is_path_safe',
    'sanitize_filename',
    'get_file_metadata',

    # File utilities - formats
    'read_json_file',
    'save_json_file',
    'read_yaml_file',
    'save_yaml_file',

    # Validation utilities - schema
    'validate_with_schema',
    'validate_dict',
    'validate_password_strength',

    # Validation utilities - input
    'is_valid_ip_address',
    'is_valid_hostname',
    'is_valid_port',
    'is_valid_uuid',
    'validate_resource_id',
    'validate_service_name',
    'validate_region',

    # Validation utilities - constraints
    'is_in_range',
    'is_valid_length',
    'is_valid_pattern',
    'is_valid_choice',
    'is_valid_dict_keys',

    # Validation utilities - type checking
    'is_iterable',
    'is_mapping',
    'is_sequence',
    'is_numeric',
    'is_valid_numeric',
    'normalize_boolean',

    # System utilities
    'get_system_resources',
    'get_process_info',
    'get_request_context',
    'get_redis_client',
    'measure_execution_time',

    # Logging utilities
    'setup_app_logging',
    'setup_logging',
    'setup_cli_logging',
    'get_logger',
    'get_security_logger',
    'get_audit_logger',
    'log_security_event',
    'log_critical',
    'log_error',
    'log_warning',
    'log_info',
    'log_debug',
    'log_file_integrity_event',
    'log_to_file',
    'sanitize_log_message',
    'obfuscate_sensitive_data',
    'get_file_integrity_events',
    'initialize_module_logging',
    'SecurityAwareJsonFormatter',
    'FileIntegrityAwareHandler',

    # File integrity functions (from core.security.cs_file_integrity)
    'calculate_file_hash',
    'check_critical_file_integrity',
    'create_file_hash_baseline',
    'detect_file_changes',
    'update_file_integrity_baseline',
    'verify_file_signature',
    'get_last_integrity_status',
    'log_file_integrity_event',
    '_detect_file_changes',
    '_check_for_permission_changes',
    '_check_additional_critical_files',
    '_consider_baseline_update',
    'verify_baseline_update',

    # Path safety utilities (from core.security.cs_utils)
    'sanitize_path',
    'is_within_directory',
    'is_safe_file_operation',

    # Validation regex patterns
    'EMAIL_REGEX',
    'URL_REGEX',
    'UUID_REGEX',
    'HOSTNAME_REGEX',
    'PORT_REGEX',
    'AWS_RESOURCE_ID_PATTERN',
    'AZURE_RESOURCE_ID_PATTERN',
    'GCP_RESOURCE_ID_PATTERN',
    'SERVICE_NAME_PATTERN',
    'AWS_REGION_PATTERN',
    'AZURE_REGION_PATTERN',
    'GCP_REGION_PATTERN',
    'ONPREM_REGION_PATTERN',
]
