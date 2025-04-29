"""
Forensic Analysis Utilities for the Cloud Infrastructure Platform.

This package provides core utilities for forensic investigation and analysis,
including file handling, cryptography, logging, timestamp normalization,
evidence tracking, and report generation. These utilities ensure consistent
operation across the forensic toolkit while maintaining proper chain of custody
and evidence integrity.

The utilities follow forensic best practices and are designed to support
investigations that may be subject to legal scrutiny.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, Union

# Set up package-level logger
logger = logging.getLogger(__name__)

# Package version information
__version__ = '1.0.0'
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Initialize feature flags and availability trackers
CRYPTO_AVAILABLE = False
ADVANCED_LOGGING_AVAILABLE = False
FORENSIC_CONSTANTS_LOADED = False
EVIDENCE_TRACKING_AVAILABLE = False
REPORTING_AVAILABLE = False
FORMAT_CONVERSION_AVAILABLE = False
ADVANCED_TIMESTAMP_AVAILABLE = False
SANITIZATION_AVAILABLE = False
NETWORK_UTILS_AVAILABLE = False
VALIDATION_UTILS_AVAILABLE = False

# Package path constants
PACKAGE_PATH = Path(__file__).parent
TEMPLATES_DIR = PACKAGE_PATH / "templates"

# Try to import the core modules and set availability flags
try:
    # Import forensic constants first as other modules depend on them
    from .forensic_constants import (
        DEFAULT_HASH_ALGORITHM,
        DEFAULT_SECURE_FILE_PERMS,
        DEFAULT_READ_ONLY_FILE_PERMS,
        DEFAULT_SECURE_DIR_PERMS,
        TEMP_DIR_FORENSICS,
        EVIDENCE_METADATA_DIR,
        FORENSIC_LOG_DIR,
        DEFAULT_TIMESTAMP_FORMAT,
        DEFAULT_TIMEZONE,
        COMMON_TIMESTAMP_FORMATS,
        SUPPORTED_HASH_ALGORITHMS,
        SAFE_FILE_EXTENSIONS,
        ALLOWED_MIME_TYPES,
        MAX_FILE_SIZE_BYTES
    )
    FORENSIC_CONSTANTS_LOADED = True
except ImportError as e:
    logger.warning(f"Could not import forensic constants: {e}")

# Load modules and track their availability
try:
    from .logging_utils import (
        log_forensic_operation,
        get_forensic_logs,
        export_forensic_logs,
        verify_log_integrity,
        setup_forensic_logger
    )
    ADVANCED_LOGGING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import forensic logging utilities: {e}")
    # Define basic logging function for other modules to use
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None, level: int = logging.INFO):
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logging.log(level=level, msg=msg)

try:
    from .crypto import (
        calculate_hash,
        verify_file_hash,
        calculate_file_hash,
        compare_hashes,
        validate_signature,
        encrypt_file,
        decrypt_file,
        secure_delete_data,
        generate_hmac
    )
    CRYPTO_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import cryptographic utilities: {e}")

try:
    from .file_utils import (
        secure_copy,
        get_file_metadata,
        verify_integrity,
        create_secure_temp_file,
        secure_delete,
        read_only_open,
        write_only_open,
        set_file_read_only,
        compare_files,
        find_files_by_pattern,
        hash_directory_contents,
        extract_archive_securely,
        write_metadata_file
    )
except ImportError as e:
    logger.warning(f"Could not import forensic file utilities: {e}")

try:
    from .evidence_tracker import (
        register_evidence,
        track_access,
        get_evidence_details,
        update_evidence_details,
        get_chain_of_custody,
        verify_evidence_integrity,
        list_evidence_by_case,
        create_evidence_container,
        export_chain_of_custody
    )
    EVIDENCE_TRACKING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import evidence tracking utilities: {e}")

try:
    from .timestamp_utils import (
        normalize_timestamp,
        parse_timestamp,
        convert_timestamp_format,
        validate_timestamp_string,
        extract_timestamps_from_text,
        format_timestamp,
        calculate_timestamp_difference,
        normalize_timestamps,
        create_timeline,
        detect_timestamp_anomalies,
        timezone_from_offset,
        format_time_human_readable
    )
    ADVANCED_TIMESTAMP_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import timestamp utilities: {e}")

try:
    from .validation_utils import (
        validate_path,
        validate_file_permissions,
        validate_file_format,
        validate_file_size,
        validate_hash_format,
        validate_ip_address,
        validate_mac_address,
        validate_port_number,
        validate_timestamp,
        validate_json,
        validate_integer_range,
        validate_float_range,
        validate_string_length,
        validate_choice
    )
    VALIDATION_UTILS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import validation utilities: {e}")

try:
    from .format_converter import (
        convert_hex_to_binary,
        convert_binary_to_hex,
        convert_base64_to_binary,
        convert_binary_to_base64,
        convert_between_timestamp_types,
        convert_json_to_xml,
        convert_xml_to_json,
        convert_json_to_csv,
        convert_to_utf8,
        detect_encoding
    )
    FORMAT_CONVERSION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import format conversion utilities: {e}")

try:
    from .sanitize import (
        redact_sensitive_data,
        detect_pii,
        sanitize_filename,
        remove_metadata,
        prepare_external_report,
        detect_credentials,
        sanitize_ip_addresses,
        mask_sensitive_fields
    )
    SANITIZATION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import sanitization utilities: {e}")

try:
    from .network_utils import (
        parse_pcap_file,
        extract_ips_from_pcap,
        extract_domains_from_pcap,
        normalize_mac_address,
        normalize_ip_address,
        is_internal_ip,
        classify_network_traffic,
        extract_http_requests,
        reassemble_tcp_stream,
        extract_dns_queries
    )
    NETWORK_UTILS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import network utilities: {e}")

try:
    from .report_builder import (
        generate_forensic_report,
        generate_html_report,
        generate_pdf_report,
        generate_json_report,
        generate_text_report,
        prepare_report_metadata,
        create_timeline_chart,
        create_evidence_summary
    )
    REPORTING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Could not import report builder utilities: {e}")

# Ensure the forensic temporary directory exists
try:
    if FORENSIC_CONSTANTS_LOADED:
        os.makedirs(TEMP_DIR_FORENSICS, mode=DEFAULT_SECURE_DIR_PERMS, exist_ok=True)
        logger.debug(f"Ensured forensic temp directory exists at {TEMP_DIR_FORENSICS}")
except (OSError, PermissionError) as e:
    logger.warning(f"Could not create forensic temporary directory: {e}")

# Define the package's public API
__all__ = [
    # Core package info
    '__version__',
    '__author__',
    '__email__',
    '__status__',

    # Feature availability flags
    'CRYPTO_AVAILABLE',
    'ADVANCED_LOGGING_AVAILABLE',
    'FORENSIC_CONSTANTS_LOADED',
    'EVIDENCE_TRACKING_AVAILABLE',
    'REPORTING_AVAILABLE',
    'FORMAT_CONVERSION_AVAILABLE',
    'ADVANCED_TIMESTAMP_AVAILABLE',
    'SANITIZATION_AVAILABLE',
    'NETWORK_UTILS_AVAILABLE',
    'VALIDATION_UTILS_AVAILABLE',

    # Path constants
    'PACKAGE_PATH',
    'TEMPLATES_DIR',

    # Helper function to get package capabilities
    'get_capabilities',

    # Module imports that will be included only if available
]

# Conditionally add available utility functions to __all__
if FORENSIC_CONSTANTS_LOADED:
    __all__.extend([
        'DEFAULT_HASH_ALGORITHM',
        'DEFAULT_SECURE_FILE_PERMS',
        'DEFAULT_READ_ONLY_FILE_PERMS',
        'DEFAULT_SECURE_DIR_PERMS',
        'TEMP_DIR_FORENSICS',
        'EVIDENCE_METADATA_DIR',
        'FORENSIC_LOG_DIR',
        'DEFAULT_TIMESTAMP_FORMAT',
        'DEFAULT_TIMEZONE',
        'COMMON_TIMESTAMP_FORMATS',
        'SUPPORTED_HASH_ALGORITHMS',
        'SAFE_FILE_EXTENSIONS',
        'ALLOWED_MIME_TYPES',
        'MAX_FILE_SIZE_BYTES'
    ])

if ADVANCED_LOGGING_AVAILABLE:
    __all__.extend([
        'log_forensic_operation',
        'get_forensic_logs',
        'export_forensic_logs',
        'verify_log_integrity',
        'setup_forensic_logger'
    ])
else:
    __all__.append('log_forensic_operation')  # Add basic version

if CRYPTO_AVAILABLE:
    __all__.extend([
        'calculate_hash',
        'verify_file_hash',
        'calculate_file_hash',
        'compare_hashes',
        'validate_signature',
        'encrypt_file',
        'decrypt_file',
        'secure_delete_data',
        'generate_hmac'
    ])

# Always include file utilities since they're core to forensic operations
__all__.extend([
    'secure_copy',
    'get_file_metadata',
    'verify_integrity',
    'create_secure_temp_file',
    'secure_delete',
    'read_only_open',
    'write_only_open',
    'set_file_read_only',
    'compare_files',
    'find_files_by_pattern',
    'hash_directory_contents',
    'extract_archive_securely',
    'write_metadata_file'
])

if EVIDENCE_TRACKING_AVAILABLE:
    __all__.extend([
        'register_evidence',
        'track_access',
        'get_evidence_details',
        'update_evidence_details',
        'get_chain_of_custody',
        'verify_evidence_integrity',
        'list_evidence_by_case',
        'create_evidence_container',
        'export_chain_of_custody'
    ])

if ADVANCED_TIMESTAMP_AVAILABLE:
    __all__.extend([
        'normalize_timestamp',
        'parse_timestamp',
        'convert_timestamp_format',
        'validate_timestamp_string',
        'extract_timestamps_from_text',
        'format_timestamp',
        'calculate_timestamp_difference',
        'normalize_timestamps',
        'create_timeline',
        'detect_timestamp_anomalies',
        'timezone_from_offset',
        'format_time_human_readable'
    ])

if VALIDATION_UTILS_AVAILABLE:
    __all__.extend([
        'validate_path',
        'validate_file_permissions',
        'validate_file_format',
        'validate_file_size',
        'validate_hash_format',
        'validate_ip_address',
        'validate_mac_address',
        'validate_port_number',
        'validate_timestamp',
        'validate_json',
        'validate_integer_range',
        'validate_float_range',
        'validate_string_length',
        'validate_choice'
    ])

if FORMAT_CONVERSION_AVAILABLE:
    __all__.extend([
        'convert_hex_to_binary',
        'convert_binary_to_hex',
        'convert_base64_to_binary',
        'convert_binary_to_base64',
        'convert_between_timestamp_types',
        'convert_json_to_xml',
        'convert_xml_to_json',
        'convert_json_to_csv',
        'convert_to_utf8',
        'detect_encoding'
    ])

if SANITIZATION_AVAILABLE:
    __all__.extend([
        'redact_sensitive_data',
        'detect_pii',
        'sanitize_filename',
        'remove_metadata',
        'prepare_external_report',
        'detect_credentials',
        'sanitize_ip_addresses',
        'mask_sensitive_fields'
    ])

if NETWORK_UTILS_AVAILABLE:
    __all__.extend([
        'parse_pcap_file',
        'extract_ips_from_pcap',
        'extract_domains_from_pcap',
        'normalize_mac_address',
        'normalize_ip_address',
        'is_internal_ip',
        'classify_network_traffic',
        'extract_http_requests',
        'reassemble_tcp_stream',
        'extract_dns_queries'
    ])

if REPORTING_AVAILABLE:
    __all__.extend([
        'generate_forensic_report',
        'generate_html_report',
        'generate_pdf_report',
        'generate_json_report',
        'generate_text_report',
        'prepare_report_metadata',
        'create_timeline_chart',
        'create_evidence_summary'
    ])

def get_capabilities() -> Dict[str, Dict[str, Any]]:
    """
    Return information about available capabilities in the forensic utilities package.

    This function helps other components determine which forensic utilities
    are available for use, which can aid in graceful degradation of functionality
    when optional dependencies are not available.

    Returns:
        Dictionary with capability information for each component
    """
    return {
        "crypto": {
            "available": CRYPTO_AVAILABLE,
            "functions": [
                "calculate_hash", "verify_file_hash", "calculate_file_hash",
                "compare_hashes", "validate_signature", "encrypt_file",
                "decrypt_file", "secure_delete_data", "generate_hmac"
            ] if CRYPTO_AVAILABLE else []
        },
        "logging": {
            "available": ADVANCED_LOGGING_AVAILABLE,
            "functions": [
                "log_forensic_operation", "get_forensic_logs",
                "export_forensic_logs", "verify_log_integrity",
                "setup_forensic_logger"
            ] if ADVANCED_LOGGING_AVAILABLE else ["log_forensic_operation"]
        },
        "file_utils": {
            "available": True,  # Always available as it's core functionality
            "functions": [
                "secure_copy", "get_file_metadata", "verify_integrity",
                "create_secure_temp_file", "secure_delete", "read_only_open",
                "write_only_open", "set_file_read_only", "compare_files",
                "find_files_by_pattern", "hash_directory_contents",
                "extract_archive_securely", "write_metadata_file"
            ]
        },
        "evidence_tracking": {
            "available": EVIDENCE_TRACKING_AVAILABLE,
            "functions": [
                "register_evidence", "track_access", "get_evidence_details",
                "update_evidence_details", "get_chain_of_custody",
                "verify_evidence_integrity", "list_evidence_by_case",
                "create_evidence_container", "export_chain_of_custody"
            ] if EVIDENCE_TRACKING_AVAILABLE else []
        },
        "timestamp_utils": {
            "available": ADVANCED_TIMESTAMP_AVAILABLE,
            "functions": [
                "normalize_timestamp", "parse_timestamp", "convert_timestamp_format",
                "validate_timestamp_string", "extract_timestamps_from_text",
                "format_timestamp", "calculate_timestamp_difference",
                "normalize_timestamps", "create_timeline", "detect_timestamp_anomalies",
                "timezone_from_offset", "format_time_human_readable"
            ] if ADVANCED_TIMESTAMP_AVAILABLE else []
        },
        "validation_utils": {
            "available": VALIDATION_UTILS_AVAILABLE,
            "functions": [
                "validate_path", "validate_file_permissions", "validate_file_format",
                "validate_file_size", "validate_hash_format", "validate_ip_address",
                "validate_mac_address", "validate_port_number", "validate_timestamp",
                "validate_json", "validate_integer_range", "validate_float_range",
                "validate_string_length", "validate_choice"
            ] if VALIDATION_UTILS_AVAILABLE else []
        },
        "format_converter": {
            "available": FORMAT_CONVERSION_AVAILABLE,
            "functions": [
                "convert_hex_to_binary", "convert_binary_to_hex",
                "convert_base64_to_binary", "convert_binary_to_base64",
                "convert_between_timestamp_types", "convert_json_to_xml",
                "convert_xml_to_json", "convert_json_to_csv",
                "convert_to_utf8", "detect_encoding"
            ] if FORMAT_CONVERSION_AVAILABLE else []
        },
        "sanitize": {
            "available": SANITIZATION_AVAILABLE,
            "functions": [
                "redact_sensitive_data", "detect_pii", "sanitize_filename",
                "remove_metadata", "prepare_external_report", "detect_credentials",
                "sanitize_ip_addresses", "mask_sensitive_fields"
            ] if SANITIZATION_AVAILABLE else []
        },
        "network_utils": {
            "available": NETWORK_UTILS_AVAILABLE,
            "functions": [
                "parse_pcap_file", "extract_ips_from_pcap", "extract_domains_from_pcap",
                "normalize_mac_address", "normalize_ip_address", "is_internal_ip",
                "classify_network_traffic", "extract_http_requests",
                "reassemble_tcp_stream", "extract_dns_queries"
            ] if NETWORK_UTILS_AVAILABLE else []
        },
        "report_builder": {
            "available": REPORTING_AVAILABLE,
            "functions": [
                "generate_forensic_report", "generate_html_report",
                "generate_pdf_report", "generate_json_report",
                "generate_text_report", "prepare_report_metadata",
                "create_timeline_chart", "create_evidence_summary"
            ] if REPORTING_AVAILABLE else []
        },
        "constants": {
            "available": FORENSIC_CONSTANTS_LOADED,
            "functions": [
                "DEFAULT_HASH_ALGORITHM", "DEFAULT_SECURE_FILE_PERMS",
                "DEFAULT_READ_ONLY_FILE_PERMS", "DEFAULT_SECURE_DIR_PERMS",
                "TEMP_DIR_FORENSICS", "EVIDENCE_METADATA_DIR", "FORENSIC_LOG_DIR",
                "DEFAULT_TIMESTAMP_FORMAT", "DEFAULT_TIMEZONE",
                "COMMON_TIMESTAMP_FORMATS", "SUPPORTED_HASH_ALGORITHMS",
                "SAFE_FILE_EXTENSIONS", "ALLOWED_MIME_TYPES", "MAX_FILE_SIZE_BYTES"
            ] if FORENSIC_CONSTANTS_LOADED else []
        }
    }

# Log initialization status
if ADVANCED_LOGGING_AVAILABLE:
    log_forensic_operation(
        "initialize_forensic_utils",
        True,
        {
            "version": __version__,
            "crypto": CRYPTO_AVAILABLE,
            "advanced_logging": ADVANCED_LOGGING_AVAILABLE,
            "constants": FORENSIC_CONSTANTS_LOADED,
            "evidence_tracking": EVIDENCE_TRACKING_AVAILABLE,
            "reporting": REPORTING_AVAILABLE,
            "format_conversion": FORMAT_CONVERSION_AVAILABLE,
            "timestamp": ADVANCED_TIMESTAMP_AVAILABLE,
            "sanitization": SANITIZATION_AVAILABLE,
            "network": NETWORK_UTILS_AVAILABLE,
            "validation": VALIDATION_UTILS_AVAILABLE
        },
        level=logging.INFO
    )
else:
    # Use standard logging
    components_available = []
    components_unavailable = []

    for component, avail in [
        ("crypto", CRYPTO_AVAILABLE),
        ("advanced_logging", ADVANCED_LOGGING_AVAILABLE),
        ("constants", FORENSIC_CONSTANTS_LOADED),
        ("evidence_tracking", EVIDENCE_TRACKING_AVAILABLE),
        ("reporting", REPORTING_AVAILABLE),
        ("format_conversion", FORMAT_CONVERSION_AVAILABLE),
        ("timestamp", ADVANCED_TIMESTAMP_AVAILABLE),
        ("sanitization", SANITIZATION_AVAILABLE),
        ("network", NETWORK_UTILS_AVAILABLE),
        ("validation", VALIDATION_UTILS_AVAILABLE)
    ]:
        if avail:
            components_available.append(component)
        else:
            components_unavailable.append(component)

    logger.info(f"Forensic utilities initialized (version {__version__})")
    if components_available:
        logger.info(f"Available components: {', '.join(components_available)}")
    if components_unavailable:
        logger.warning(f"Unavailable components: {', '.join(components_unavailable)}")
