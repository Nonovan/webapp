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
from typing import Dict, Any, List, Optional, Set, Tuple, Union, Callable
from datetime import datetime

# Set up package-level logger
logger = logging.getLogger(__name__)

# Package version information
__version__ = '0.1.1'
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
CORE_INTEGRITY_AVAILABLE = False

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

# Try to import core security module for baseline functionality
try:
    from core.security.cs_file_integrity import update_file_integrity_baseline as core_update_baseline
    CORE_INTEGRITY_AVAILABLE = True
    logger.debug("Core file integrity module available")
except ImportError as e:
    logger.warning(f"Core file integrity module not available: {e}")

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
        track_analysis,
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
        # Encoding/decoding conversions
        bytes_to_base64,
        base64_to_bytes,
        bytes_to_hex,
        hex_to_bytes,

        # Binary conversions
        convert_hex_to_binary,
        convert_binary_to_hex,
        convert_base64_to_binary,
        convert_binary_to_base64,

        # Timestamp conversions
        convert_between_timestamp_types,

        # Structured data format conversions
        convert_json_to_xml,
        convert_xml_to_json,
        convert_json_to_csv,
        dict_to_xml,
        xml_to_dict,
        dict_list_to_csv_string,
        csv_string_to_dict_list,

        # Text encoding
        convert_to_utf8,
        detect_encoding,

        # File format conversion
        convert_file_format,
        detect_file_format
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
        mask_sensitive_value
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

# Add a basic HTML report generation function that works without external dependencies
def generate_html_report_basic(
    report_data: Dict[str, Any],
    output_path: str,
    title: str = "Forensic Analysis Report",
    case_id: Optional[str] = None,
    analyst_name: Optional[str] = None
) -> bool:
    """
    Generate a simple HTML report from forensic data.

    This is a basic implementation that works without requiring external dependencies.
    For more advanced report generation with templates, use the functions from report_builder.

    Args:
        report_data: Dictionary containing the report content
        output_path: Path where to save the generated HTML report
        title: Title for the report
        case_id: Optional case identifier to include in the report
        analyst_name: Optional analyst name to include in the report

    Returns:
        True if the report was successfully generated, False otherwise
    """
    try:
        generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Start with basic HTML structure
        html_lines = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            f"<title>{title}</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }",
            "h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }",
            ".metadata { margin-bottom: 20px; padding: 10px; background-color: #f5f5f5; border-radius: 4px; }",
            ".section { margin-bottom: 20px; }",
            "table { width: 100%; border-collapse: collapse; margin: 15px 0; }",
            "th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }",
            "th { background-color: #f2f2f2; }",
            "tr:hover { background-color: #f5f5f5; }",
            ".footer { margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }",
            "</style>",
            "</head>",
            "<body>",
            f"<h1>{title}</h1>",
            "<div class='metadata'>",
            f"<p><strong>Case ID:</strong> {case_id or 'N/A'}</p>",
            f"<p><strong>Analyst:</strong> {analyst_name or 'N/A'}</p>",
            f"<p><strong>Generated:</strong> {generation_time}</p>",
            "</div>"
        ]

        # Add sections from report data
        for section_title, section_content in report_data.items():
            html_lines.append(f"<div class='section'>")
            html_lines.append(f"<h2>{section_title.replace('_', ' ').title()}</h2>")

            # Handle different content types appropriately
            if isinstance(section_content, list):
                if section_content and isinstance(section_content[0], dict):
                    # Create a table for list of dictionaries
                    if section_content:
                        keys = section_content[0].keys()
                        html_lines.append("<table>")
                        html_lines.append("<tr>")
                        for key in keys:
                            html_lines.append(f"<th>{key.replace('_', ' ').title()}</th>")
                        html_lines.append("</tr>")

                        for item in section_content:
                            html_lines.append("<tr>")
                            for key in keys:
                                value = item.get(key, "")
                                html_lines.append(f"<td>{value}</td>")
                            html_lines.append("</tr>")
                        html_lines.append("</table>")
                else:
                    # Create a simple list
                    html_lines.append("<ul>")
                    for item in section_content:
                        html_lines.append(f"<li>{item}</li>")
                    html_lines.append("</ul>")
            elif isinstance(section_content, dict):
                # Create definition list for dictionary
                html_lines.append("<dl>")
                for key, value in section_content.items():
                    html_lines.append(f"<dt><strong>{key.replace('_', ' ').title()}</strong></dt>")
                    if isinstance(value, dict):
                        html_lines.append("<dd>")
                        html_lines.append("<ul>")
                        for k, v in value.items():
                            html_lines.append(f"<li><strong>{k}:</strong> {v}</li>")
                        html_lines.append("</ul>")
                        html_lines.append("</dd>")
                    else:
                        html_lines.append(f"<dd>{value}</dd>")
                html_lines.append("</dl>")
            else:
                # Simple paragraph for string or other types
                html_lines.append(f"<p>{section_content}</p>")

            html_lines.append("</div>")

        # Add footer
        html_lines.append("<div class='footer'>")
        html_lines.append(f"<p>Generated by Forensic Analysis Utilities v{__version__}</p>")
        html_lines.append("</div>")
        html_lines.append("</body>")
        html_lines.append("</html>")

        # Write to file
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_lines))

        # Log the operation
        log_forensic_operation(
            "generate_html_report_basic",
            True,
            {"title": title, "output_path": output_path, "case_id": case_id}
        )
        return True

    except Exception as e:
        # Log the error
        log_forensic_operation(
            "generate_html_report_basic",
            False,
            {"error": str(e), "output_path": output_path},
            level=logging.ERROR
        )
        return False

# Ensure the forensic temporary directory exists
try:
    if FORENSIC_CONSTANTS_LOADED:
        os.makedirs(TEMP_DIR_FORENSICS, mode=DEFAULT_SECURE_DIR_PERMS, exist_ok=True)
        logger.debug(f"Ensured forensic temp directory exists at {TEMP_DIR_FORENSICS}")
except (OSError, PermissionError) as e:
    logger.warning(f"Could not create forensic temporary directory: {e}")

def update_file_integrity_baseline(
    baseline_path: str,
    updates: List[Dict[str, Any]],
    app=None,
    remove_missing: bool = False,
    analyst: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Update a file integrity baseline with new or modified files.

    This function integrates with the core security baseline functionality when available
    or performs a standalone update when the core security module is not present.
    All updates are logged for forensic auditing purposes.

    Args:
        baseline_path: Path to the baseline file
        updates: List of dicts with file paths and hashes to update
                Each dict should have "path" and either "current_hash" or "hash"
        app: Flask application instance (optional, required for core integration)
        remove_missing: If True, files no longer existing are removed from baseline
        analyst: Name of the analyst performing the update (for audit log)

    Returns:
        Tuple of (success: bool, message: str)
    """
    operation_details = {
        "baseline_path": baseline_path,
        "updates_count": len(updates),
        "remove_missing": remove_missing,
        "analyst": analyst or "system"
    }

    # Validate input parameters
    if not baseline_path:
        msg = "Invalid baseline path"
        log_forensic_operation("update_file_baseline", False, {**operation_details, "error": msg}, level=logging.ERROR)
        return False, msg

    if not updates or not isinstance(updates, list):
        msg = "No updates provided or invalid format"
        log_forensic_operation("update_file_baseline", False, {**operation_details, "error": msg}, level=logging.ERROR)
        return False, msg

    # Log operation start
    log_forensic_operation("update_file_baseline", True, {**operation_details, "status": "started"})

    try:
        if CORE_INTEGRITY_AVAILABLE:
            # Use core security module implementation
            logger.debug("Using core security file integrity update")
            success = core_update_baseline(
                app=app,
                baseline_path=baseline_path,
                updates=updates,
                remove_missing=remove_missing
            )

            if success:
                msg = f"Baseline updated successfully via core security module: {len(updates)} changes applied"
                log_forensic_operation("update_file_baseline", True, {**operation_details, "status": "completed"})
                return True, msg
            else:
                msg = "Failed to update baseline via core security module"
                log_forensic_operation("update_file_baseline", False, {**operation_details, "error": msg})
                return False, msg
        else:
            # Standalone implementation
            logger.debug("Using standalone file integrity update")

            # Create parent directory if it doesn't exist
            os.makedirs(os.path.dirname(baseline_path), exist_ok=True)

            # Load existing baseline or create new one
            baseline = {}
            if os.path.exists(baseline_path):
                try:
                    with open(baseline_path, 'r') as f:
                        import json
                        baseline = json.load(f)
                except (json.JSONDecodeError, IOError) as e:
                    msg = f"Error reading baseline file: {str(e)}"
                    log_forensic_operation("update_file_baseline", False, {**operation_details, "error": msg})
                    return False, msg

            # Process updates
            applied_changes = 0
            for update in updates:
                if not isinstance(update, dict):
                    logger.warning(f"Skipping invalid update entry: {update}")
                    continue

                path = update.get('path')
                if not path:
                    logger.warning("Skipping update with missing path")
                    continue

                # Get hash value from update (support both "hash" and "current_hash" keys)
                hash_value = update.get('current_hash') or update.get('hash')
                if not hash_value:
                    logger.warning(f"Skipping update with missing hash for {path}")
                    continue

                # Update baseline entry
                baseline[path] = hash_value
                applied_changes += 1

            # Handle file removals
            removed_count = 0
            if remove_missing:
                to_remove = []
                for path in baseline:
                    if os.path.exists(path):
                        continue
                    to_remove.append(path)

                for path in to_remove:
                    del baseline[path]
                    removed_count += 1

            # Write updated baseline
            try:
                with open(baseline_path, 'w') as f:
                    import json
                    json.dump(baseline, f, indent=2)
            except IOError as e:
                msg = f"Error writing baseline file: {str(e)}"
                log_forensic_operation("update_file_baseline", False, {**operation_details, "error": msg})
                return False, msg

            msg = f"Baseline updated successfully: {applied_changes} changes applied, {removed_count} entries removed"
            log_forensic_operation("update_file_baseline", True, {
                **operation_details,
                "status": "completed",
                "changes_applied": applied_changes,
                "entries_removed": removed_count
            })
            return True, msg

    except Exception as e:
        msg = f"Unexpected error updating baseline: {str(e)}"
        log_forensic_operation("update_file_baseline", False, {**operation_details, "error": msg}, level=logging.ERROR)
        return False, msg

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
    'CORE_INTEGRITY_AVAILABLE',

    # Path constants
    'PACKAGE_PATH',
    'TEMPLATES_DIR',

    # Helper functions
    'get_capabilities',
    'update_file_integrity_baseline',

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
        'track_analysis',
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
        # Encoding/decoding functions
        'bytes_to_base64',
        'base64_to_bytes',
        'bytes_to_hex',
        'hex_to_bytes',

        # Binary conversions
        'convert_hex_to_binary',
        'convert_binary_to_hex',
        'convert_base64_to_binary',
        'convert_binary_to_base64',

        # Timestamp conversions
        'convert_between_timestamp_types',

        # Structured data format conversions
        'convert_json_to_xml',
        'convert_xml_to_json',
        'convert_json_to_csv',
        'dict_to_xml',
        'xml_to_dict',
        'dict_list_to_csv_string',
        'csv_string_to_dict_list',

        # Text encoding
        'convert_to_utf8',
        'detect_encoding',

        # File format conversion
        'convert_file_format',
        'detect_file_format'
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
        'mask_sensitive_value'
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
                # Encoding/decoding
                "bytes_to_base64", "base64_to_bytes", "bytes_to_hex", "hex_to_bytes",
                # Binary conversions
                "convert_hex_to_binary", "convert_binary_to_hex",
                "convert_base64_to_binary", "convert_binary_to_base64",
                # Timestamp conversions
                "convert_between_timestamp_types",
                # Structured data conversions
                "convert_json_to_xml", "convert_xml_to_json", "convert_json_to_csv",
                "dict_to_xml", "xml_to_dict", "dict_list_to_csv_string", "csv_string_to_dict_list",
                # Text encoding
                "convert_to_utf8", "detect_encoding",
                # File format conversion
                "convert_file_format", "detect_file_format"
            ] if FORMAT_CONVERSION_AVAILABLE else []
        },
        "sanitize": {
            "available": SANITIZATION_AVAILABLE,
            "functions": [
                "redact_sensitive_data", "detect_pii", "sanitize_filename",
                "remove_metadata", "prepare_external_report", "detect_credentials",
                "sanitize_ip_addresses", "mask_sensitive_value"
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
        },
        "file_integrity": {
            "available": True,  # Standalone implementation always available
            "core_integration": CORE_INTEGRITY_AVAILABLE,
            "functions": [
                "update_file_integrity_baseline"
            ]
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
            "validation": VALIDATION_UTILS_AVAILABLE,
            "core_integrity_integration": CORE_INTEGRITY_AVAILABLE
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
        ("validation", VALIDATION_UTILS_AVAILABLE),
        ("core_integrity_integration", CORE_INTEGRITY_AVAILABLE)
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
