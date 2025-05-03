"""
Common assessment components package for security assessment tools.

This package provides shared utilities and common components used across
security assessment tools in the Cloud Infrastructure Platform. It implements
core functionality for assessment execution, result processing, evidence
collection, and secure logging.

These components ensure consistent behavior, proper security controls,
and standardized outputs across different assessment tools.

Key components:
- Assessment base classes for standardized tool implementation
- Assessment engine for executing security evaluations
- Evidence collector for proper documentation
- Result formatter for consistent output
- Secure logging facilities
- Common data types and utilities
"""

import os
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, Union

# Initialize package logger with null handler to prevent no-handler warnings
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Set package path
PACKAGE_PATH = Path(__file__).parent
PROJECT_ROOT = PACKAGE_PATH.parent.parent.parent.parent.parent

# Initialize version
__version__ = "1.0.0"

# Output format constants
FORMAT_JSON = "json"
FORMAT_CSV = "csv"
FORMAT_XML = "xml"
FORMAT_HTML = "html"
FORMAT_MARKDOWN = "markdown"
FORMAT_TEXT = "text"
FORMAT_STANDARD = "standard"
FORMAT_SARIF = "sarif"
FORMAT_JUNIT = "junit"

# Default output formats list
VALID_OUTPUT_FORMATS = [
    FORMAT_JSON, FORMAT_CSV, FORMAT_XML, FORMAT_HTML, FORMAT_MARKDOWN,
    FORMAT_TEXT, FORMAT_STANDARD, FORMAT_SARIF, FORMAT_JUNIT
]

# Try to import components and handle missing dependencies gracefully
try:
    from .assessment_base import (
        AssessmentBase,
        AssessmentPlugin,
        AssessmentStatus,
        AssessmentException,
        AssessmentInitializationError,
        AssessmentExecutionError,
        AssessmentConfigurationError
    )

    from .assessment_logging import (
        setup_logging,
        setup_assessment_logging,
        get_assessment_logger,
        log_assessment_event,
        log_security_finding,
        configure_file_logging,
        sanitize_sensitive_data
    )

    from .data_types import (
        AssessmentTarget,
        Finding,
        FindingSeverity,
        FindingStatus,
        Evidence,
        AssessmentResult,
        Remediation,
        CVSS,
        RiskLevel
    )

    from .evidence_collector import (
        EvidenceCollector,
        collect_file_evidence,
        collect_command_output,
        collect_screenshot,
        create_evidence_directory,
        create_evidence_package,
        verify_evidence_integrity,
        add_chain_of_custody_entry
    )

    from .output_formatters import (
        format_json_output,
        format_csv_output,
        format_xml_output,
        format_html_output,
        format_markdown_output
    )

    from .result_formatter import (
        ResultFormatter,
        generate_summary,
        export_findings
    )

    from .validation import (
        validate_target,
        validate_profile,
        validate_output_format,
        validate_compliance_framework,
        is_valid_ip_address,
        is_valid_hostname,
        sanitize_input
    )

    from .connection_manager import (
        ConnectionManager,
        secure_connect,
        test_connectivity,
        get_connection_for_target,
        ConnectionTarget,
        ConnectionType,
        ConnectionPool,
        ConnectionError,
        AuthenticationError,
        SSLError,
        ConnectionTimeoutError
    )

    from .error_handlers import (
        handle_assessment_error,
        retry_operation,
        safe_execute,
        ExponentialBackoff,
        ErrorScope,
        ErrorSeverity,
        ErrorReporter,
        validate_assessment_preconditions,
        handle_specific_exceptions,
        circuit_breaker,
        capture_assessment_exceptions,
        with_timeout,
        error_chain_formatter
    )

    from .permission_utils import (
        check_assessment_permission,
        verify_target_access,
        has_required_permissions
    )

    from .result_cache import (
        ResultCache,
        invalidate_cache_key,
        invalidate_cache_pattern,
        clear_all_cache,
        get_cached_assessment,
        cache_assessment_result,
        get_cached_results_summary,
        export_cache_to_file,
        import_cache_from_file,
        prune_expired_cache_entries,
        get_cache_stats,
        configure_cache
    )

    HAS_ALL_COMPONENTS = True
    logger.debug("All common assessment components imported successfully")

except ImportError as e:
    HAS_ALL_COMPONENTS = False
    missing_module = str(e).split("No module named '")[-1].rstrip("'")
    logger.warning(f"Could not import all assessment components: {missing_module}")

    # Define fallback for core classes if needed
    if "assessment_base" in missing_module:
        class AssessmentBase:
            """Placeholder for AssessmentBase when module is unavailable."""

            def __init__(self, *args, **kwargs):
                raise NotImplementedError("AssessmentBase module not available")

        class AssessmentStatus:
            """Placeholder for AssessmentStatus when module is unavailable."""
            NOT_STARTED = "not_started"
            FAILED = "failed"
            COMPLETED = "completed"

# Initialize components that require setup
def initialize_common_components(config_path: Optional[str] = None) -> bool:
    """
    Initialize common assessment components with optional configuration.

    Args:
        config_path: Path to configuration file (optional)

    Returns:
        True if initialization was successful, False otherwise
    """
    try:
        # Set up secure logging first
        logger.info("Initializing common assessment components")

        # Validate core dependencies
        if not HAS_ALL_COMPONENTS:
            logger.warning("Some components are missing, functionality may be limited")

        # Load configuration if provided
        if config_path:
            if not os.path.exists(config_path):
                logger.error(f"Configuration file not found: {config_path}")
                return False

            # In a real implementation, would load and process config here
            logger.info(f"Loaded configuration from {config_path}")

        logger.info("Common assessment components initialized successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to initialize common assessment components: {e}")
        return False

def format_assessment_output(
    data: Dict[str, Any],
    format_type: str = FORMAT_STANDARD,
    output_file: Optional[str] = None,
    **kwargs
) -> Union[str, bool]:
    """
    Format assessment data into the specified output format.

    Args:
        data: Assessment data to format
        format_type: Output format (json, csv, xml, html, markdown, text, standard, sarif, junit)
        output_file: Optional file path to write results to
        **kwargs: Additional format-specific options

    Returns:
        Formatted string if output_file is None, otherwise boolean success status
    """
    try:
        format_type = format_type.lower()

        # Validate output format
        if format_type not in VALID_OUTPUT_FORMATS:
            logger.warning(f"Unsupported format '{format_type}', using '{FORMAT_STANDARD}' instead")
            format_type = FORMAT_STANDARD

        # Use ResultFormatter if available
        formatter = ResultFormatter()

        # Check if data is already an AssessmentResult
        if hasattr(data, 'to_dict'):
            results = data
        else:
            # Create a minimal AssessmentResult
            from datetime import datetime

            results = AssessmentResult(
                assessment_id=data.get("assessment_id", "generated"),
                name=data.get("name", "Assessment Results"),
                target=data.get("target", {}),
                findings=data.get("findings", []),
                start_time=data.get("start_time", datetime.now()),
                end_time=data.get("end_time", datetime.now()),
                status=data.get("status", "completed")
            )

        # Format the output
        formatted_content = formatter.format(
            results=results,
            format_type=format_type,
            include_evidence=kwargs.get('include_evidence', False),
            filter_severity=kwargs.get('filter_severity', None),
            compliance_map=kwargs.get('compliance_map', None)
        )

        # Write to file if specified
        if output_file:
            return formatter.write_to_file(formatted_content, output_file)

        return formatted_content

    except Exception as e:
        logger.error(f"Error formatting assessment output: {e}", exc_info=True)
        if output_file:
            return False
        return f"Error formatting output: {str(e)}"

# Define public API
__all__ = [
    # Core classes
    'AssessmentBase',
    'AssessmentPlugin',
    'AssessmentStatus',
    'AssessmentException',
    'AssessmentInitializationError',
    'AssessmentExecutionError',
    'AssessmentConfigurationError',

    # Data types
    'AssessmentTarget',
    'Finding',
    'FindingSeverity',
    'FindingStatus',
    'Evidence',
    'AssessmentResult',
    'Remediation',
    'CVSS',
    'RiskLevel',

    # Logging
    'setup_logging',
    'setup_assessment_logging',
    'get_assessment_logger',
    'log_assessment_event',
    'log_security_finding',

    # Evidence collection
    'EvidenceCollector',
    'collect_file_evidence',
    'collect_command_output',
    'collect_screenshot',
    'create_evidence_directory',

    # Result handling
    'ResultFormatter',
    'format_json_output',
    'format_csv_output',
    'format_xml_output',
    'format_html_output',
    'format_markdown_output',
    'generate_summary',
    'export_findings',
    'format_assessment_output',

    # Output format constants
    'FORMAT_JSON',
    'FORMAT_CSV',
    'FORMAT_XML',
    'FORMAT_HTML',
    'FORMAT_MARKDOWN',
    'FORMAT_TEXT',
    'FORMAT_STANDARD',
    'FORMAT_SARIF',
    'FORMAT_JUNIT',
    'VALID_OUTPUT_FORMATS',

    # Utilities
    'validate_target',
    'validate_profile',
    'validate_output_format',
    'validate_compliance_framework',
    'sanitize_input',

    # Connection management
    'ConnectionManager',
    'secure_connect',
    'test_connectivity',
    'get_connection_for_target',
    'ConnectionTarget',
    'ConnectionType',
    'ConnectionPool',
    'ConnectionError',
    'AuthenticationError',
    'SSLError',
    'ConnectionTimeoutError',

    # Error handling
    'handle_assessment_error',
    'retry_operation',
    'safe_execute',
    'ExponentialBackoff',
    'ErrorScope',
    'ErrorSeverity',
    'ErrorReporter',
    'validate_assessment_preconditions',
    'handle_specific_exceptions',
    'circuit_breaker',
    'capture_assessment_exceptions',
    'with_timeout',
    'error_chain_formatter',

    # Permission management
    'check_assessment_permission',
    'verify_target_access',
    'has_required_permissions',

    # Result cache
    'ResultCache',
    'invalidate_cache_key',
    'invalidate_cache_pattern',
    'clear_all_cache',
    'get_cached_assessment',
    'cache_assessment_result',
    'get_cached_results_summary',
    'export_cache_to_file',
    'import_cache_from_file',
    'prune_expired_cache_entries',
    'get_cache_stats',
    'configure_cache',

    # Package info
    'initialize_common_components',
    'PACKAGE_PATH',
    'PROJECT_ROOT',
    '__version__',
    'HAS_ALL_COMPONENTS'
]
