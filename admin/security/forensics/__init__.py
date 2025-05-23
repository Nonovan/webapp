"""
Digital Forensics Package for Cloud Infrastructure Platform.

This package provides forensic analysis capabilities for security incident investigation
and response, enabling secure collection, preservation, and analysis of digital evidence.
The tools follow forensic best practices and legal requirements to ensure evidence integrity
and proper chain of custody documentation.

Key capabilities include:
- Memory acquisition and analysis for volatile data capture
- Disk forensics for file system analysis and data recovery
- Network traffic capture and analysis for communication reconstruction
- Static file analysis for malware detection and attribution
- Live response tools for active system investigation
- Timeline construction for incident chronology
- Evidence handling utilities with chain of custody tracking
- Report generation with proper forensic documentation

All components are designed to maintain evidence integrity through cryptographic verification,
detailed logging, and minimal system impact during evidence collection.
"""

import logging
import os
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from pathlib import Path

# Initialize package-level logger
logger = logging.getLogger(__name__)

# Version information
__version__ = '1.0.0'
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Initialize capability flags for dependency-based functionality
CRYPTO_AVAILABLE = False
EVIDENCE_TRACKING_AVAILABLE = False
STATIC_ANALYSIS_AVAILABLE = False
LIVE_RESPONSE_AVAILABLE = False
MEMORY_ANALYSIS_AVAILABLE = False
NETWORK_ANALYSIS_AVAILABLE = False
TIMELINE_AVAILABLE = False
REPORT_GENERATION_AVAILABLE = False

# Base package directory
PACKAGE_ROOT = Path(os.path.dirname(os.path.abspath(__file__)))

# Import core utility modules with fallbacks
try:
    from .utils import (
        log_forensic_operation,
        calculate_file_hash,
        verify_file_hash,
        create_secure_temp_file,
        secure_delete,
        verify_evidence_integrity,
        get_forensic_logs,
        export_forensic_logs,
        update_file_integrity_baseline
    )
    CRYPTO_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Forensic utils module not fully available: {e}")

    # Define minimal implementations of critical functions
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict[str, Any]] = None) -> None:
        """Log a forensic operation (fallback implementation)."""
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logger.info(msg)

    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash (fallback implementation)."""
        import hashlib
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.new(algorithm)
                for chunk in iter(lambda: f.read(4096), b''):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return None

# Try to import evidence tracking capabilities
try:
    from .utils.evidence_tracker import (
        register_evidence,
        track_access,
        track_analysis,
        get_evidence_details,
        update_evidence_details,
        get_chain_of_custody,
        list_evidence_by_case,
        create_evidence_container,
        export_chain_of_custody,
        register_analysis_result
    )
    EVIDENCE_TRACKING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Evidence tracking not available: {e}")

# Try to import static analysis capabilities
try:
    from .static_analysis import (
        analyze_file,
        check_malware_signatures,
        scan_with_yara,
        verify_code_signature,
        calculate_multiple_file_hashes,
        find_similar_files,
        save_analysis_report,
        calculate_hash,
        calculate_multiple_hashes,
        calculate_fuzzy_hash
    )
    STATIC_ANALYSIS_AVAILABLE = True
except ImportError as e:
    logger.info(f"Static analysis module not available: {e}")

# Try to import live response capabilities
try:
    from .live_response import (
        get_collector,
        LiveResponseConfig,
        ARTIFACT_TYPES,
        update_evidence_integrity_baseline,
        verify_evidence_integrity as verify_evidence_directory_integrity,
        COLLECTION_TYPES
    )
    LIVE_RESPONSE_AVAILABLE = True
except ImportError as e:
    logger.info(f"Live response module not available: {e}")

# Try to import memory analysis capabilities
try:
    from .memory_analysis import analyze_memory_dump
    MEMORY_ANALYSIS_AVAILABLE = True
except ImportError as e:
    logger.info(f"Memory analysis module not available: {e}")

# Try to import network analysis capabilities
try:
    from .network_analysis import (
        analyze_pcap,
        extract_connections,
        extract_dns_queries,
        extract_http_requests
    )
    NETWORK_ANALYSIS_AVAILABLE = True
except ImportError as e:
    logger.info(f"Network analysis module not available: {e}")

# Try to import timeline creation capabilities
try:
    from .timeline_builder import (
        create_timeline,
        add_event,
        merge_timelines,
        export_timeline
    )
    TIMELINE_AVAILABLE = True
except ImportError as e:
    logger.info(f"Timeline module not available: {e}")

# Try to import report generation capabilities
try:
    from .utils.report_builder import (
        generate_forensic_report,
        generate_html_report,
        generate_pdf_report,
        generate_json_report,
        generate_text_report,
        prepare_report_metadata,
        create_timeline_chart,
        create_evidence_summary
    )
    REPORT_GENERATION_AVAILABLE = True
except ImportError as e:
    logger.info(f"Report generation module not available: {e}")

def get_capabilities() -> Dict[str, Dict[str, Any]]:
    """
    Get available forensic capabilities in the current environment.

    Returns:
        Dict containing available forensic capabilities and their functions
    """
    capabilities = {
        "crypto": {
            "available": CRYPTO_AVAILABLE,
            "functions": [
                "calculate_file_hash",
                "verify_file_hash",
                "secure_delete",
                "create_secure_temp_file",
                "update_file_integrity_baseline"
            ] if CRYPTO_AVAILABLE else []
        },
        "evidence_tracking": {
            "available": EVIDENCE_TRACKING_AVAILABLE,
            "functions": [
                "register_evidence",
                "track_access",
                "track_analysis",
                "get_evidence_details",
                "update_evidence_details",
                "get_chain_of_custody",
                "list_evidence_by_case",
                "create_evidence_container",
                "export_chain_of_custody",
                "register_analysis_result"
            ] if EVIDENCE_TRACKING_AVAILABLE else []
        },
        "static_analysis": {
            "available": STATIC_ANALYSIS_AVAILABLE,
            "functions": [
                "analyze_file",
                "check_malware_signatures",
                "scan_with_yara",
                "verify_code_signature",
                "calculate_multiple_file_hashes",
                "find_similar_files",
                "save_analysis_report",
                "calculate_hash",
                "calculate_multiple_hashes",
                "calculate_fuzzy_hash"
            ] if STATIC_ANALYSIS_AVAILABLE else []
        },
        "live_response": {
            "available": LIVE_RESPONSE_AVAILABLE,
            "functions": [
                "get_collector",
                "LiveResponseConfig",
                "update_evidence_integrity_baseline",
                "verify_evidence_directory_integrity",
                "COLLECTION_TYPES",
                "ARTIFACT_TYPES"
            ] if LIVE_RESPONSE_AVAILABLE else []
        },
        "memory_analysis": {
            "available": MEMORY_ANALYSIS_AVAILABLE,
            "functions": [
                "analyze_memory_dump"
            ] if MEMORY_ANALYSIS_AVAILABLE else []
        },
        "network_analysis": {
            "available": NETWORK_ANALYSIS_AVAILABLE,
            "functions": [
                "analyze_pcap",
                "extract_connections",
                "extract_dns_queries",
                "extract_http_requests"
            ] if NETWORK_ANALYSIS_AVAILABLE else []
        },
        "timeline": {
            "available": TIMELINE_AVAILABLE,
            "functions": [
                "create_timeline",
                "add_event",
                "merge_timelines",
                "export_timeline"
            ] if TIMELINE_AVAILABLE else []
        },
        "reporting": {
            "available": REPORT_GENERATION_AVAILABLE,
            "functions": [
                "generate_forensic_report",
                "generate_html_report",
                "generate_pdf_report",
                "generate_json_report",
                "generate_text_report",
                "prepare_report_metadata",
                "create_timeline_chart",
                "create_evidence_summary"
            ] if REPORT_GENERATION_AVAILABLE else []
        }
    }

    # Add signature database management capability
    capabilities["signature_database"] = {
        "available": STATIC_ANALYSIS_AVAILABLE,
        "functions": [
            "update_signature_database"
        ] if STATIC_ANALYSIS_AVAILABLE else []
    }

    return capabilities

def analyze_evidence(
    evidence_path: str,
    evidence_type: str,
    output_dir: Optional[str] = None,
    case_id: Optional[str] = None,
    analyst: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level function to analyze evidence with the appropriate forensic tool.

    This function serves as an entry point for evidence analysis, automatically
    selecting the appropriate analysis method based on evidence type.

    Args:
        evidence_path: Path to the evidence file
        evidence_type: Type of evidence ("memory", "disk", "network", "file", etc.)
        output_dir: Directory for analysis output (optional)
        case_id: Case identifier for tracking and documentation (optional)
        analyst: Name of analyst performing the analysis (optional)

    Returns:
        Dictionary containing analysis results

    Raises:
        ValueError: If evidence_type is not supported
        FileNotFoundError: If evidence_path does not exist
    """
    if not os.path.exists(evidence_path):
        raise FileNotFoundError(f"Evidence not found: {evidence_path}")

    # Log the analysis operation
    operation_details = {
        "evidence_path": evidence_path,
        "evidence_type": evidence_type,
        "output_dir": output_dir,
        "case_id": case_id
    }
    log_forensic_operation("analyze_evidence_start", True, operation_details)

    # Create results structure
    results = {
        "evidence": evidence_path,
        "evidence_type": evidence_type,
        "timestamp": None,  # Will be set by specific analyzers
        "analyst": analyst,
        "case_id": case_id,
        "findings": {},
        "status": "initialized"
    }

    try:
        # Select appropriate analysis method based on evidence type
        if evidence_type == "memory" and MEMORY_ANALYSIS_AVAILABLE:
            results["findings"] = analyze_memory_dump(
                evidence_path, output_dir=output_dir, case_id=case_id, analyst=analyst)
            results["status"] = "completed"

        elif evidence_type == "network" and NETWORK_ANALYSIS_AVAILABLE:
            results["findings"] = analyze_pcap(
                evidence_path, output_dir=output_dir, case_id=case_id, analyst=analyst)
            results["status"] = "completed"

        elif evidence_type == "file" and STATIC_ANALYSIS_AVAILABLE:
            results["findings"] = analyze_file(
                evidence_path, output_dir=output_dir, case_id=case_id, analyst=analyst)
            results["status"] = "completed"

        else:
            results["status"] = "error"
            results["error"] = f"Unsupported evidence type or analysis module not available: {evidence_type}"
            log_forensic_operation("analyze_evidence_error", False, {
                **operation_details,
                "error": results["error"]
            })
            return results

        # Update evidence tracking if available
        if EVIDENCE_TRACKING_AVAILABLE and case_id:
            try:
                # Generate an evidence ID if not tracking the original evidence
                evidence_id = os.path.basename(evidence_path)
                update_evidence_details(
                    evidence_id, case_id,
                    {"analysis_performed": True, "analyst": analyst, "findings": results["status"]}
                )
                # Track the analysis artifacts if output_dir is specified
                if output_dir:
                    register_evidence(
                        case_id=case_id,
                        evidence_description=f"Analysis results for {os.path.basename(evidence_path)}",
                        evidence_type="analysis_results",
                        source_identifier=evidence_path,
                        acquisition_method="forensic_analysis",
                        acquisition_tool=f"forensics.{evidence_type}_analysis",
                        analyst=analyst or "system",
                        path=output_dir
                    )
            except Exception as e:
                logger.warning(f"Failed to update evidence tracking: {e}")

        # Log successful completion
        log_forensic_operation("analyze_evidence_complete", True, {
            **operation_details,
            "status": "completed"
        })

        return results

    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
        log_forensic_operation("analyze_evidence_error", False, {
            **operation_details,
            "error": str(e)
        })
        return results

def update_signature_database(
    db_type: str,
    source_path: str,
    analyst: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update a forensic signature database with new signatures.

    This function provides a central interface to update various signature databases
    used in forensic analysis, such as malware signatures, code signing certificates,
    or file type signatures.

    Args:
        db_type: Type of database to update ("malware", "code_signing", "file_types")
        source_path: Path to the source signature file or directory
        analyst: Name of analyst performing the update (for audit logs)

    Returns:
        Dictionary containing update results with status and details

    Raises:
        ValueError: If db_type is not supported or source_path is invalid
        PermissionError: If the user lacks permission to update the database
    """
    result = {
        "db_type": db_type,
        "source": source_path,
        "timestamp": None,  # Will be set during the update
        "analyst": analyst,
        "status": "initialized",
        "details": {}
    }

    operation_details = {
        "db_type": db_type,
        "source_path": source_path,
        "analyst": analyst or "system"
    }

    log_forensic_operation("update_signature_database_start", True, operation_details)

    try:
        # Validate database type
        valid_db_types = ["malware", "code_signing", "file_types", "yara_rules"]
        if db_type not in valid_db_types:
            error_msg = f"Invalid database type: {db_type}. Valid types are: {', '.join(valid_db_types)}"
            log_forensic_operation("update_signature_database_error", False,
                                  {**operation_details, "error": error_msg})
            result["status"] = "error"
            result["details"]["error"] = error_msg
            return result

        # Check if static analysis is available
        if not STATIC_ANALYSIS_AVAILABLE:
            error_msg = "Static analysis module not available, cannot update signature database"
            log_forensic_operation("update_signature_database_error", False,
                                  {**operation_details, "error": error_msg})
            result["status"] = "error"
            result["details"]["error"] = error_msg
            return result

        # Process the update using the appropriate database manager
        if db_type in ["malware", "code_signing", "file_types"]:
            # Import the database manager at runtime to avoid circular imports
            from .static_analysis.common.signature_db import SignatureDBManager
            db_manager = SignatureDBManager()
            update_success = db_manager.update_database(db_type, source_path)

            if update_success:
                result["status"] = "completed"
                db_info = db_manager.get_database_info()
                result["details"]["database_info"] = db_info.get(db_type, {})
                log_forensic_operation("update_signature_database_complete", True,
                                      {**operation_details, "status": "completed"})
            else:
                result["status"] = "error"
                result["details"]["error"] = f"Failed to update {db_type} database"
                log_forensic_operation("update_signature_database_error", False,
                                      {**operation_details, "error": result["details"]["error"]})

        # Special handling for YARA rules
        elif db_type == "yara_rules":
            from .static_analysis.common.yara_rules import YaraScanner
            yara_scanner = YaraScanner()
            update_success = yara_scanner.add_rules_from_path(source_path)

            if update_success:
                result["status"] = "completed"
                result["details"]["rules_added"] = update_success
                log_forensic_operation("update_signature_database_complete", True,
                                     {**operation_details, "status": "completed", "rules_added": update_success})
            else:
                result["status"] = "error"
                result["details"]["error"] = "Failed to update YARA rules"
                log_forensic_operation("update_signature_database_error", False,
                                      {**operation_details, "error": result["details"]["error"]})

        return result

    except Exception as e:
        error_msg = str(e)
        result["status"] = "error"
        result["details"]["error"] = error_msg
        log_forensic_operation("update_signature_database_error", False,
                              {**operation_details, "error": error_msg})
        return result

# Export public API
__all__ = [
    # Version information
    '__version__',
    '__author__',
    '__email__',

    # Core functionality
    'get_capabilities',
    'analyze_evidence',
    'update_signature_database',
    'log_forensic_operation',

    # Conditionally available components
    *(['calculate_file_hash', 'verify_file_hash', 'create_secure_temp_file',
       'secure_delete', 'verify_evidence_integrity', 'update_file_integrity_baseline',
       'get_forensic_logs', 'export_forensic_logs'] if CRYPTO_AVAILABLE else []),

    *(['register_evidence', 'track_access', 'track_analysis', 'get_evidence_details',
       'update_evidence_details', 'get_chain_of_custody', 'list_evidence_by_case',
       'create_evidence_container', 'export_chain_of_custody', 'register_analysis_result']
       if EVIDENCE_TRACKING_AVAILABLE else []),

    *(['analyze_file', 'check_malware_signatures', 'scan_with_yara', 'verify_code_signature',
       'calculate_multiple_file_hashes', 'find_similar_files', 'save_analysis_report',
       'calculate_hash', 'calculate_multiple_hashes', 'calculate_fuzzy_hash']
      if STATIC_ANALYSIS_AVAILABLE else []),

    *(['get_collector', 'LiveResponseConfig', 'ARTIFACT_TYPES', 'COLLECTION_TYPES',
       'update_evidence_integrity_baseline', 'verify_evidence_directory_integrity']
      if LIVE_RESPONSE_AVAILABLE else []),

    *(['analyze_memory_dump'] if MEMORY_ANALYSIS_AVAILABLE else []),

    *(['analyze_pcap', 'extract_connections', 'extract_dns_queries', 'extract_http_requests']
      if NETWORK_ANALYSIS_AVAILABLE else []),

    *(['create_timeline', 'add_event', 'merge_timelines', 'export_timeline']
      if TIMELINE_AVAILABLE else []),

    *(['generate_forensic_report', 'generate_html_report', 'generate_pdf_report',
       'generate_json_report', 'generate_text_report', 'prepare_report_metadata',
       'create_timeline_chart', 'create_evidence_summary']
      if REPORT_GENERATION_AVAILABLE else [])
]

# Log initialization status
log_forensic_operation(
    "forensics_package_init",
    True,
    {
        "version": __version__,
        "crypto_available": CRYPTO_AVAILABLE,
        "evidence_tracking_available": EVIDENCE_TRACKING_AVAILABLE,
        "static_analysis_available": STATIC_ANALYSIS_AVAILABLE,
        "live_response_available": LIVE_RESPONSE_AVAILABLE,
        "memory_analysis_available": MEMORY_ANALYSIS_AVAILABLE,
        "network_analysis_available": NETWORK_ANALYSIS_AVAILABLE,
        "timeline_available": TIMELINE_AVAILABLE,
        "report_generation_available": REPORT_GENERATION_AVAILABLE
    }
)
