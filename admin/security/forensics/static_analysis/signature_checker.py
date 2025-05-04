"""
Signature Checker Tool for Forensic Static Analysis

This tool verifies file signatures, checks against known malware hash databases,
and performs YARA rule matching as part of the static analysis process within
the Cloud Infrastructure Platform's Forensic Analysis Toolkit.

Key features:
- Malware signature detection via hash comparison
- YARA rule pattern matching for suspicious patterns
- Code signing certificate verification
- Comprehensive reporting with detailed analysis
- Integration with forensic logging and evidence handling
"""

import argparse
import json
import logging
import os
import sys
import time
import hashlib
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set, Union

# Add parent directory to path for module imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

# Attempt to import common forensic and static analysis utilities
try:
    # Common file operations and analysis
    from admin.security.forensics.utils.forensic_constants import SAFE_FILE_EXTENSIONS
    from admin.security.forensics.static_analysis.common.file_utils import (
        safe_analyze_file,
        calculate_hash,
        calculate_multiple_hashes,
        save_analysis_report,
        identify_file_type,
        validate_file_integrity
    )
    # Signature database management
    from admin.security.forensics.static_analysis.common.signature_db import SignatureDBManager, SignatureVerificationStatus
    # YARA scanning capabilities
    from admin.security.forensics.static_analysis.common.yara_rules import YaraScanner
    # Core forensic logging and validation
    from admin.security.forensics.utils.logging_utils import (
        setup_forensic_logger,
        log_forensic_operation
    )
    from admin.security.forensics.utils.validation_utils import (
        validate_path,
        validate_file_permissions,
        ALLOWED_MIME_TYPES
    )
    # Evidence tracking if available
    try:
        from admin.security.forensics.utils.evidence_tracker import (
            get_evidence_details,
            update_evidence_details,
            track_analysis
        )
        EVIDENCE_TRACKING_AVAILABLE = True
    except ImportError:
        EVIDENCE_TRACKING_AVAILABLE = False

    FORENSIC_CORE_AVAILABLE = True
    SIGNATURE_DB_AVAILABLE = True
    YARA_SCANNER_AVAILABLE = True

except ImportError as e:
    # Fallback if core forensic utilities are not available
    print(f"Warning: Critical forensic modules could not be imported: {e}. Functionality may be limited.")
    # Define dummy functions or basic fallbacks if necessary
    FORENSIC_CORE_AVAILABLE = False
    SIGNATURE_DB_AVAILABLE = False
    YARA_SCANNER_AVAILABLE = False
    EVIDENCE_TRACKING_AVAILABLE = False

    # Basic logging setup if forensic logger fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('signature_checker_fallback')

    # Dummy log function
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any], level=logging.INFO):
        logger.log(level, f"Operation '{operation}' {'succeeded' if success else 'failed'}. Details: {details}")

    # Dummy validation - providing better implementation
    def validate_path(path_str: str, **kwargs) -> tuple[bool, str]:
        """Basic path validation fallback."""
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        if kwargs.get('must_be_file', False) and not os.path.isfile(path_str):
            return False, f"Path is not a file: {path_str}"
        if kwargs.get('must_be_dir', False) and not os.path.isdir(path_str):
            return False, f"Path is not a directory: {path_str}"
        if kwargs.get('check_read', False) and not os.access(path_str, os.R_OK):
            return False, f"Path not readable: {path_str}"
        return True, "Path is valid"

    def validate_file_permissions(path_str: str) -> tuple[bool, str]:
        """Basic file permissions validation fallback."""
        if not os.path.exists(path_str):
            return False, f"Path does not exist: {path_str}"
        if not os.access(path_str, os.R_OK):
            return False, f"File not readable: {path_str}"
        return True, "File permissions are valid"

    # Dummy file type identification
    def identify_file_type(file_path: str) -> Dict[str, Any]:
        """Basic file type identification fallback."""
        result = {"mime_type": "application/octet-stream", "extension": "bin", "description": "Unknown"}
        try:
            import mimetypes
            mime_type, encoding = mimetypes.guess_type(file_path)
            if mime_type:
                result["mime_type"] = mime_type
                result["extension"] = file_path.split('.')[-1].lower() if '.' in file_path else ""
                result["description"] = mime_type
        except Exception:
            pass
        return result

    # Dummy hash calculation function
    def calculate_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash using specified algorithm."""
        import hashlib
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as ex:
            logger.error(f"Hash calculation failed: {ex}")
            return None

    # More comprehensive multi-hash calculation
    def calculate_multiple_hashes(file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        """Calculate multiple hashes for a file."""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']

        result = {}
        for algorithm in algorithms:
            result[algorithm] = calculate_hash(file_path, algorithm)
        return result

    # Dummy file integrity validation
    def validate_file_integrity(file_path: str) -> bool:
        """Basic file integrity validation."""
        return os.path.exists(file_path) and os.access(file_path, os.R_OK)

    # Dummy save function - improved
    def save_analysis_report(data: Dict[str, Any], output_path: str, format: str = "json") -> bool:
        """Save analysis report to a file."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                if format.lower() == 'json':
                    json.dump(data, f, indent=4, default=str)
                elif format.lower() == 'yaml':
                    try:
                        yaml.dump(data, f, default_flow_style=False)
                    except ImportError:
                        # Fall back to JSON if yaml not available
                        json.dump(data, f, indent=4, default=str)
                else:  # Basic text fallback
                    f.write(format_results_text(data))
            logger.info(f"Report saved to {output_path}")
            return True
        except Exception as ex:
            logger.error(f"Failed to save report to {output_path}: {ex}")
            return False

    # Define constants to match the expected imports
    SAFE_FILE_EXTENSIONS.update({'.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.pdf'})
    ALLOWED_MIME_TYPES.update({
        'text/plain', 'text/html', 'text/csv', 'text/xml',
        'application/json', 'application/xml', 'application/pdf'
    })

    # Define a simple SignatureVerificationStatus class for fallback
    class SignatureVerificationStatus:
        def __init__(self, verified=False, verification_attempted=False,
                     signer_name="", reason="", timestamp=None):
            self.verified = verified
            self.verification_attempted = verification_attempted
            self.signer_name = signer_name
            self.reason = reason
            self.timestamp = timestamp or datetime.now()

        def to_dict(self):
            return {
                "verified": self.verified,
                "verification_attempted": self.verification_attempted,
                "signer_name": self.signer_name,
                "reason": self.reason,
                "timestamp": str(self.timestamp)
            }

# Setup logger if core utils are available
if FORENSIC_CORE_AVAILABLE:
    setup_forensic_logger()
    logger = logging.getLogger('forensic_signature_checker')
else:
    # Use the fallback logger defined above
    pass


# --- Constants ---
DEFAULT_OUTPUT_FORMAT = "json"
SUPPORTED_OUTPUT_FORMATS = ["json", "text", "yaml", "csv"]
DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_HASH_ALGORITHMS = ["md5", "sha1", "sha256"]
MAX_STRING_DISPLAY_LENGTH = 100  # Maximum length for displaying strings in output
MAX_REPORT_SIZE_MB = 100  # Maximum report size in MB
TEMP_DIR = os.environ.get("TEMP_DIR", "/tmp/forensic_signature_checker")
HIGH_RISK_MIME_TYPES = {
    'application/x-dosexec', 'application/x-executable', 'application/x-sharedlib',
    'application/x-mach-binary', 'application/vnd.microsoft.portable-executable',
    'application/x-msdownload', 'application/x-ms-shortcut'
}
REPUTATION_SERVICE_TIMEOUT = 10  # Seconds
DEFAULT_SIGNATURE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common", "signature_db")
DEFAULT_YARA_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common", "yara_rules")


# --- Core Functions ---

def check_malware_signatures(file_path: str, db_manager: Optional[Any]) -> Dict[str, Any]:
    """
    Check the file's hash against known malware signature databases.

    Args:
        file_path: Path to file for analysis
        db_manager: SignatureDBManager instance or None

    Returns:
        Dictionary with status and any matches found
    """
    results = {"status": "skipped", "matches": []}
    start_time = time.time()

    if not SIGNATURE_DB_AVAILABLE or db_manager is None:
        results["status"] = "error"
        results["error_message"] = "SignatureDBManager not available."
        logger.warning("Malware signature check skipped: SignatureDBManager not available.")
        return results

    logger.info(f"Checking malware signatures for: {file_path}")

    # Record operation details for logging
    operation_details = {
        "file": file_path,
        "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        "operation": "check_malware_signatures"
    }

    try:
        # Calculate multiple hashes for comprehensive comparison
        # Note: SignatureDBManager should handle hash algorithm selection internally
        file_hashes = calculate_multiple_hashes(file_path, DEFAULT_HASH_ALGORITHMS)

        if not file_hashes or not any(file_hashes.values()):
            results["status"] = "error"
            results["error_message"] = "Failed to calculate file hashes."
            log_forensic_operation(
                "malware_signature_check",
                False,
                {**operation_details, "error": results["error_message"]},
                level=logging.ERROR
            )
            return results

        results["hashes"] = file_hashes

        # Get file type information for context
        file_type_info = identify_file_type(file_path)
        results["file_info"] = file_type_info

        # Check against malware database
        matches = db_manager.check_malware_signatures(
            file_path=file_path,
            file_hash=file_hashes.get(DEFAULT_HASH_ALGORITHM)
        )

        if matches:
            results["status"] = "detected"
            results["matches_count"] = len(matches)
            results["matches"] = [match.to_dict() for match in matches]  # Assuming match object has to_dict()

            # Add risk level based on malware categories
            risk_levels = [match.risk_level for match in matches if hasattr(match, 'risk_level')]
            if risk_levels:
                results["risk_level"] = max(risk_levels, default="medium")
            else:
                results["risk_level"] = "medium"

            logger.warning(f"Malware signatures detected for {file_path}: {len(matches)} matches.")

            # Log forensic event for malware detection
            log_forensic_operation(
                "malware_signature_detected",
                True,
                {
                    **operation_details,
                    "matches_count": len(matches),
                    "risk_level": results["risk_level"],
                    "detection_names": [match.name for match in matches[:5] if hasattr(match, 'name')]
                },
                level=logging.WARNING
            )
        else:
            results["status"] = "clean"
            results["risk_level"] = "low"
            logger.info(f"No known malware signatures found for {file_path}.")

            log_forensic_operation(
                "malware_signature_check",
                True,
                {**operation_details, "status": "clean"},
                level=logging.INFO
            )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error checking malware signatures for {file_path}: {error_msg}", exc_info=True)
        results["status"] = "error"
        results["error_message"] = error_msg

        log_forensic_operation(
            "malware_signature_check",
            False,
            {**operation_details, "error": error_msg},
            level=logging.ERROR
        )

    # Add execution time
    results["execution_time"] = time.time() - start_time

    return results


def scan_with_yara(file_path: str, yara_scanner: Optional[Any], rules_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan the file using YARA rules.

    Args:
        file_path: Path to file for analysis
        yara_scanner: YaraScanner instance or None
        rules_path: Path to YARA rules file or directory

    Returns:
        Dictionary with status and any matches found
    """
    results = {"status": "skipped", "matches": []}
    start_time = time.time()

    if not YARA_SCANNER_AVAILABLE or yara_scanner is None:
        results["status"] = "error"
        results["error_message"] = "YaraScanner not available."
        logger.warning("YARA scan skipped: YaraScanner not available.")
        return results

    # Use default rules path if none provided
    if not rules_path:
        rules_path = DEFAULT_YARA_RULES_PATH
        logger.info(f"No YARA rules path provided, using default: {rules_path}")

        # Check if default rules path exists
        if not os.path.exists(rules_path):
            results["status"] = "error"
            results["error_message"] = f"Default YARA rules path not found: {rules_path}"
            logger.warning(results["error_message"])
            return results

    logger.info(f"Scanning {file_path} with YARA rules from: {rules_path}")

    # Record operation details for logging
    operation_details = {
        "file": file_path,
        "rules_path": rules_path,
        "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        "operation": "yara_scan"
    }

    try:
        # Check if the file is readable before scanning
        valid, validation_msg = validate_path(file_path, check_read=True)
        if not valid:
            results["status"] = "error"
            results["error_message"] = f"File validation failed: {validation_msg}"
            log_forensic_operation(
                "yara_scan_error",
                False,
                {**operation_details, "error": results["error_message"]},
                level=logging.ERROR
            )
            return results

        # Get file type information for context
        file_type_info = identify_file_type(file_path)
        results["file_info"] = file_type_info

        # Scan the file with YARA rules
        matches = yara_scanner.scan_file(file_path, rules_path=rules_path)

        if matches:
            results["status"] = "detected"
            results["matches_count"] = len(matches)

            # Format matches for reporting - depend on YaraScanner implementation
            formatted_matches = []
            high_severity_count = 0
            for match in matches:
                match_data = {
                    "rule": match.rule if hasattr(match, 'rule') else "Unknown rule",
                    "tags": match.tags if hasattr(match, 'tags') else [],
                    "meta": match.meta if hasattr(match, 'meta') else {},
                    "strings": []  # Will contain string matches, truncated
                }

                # Add string matches if available (might be long, so limit their size)
                if hasattr(match, 'strings') and match.strings:
                    for string_match in match.strings[:10]:  # Limit to first 10 matches
                        try:
                            offset, identifier, matched_data = string_match
                            # Convert binary data to a safe representation
                            if isinstance(matched_data, bytes):
                                # Show hex representation for binary data
                                data_repr = matched_data.hex()[:100]
                            else:
                                data_repr = str(matched_data)[:100]

                            match_data["strings"].append({
                                "offset": offset,
                                "identifier": identifier,
                                "data": data_repr
                            })
                        except (ValueError, TypeError, IndexError):
                            # Skip malformed string matches
                            continue

                # Determine severity from meta if available
                severity = "medium"  # Default
                if match_data["meta"] and "severity" in match_data["meta"]:
                    severity = match_data["meta"]["severity"]

                match_data["severity"] = severity

                if severity.lower() in ("high", "critical"):
                    high_severity_count += 1

                formatted_matches.append(match_data)

            results["matches"] = formatted_matches

            # Determine overall risk level based on match severities
            if high_severity_count > 0:
                results["risk_level"] = "high"
            elif len(matches) > 5:
                results["risk_level"] = "medium"
            else:
                results["risk_level"] = "low"

            logger.warning(f"YARA matches found for {file_path}: {len(matches)} rules.")

            # Log forensic event for yara detection
            log_forensic_operation(
                "yara_match_detected",
                True,
                {
                    **operation_details,
                    "matches_count": len(matches),
                    "high_severity_count": high_severity_count,
                    "risk_level": results["risk_level"],
                    "rule_names": [m.rule for m in matches[:5] if hasattr(m, 'rule')]
                },
                level=logging.WARNING
            )
        else:
            results["status"] = "clean"
            results["risk_level"] = "low"
            logger.info(f"No YARA rule matches found for {file_path}.")

            log_forensic_operation(
                "yara_scan",
                True,
                {**operation_details, "status": "clean"},
                level=logging.INFO
            )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error scanning {file_path} with YARA: {error_msg}", exc_info=True)
        results["status"] = "error"
        results["error_message"] = error_msg

        log_forensic_operation(
            "yara_scan",
            False,
            {**operation_details, "error": error_msg},
            level=logging.ERROR
        )

    # Add execution time
    results["execution_time"] = time.time() - start_time

    return results


def verify_code_signature(file_path: str, db_manager: Optional[Any]) -> Dict[str, Any]:
    """
    Verify the digital code signing signature of the file.

    Args:
        file_path: Path to file for analysis
        db_manager: SignatureDBManager instance or None

    Returns:
        Dictionary with verification status and details
    """
    results = {"status": "skipped", "details": {}}
    start_time = time.time()

    if not SIGNATURE_DB_AVAILABLE or db_manager is None:
        results["status"] = "error"
        results["error_message"] = "SignatureDBManager not available."
        logger.warning("Code signature verification skipped: SignatureDBManager not available.")
        return results

    logger.info(f"Verifying code signature for: {file_path}")

    # Record operation details for logging
    operation_details = {
        "file": file_path,
        "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        "operation": "verify_code_signature"
    }

    # Get file type information to determine if signature verification is applicable
    file_type_info = identify_file_type(file_path)
    results["file_info"] = file_type_info

    # Skip signature verification for non-executable file types
    if file_type_info.get("mime_type") not in HIGH_RISK_MIME_TYPES and not file_path.lower().endswith(
            ('.exe', '.dll', '.sys', '.ocx', '.cab', '.msi', '.jar', '.app', '.dylib', '.so')):
        results["status"] = "not_applicable"
        results["details"] = {"message": "File type does not typically have code signatures."}
        logger.info(f"Skipping signature verification for non-executable file: {file_path}")
        return results

    try:
        # Verify signature using SignatureDBManager
        verification_status = db_manager.verify_code_signature(file_path)

        # Handle verification result
        if verification_status.verified:
            results["status"] = "verified"
            results["details"] = verification_status.to_dict()
            results["risk_level"] = "low"

            logger.info(f"Code signature verified for {file_path}. Signer: {verification_status.signer_name}")

            log_forensic_operation(
                "signature_verification",
                True,
                {
                    **operation_details,
                    "status": "verified",
                    "signer": verification_status.signer_name,
                    "timestamp": str(verification_status.timestamp) if hasattr(verification_status, 'timestamp') else ""
                },
                level=logging.INFO
            )

        elif verification_status.verification_attempted:
            results["status"] = "invalid"
            results["details"] = verification_status.to_dict()
            results["risk_level"] = "high"

            logger.warning(f"Invalid code signature for {file_path}. Reason: {verification_status.reason}")

            log_forensic_operation(
                "signature_verification",
                False,
                {
                    **operation_details,
                    "status": "invalid",
                    "reason": verification_status.reason
                },
                level=logging.WARNING
            )

        else:
            results["status"] = "not_signed"
            results["details"] = {"message": "File is not signed."}

            # Executable files without signatures are higher risk
            if file_type_info.get("mime_type") in HIGH_RISK_MIME_TYPES:
                results["risk_level"] = "high"
                log_level = logging.WARNING
            else:
                results["risk_level"] = "medium"
                log_level = logging.INFO

            logger.log(log_level, f"No code signature found for {file_path}.")

            log_forensic_operation(
                "signature_verification",
                True,
                {**operation_details, "status": "not_signed"},
                level=log_level
            )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error verifying code signature for {file_path}: {error_msg}", exc_info=True)
        results["status"] = "error"
        results["error_message"] = error_msg
        results["risk_level"] = "unknown"

        log_forensic_operation(
            "signature_verification",
            False,
            {**operation_details, "error": error_msg},
            level=logging.ERROR
        )

    # Add execution time
    results["execution_time"] = time.time() - start_time

    return results


def check_reputation(file_path: str, hash_values: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Check file reputation using online services if available.

    Args:
        file_path: Path to file for analysis
        hash_values: Pre-calculated hash values or None

    Returns:
        Dictionary with reputation data
    """
    results = {"status": "skipped", "sources": []}

    # If hash values not provided, calculate them
    if not hash_values:
        try:
            hash_values = calculate_multiple_hashes(file_path, ["md5", "sha1", "sha256"])
        except Exception as e:
            results["status"] = "error"
            results["error_message"] = f"Failed to calculate hashes: {e}"
            return results

    # Record which hashes we're using
    results["hashes"] = hash_values

    # Try to query reputation services if available
    try:
        # This is a placeholder for reputation checking logic
        # In a complete implementation, this would connect to reputation services
        # such as VirusTotal, AlienVault OTX, or internal threat intelligence platforms

        # For now, just return a dummy result
        results["status"] = "completed"
        results["sources"] = []
        results["known_bad"] = False
        results["risk_score"] = 0

        logger.info(f"Reputation check completed for {file_path} (placeholder implementation)")

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error checking reputation for {file_path}: {error_msg}")
        results["status"] = "error"
        results["error_message"] = error_msg

    return results


def format_results_text(results: Dict[str, Any]) -> str:
    """
    Format analysis results as human-readable text.

    Args:
        results: Analysis results dictionary

    Returns:
        Formatted text representation
    """
    output_lines = []
    output_lines.append("=== Signature Checker Analysis Report ===")
    output_lines.append(f"File: {results.get('file_path', 'Unknown')}")
    output_lines.append(f"Analysis Time: {results.get('analysis_timestamp', datetime.now().isoformat())}")

    # Add summary information
    output_lines.append("\n--- Summary ---")
    summary = results.get("analysis_summary", {})

    # Show overall risk assessment if available
    if "overall_risk_level" in summary:
        output_lines.append(f"Overall Risk Level: {summary['overall_risk_level'].upper()}")

    # Show status for each check
    if "malware_db_status" in summary:
        output_lines.append(f"Malware Signatures: {summary['malware_db_status'].upper()}")
    if "yara_scan_status" in summary:
        output_lines.append(f"YARA Scan: {summary['yara_scan_status'].upper()}")
    if "code_signing_status" in summary:
        output_lines.append(f"Code Signature: {summary['code_signing_status'].upper()}")
    if "reputation_status" in summary:
        output_lines.append(f"Reputation Check: {summary['reputation_status'].upper()}")

    # Add file hashes if available
    if "file_hashes" in results:
        output_lines.append("\n--- File Hashes ---")
        for alg, hash_val in results["file_hashes"].items():
            output_lines.append(f"{alg.upper()}: {hash_val}")

    # Add malware signature details if available
    if "malware_signature_check" in results:
        malware_check = results["malware_signature_check"]
        output_lines.append("\n--- Malware Signature Check ---")
        output_lines.append(f"Status: {malware_check.get('status', 'Unknown').upper()}")

        matches = malware_check.get("matches", [])
        if matches:
            output_lines.append(f"Matched {len(matches)} malware signatures:")
            for i, match in enumerate(matches[:10]):  # Show first 10
                name = match.get("name", "Unknown")
                source = match.get("source", "Unknown")
                family = match.get("family", "Unknown")
                category = match.get("category", "Unknown")

                output_lines.append(f"  {i+1}. {name} (Family: {family}, Category: {category}, Source: {source})")

            if len(matches) > 10:
                output_lines.append(f"  ... and {len(matches) - 10} more matches")

        elif malware_check.get("status") == "error":
            output_lines.append(f"Error: {malware_check.get('error_message', 'Unknown error')}")
        else:
            output_lines.append("No malware signatures detected.")

    # Add YARA scan details if available
    if "yara_scan" in results:
        yara_scan = results["yara_scan"]
        output_lines.append("\n--- YARA Scan ---")
        output_lines.append(f"Status: {yara_scan.get('status', 'Unknown').upper()}")

        matches = yara_scan.get("matches", [])
        if matches:
            output_lines.append(f"Matched {len(matches)} YARA rules:")
            for i, match in enumerate(matches[:10]):  # Show first 10
                rule = match.get("rule", "Unknown")
                tags = ", ".join(match.get("tags", []))
                severity = match.get("severity", "medium").upper()
                description = match.get("meta", {}).get("description", "No description")

                output_lines.append(f"  {i+1}. {rule} (Severity: {severity})")
                if tags:
                    output_lines.append(f"     Tags: {tags}")
                output_lines.append(f"     Description: {description}")

                # Show extracted strings if available (limit to first few)
                strings = match.get("strings", [])
                if strings:
                    output_lines.append(f"     Matched {len(strings)} string patterns:")
                    for j, string_match in enumerate(strings[:3]):
                        offset = string_match.get("offset", "Unknown")
                        identifier = string_match.get("identifier", "Unknown")
                        data = string_match.get("data", "")

                        if len(data) > 40:
                            data = data[:37] + "..."

                        output_lines.append(f"       - '{identifier}' at offset {offset}: {data}")

                    if len(strings) > 3:
                        output_lines.append(f"       ... and {len(strings) - 3} more string matches")

            if len(matches) > 10:
                output_lines.append(f"  ... and {len(matches) - 10} more rule matches")

        elif yara_scan.get("status") == "error":
            output_lines.append(f"Error: {yara_scan.get('error_message', 'Unknown error')}")
        else:
            output_lines.append("No YARA rules matched.")

    # Add code signing details if available
    if "code_signature_verification" in results:
        sig_verify = results["code_signature_verification"]
        output_lines.append("\n--- Code Signature Verification ---")
        output_lines.append(f"Status: {sig_verify.get('status', 'Unknown').upper()}")

        details = sig_verify.get("details", {})
        if details:
            if sig_verify.get("status") == "verified":
                output_lines.append(f"Signer: {details.get('signer_name', 'Unknown')}")
                output_lines.append(f"Timestamp: {details.get('timestamp', 'Unknown')}")
                output_lines.append(f"Issuer: {details.get('issuer', 'Unknown')}")
                if details.get("valid_from") and details.get("valid_to"):
                    output_lines.append(f"Validity: {details.get('valid_from')} to {details.get('valid_to')}")
            elif sig_verify.get("status") == "invalid":
                output_lines.append(f"Reason: {details.get('reason', 'Unknown')}")
            else:
                message = details.get("message", "No additional information")
                output_lines.append(f"Message: {message}")

        elif sig_verify.get("status") == "error":
            output_lines.append(f"Error: {sig_verify.get('error_message', 'Unknown error')}")

    # Add reputation details if available
    if "reputation_check" in results:
        reputation = results["reputation_check"]
        output_lines.append("\n--- Reputation Check ---")
        output_lines.append(f"Status: {reputation.get('status', 'Unknown').upper()}")

        if reputation.get("known_bad"):
            output_lines.append("File is known malicious!")
            output_lines.append(f"Risk Score: {reputation.get('risk_score', 'Unknown')}")

        sources = reputation.get("sources", [])
        if sources:
            output_lines.append(f"Checked {len(sources)} reputation sources:")
            for source in sources:
                name = source.get("name", "Unknown")
                result = source.get("result", "Unknown")
                output_lines.append(f"  - {name}: {result}")

        elif reputation.get("status") == "error":
            output_lines.append(f"Error: {reputation.get('error_message', 'Unknown error')}")

    # Add execution time if available
    if "execution_time" in results:
        output_lines.append(f"\nExecution Time: {results['execution_time']:.2f} seconds")

    return "\n".join(output_lines)


def format_results_csv(results: Dict[str, Any]) -> str:
    """
    Format analysis results as CSV for easy parsing.

    Args:
        results: Analysis results dictionary

    Returns:
        CSV representation
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Basic file info
    writer.writerow(['File Path', results.get('file_path', 'Unknown')])
    writer.writerow(['Analysis Time', results.get('analysis_timestamp', datetime.now().isoformat())])
    writer.writerow([])

    # Summary
    writer.writerow(['Analysis Summary'])
    summary = results.get("analysis_summary", {})
    for key, value in summary.items():
        writer.writerow([key, value])
    writer.writerow([])

    # File hashes
    if "file_hashes" in results:
        writer.writerow(['File Hashes'])
        for alg, hash_val in results["file_hashes"].items():
            writer.writerow([alg, hash_val])
        writer.writerow([])

    # Malware signatures
    if "malware_signature_check" in results:
        check = results["malware_signature_check"]
        writer.writerow(['Malware Signature Check'])
        writer.writerow(['Status', check.get('status', 'Unknown')])

        matches = check.get("matches", [])
        if matches:
            writer.writerow([])
            writer.writerow(['Match #', 'Name', 'Family', 'Category', 'Source', 'Risk Level'])

            for i, match in enumerate(matches):
                writer.writerow([
                    i + 1,
                    match.get('name', 'Unknown'),
                    match.get('family', 'Unknown'),
                    match.get('category', 'Unknown'),
                    match.get('source', 'Unknown'),
                    match.get('risk_level', 'Unknown')
                ])
        writer.writerow([])

    # YARA scan
    if "yara_scan" in results:
        scan = results["yara_scan"]
        writer.writerow(['YARA Scan'])
        writer.writerow(['Status', scan.get('status', 'Unknown')])

        matches = scan.get("matches", [])
        if matches:
            writer.writerow([])
            writer.writerow(['Match #', 'Rule', 'Severity', 'Description', 'Tags'])

            for i, match in enumerate(matches):
                writer.writerow([
                    i + 1,
                    match.get('rule', 'Unknown'),
                    match.get('severity', 'Unknown'),
                    match.get('meta', {}).get('description', 'No description'),
                    ','.join(match.get('tags', []))
                ])
        writer.writerow([])

    # Code signature verification
    if "code_signature_verification" in results:
        verify = results["code_signature_verification"]
        writer.writerow(['Code Signature Verification'])
        writer.writerow(['Status', verify.get('status', 'Unknown')])

        details = verify.get("details", {})
        for key, value in details.items():
            writer.writerow([key, value])
        writer.writerow([])

    # Reputation check
    if "reputation_check" in results:
        rep = results["reputation_check"]
        writer.writerow(['Reputation Check'])
        writer.writerow(['Status', rep.get('status', 'Unknown')])
        writer.writerow(['Known Bad', rep.get('known_bad', False)])
        writer.writerow(['Risk Score', rep.get('risk_score', 'Unknown')])
        writer.writerow([])

        sources = rep.get("sources", [])
        if sources:
            writer.writerow(['Source', 'Result', 'Details'])
            for source in sources:
                writer.writerow([
                    source.get('name', 'Unknown'),
                    source.get('result', 'Unknown'),
                    source.get('details', '')
                ])
        writer.writerow([])

    # Add execution time if available
    if "execution_time" in results:
        writer.writerow(['Execution Time (sec)', f"{results['execution_time']:.2f}"])

    return output.getvalue()


def get_risk_score(analysis_results: Dict[str, Any]) -> Tuple[float, str]:
    """
    Calculate overall risk score from analysis results.

    Args:
        analysis_results: Analysis results dictionary

    Returns:
        Tuple of (risk_score, risk_level)
    """
    # Start with a neutral score
    risk_score = 0.0

    # Check malware signatures - highest impact
    malware_check = analysis_results.get("malware_signature_check", {})
    if malware_check.get("status") == "detected":
        # Direct malware match is high risk
        risk_score += 0.6

        # Add risk based on number of matches
        match_count = len(malware_check.get("matches", []))
        risk_score += min(0.2, match_count * 0.05)

    # Check YARA rules
    yara_scan = analysis_results.get("yara_scan", {})
    if yara_scan.get("status") == "detected":
        # YARA detections add significant risk
        risk_score += 0.4

        # Add risk based on number and severity of matches
        matches = yara_scan.get("matches", [])
        high_severity_matches = sum(1 for m in matches if m.get("severity", "").lower() in ("high", "critical"))
        risk_score += min(0.3, high_severity_matches * 0.1)

    # Check code signature
    sig_verify = analysis_results.get("code_signature_verification", {})
    sig_status = sig_verify.get("status", "")

    if sig_status == "invalid":
        # Invalid signature (tampered, revoked, etc.) is high risk
        risk_score += 0.4
    elif sig_status == "not_signed":
        # Unsigned executable is moderate risk
        file_info = sig_verify.get("file_info", {})
        if file_info.get("mime_type") in HIGH_RISK_MIME_TYPES:
            risk_score += 0.3
        else:
            risk_score += 0.1

    # Check reputation
    reputation = analysis_results.get("reputation_check", {})
    if reputation.get("known_bad", False):
        # Known bad reputation adds significant risk
        risk_score += 0.5
    elif reputation.get("status") == "completed" and reputation.get("risk_score"):
        # Add normalized risk from reputation service
        risk_score += float(reputation.get("risk_score", 0)) / 100.0

    # Cap risk at 1.0
    risk_score = min(1.0, risk_score)

    # Determine risk level based on score
    if risk_score >= 0.7:
        risk_level = "high"
    elif risk_score >= 0.4:
        risk_level = "medium"
    else:
        risk_level = "low"

    return risk_score, risk_level


def update_evidence_record(evidence_id: str, case_id: str, analyst: str, analysis_results: Dict[str, Any]) -> bool:
    """
    Update evidence tracking with analysis results if available.

    Args:
        evidence_id: Evidence identifier
        case_id: Case identifier
        analyst: Analyst name
        analysis_results: Analysis results dictionary

    Returns:
        True if successful, False otherwise
    """
    if not EVIDENCE_TRACKING_AVAILABLE or not evidence_id or not case_id:
        return False

    try:
        # Get existing evidence details
        evidence = get_evidence_details(case_id, evidence_id)
        if not evidence:
            logger.warning(f"Evidence record not found for ID: {evidence_id}")
            return False

        # Prepare analysis summary for evidence tracking
        summary = analysis_results.get("analysis_summary", {})
        risk_level = summary.get("overall_risk_level", "unknown")

        # Add or update analysis_results field in evidence metadata
        updates = {
            "signature_analysis": {
                "timestamp": datetime.now().isoformat(),
                "analyst": analyst,
                "risk_level": risk_level,
                "malware_status": summary.get("malware_db_status", "unknown"),
                "yara_status": summary.get("yara_scan_status", "unknown"),
                "signature_status": summary.get("code_signing_status", "unknown")
            }
        }

        # Add hash values if available
        if "file_hashes" in analysis_results:
            updates["signature_analysis"]["hashes"] = analysis_results["file_hashes"]

        # Update evidence record
        updated = update_evidence_details(case_id, evidence_id, updates, analyst)

        if updated:
            # Log analysis activity in chain of custody
            track_analysis(
                case_id=case_id,
                evidence_id=evidence_id,
                analyst=analyst,
                action="signature_analysis",
                purpose="Performed signature checks and malware analysis",
                details={
                    "tool": "signature_checker",
                    "risk_level": risk_level,
                    "findings": bool(
                        summary.get("malware_db_status") == "detected" or
                        summary.get("yara_scan_status") == "detected" or
                        summary.get("code_signing_status") == "invalid"
                    )
                }
            )

        return updated

    except Exception as e:
        logger.error(f"Error updating evidence record: {e}")
        return False


# --- Main Execution ---

def main() -> int:
    """
    Main function to parse arguments and orchestrate signature checks.

    Returns:
        Exit code:
        0 - Success with no detections
        1 - Error during analysis
        2 - Success with security detections
    """
    parser = argparse.ArgumentParser(
        description="Forensic Signature Checker: Verify file signatures, check malware DB, and run YARA scans.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check file against known malware signatures
  signature_checker.py --file suspicious_file.exe --check-signatures

  # Scan file with YARA rules
  signature_checker.py --file suspicious_script.js --yara-rules ./rules/suspicious/

  # Verify digital signature on executable
  signature_checker.py --file application.exe --verify-signature

  # Perform all checks and save results to JSON file
  signature_checker.py --file unknown_file.bin --full-analysis --output results.json

  # Forensic case tracking
  signature_checker.py --file evidence.exe --full-analysis --case-id CASE-2023-42 --evidence-id EV-123 --analyst "John Smith"
"""
    )

    # Required file argument
    parser.add_argument("--file", required=True, help="Path to the file to analyze.")

    # Analysis options
    parser.add_argument("--check-signatures", action="store_true",
                        help="Check file hash against known malware databases.")
    parser.add_argument("--yara-rules", help="Path to YARA rules file or directory. If not specified, uses default rules.")
    parser.add_argument("--verify-signature", action="store_true",
                        help="Verify digital code signing signature (if applicable).")
    parser.add_argument("--check-reputation", action="store_true",
                        help="Check file reputation with threat intelligence (if available).")
    parser.add_argument("--full-analysis", action="store_true",
                        help="Perform all available analysis types.")

    # Output options
    parser.add_argument("--output", help="Path to save the analysis report.")
    parser.add_argument("--output-format", choices=SUPPORTED_OUTPUT_FORMATS, default=DEFAULT_OUTPUT_FORMAT,
                        help="Format for the output report.")
    parser.add_argument("--include-strings", action="store_true",
                        help="Include matched strings in the output (can increase report size).")

    # Forensic context
    parser.add_argument("--case-id", help="Case ID for forensic logging and evidence tracking.")
    parser.add_argument("--analyst", help="Analyst name for forensic logging.")
    parser.add_argument("--evidence-id", help="Evidence ID for tracking in the evidence management system.")

    # Configuration options
    parser.add_argument("--db-path", help="Path to the signature database directory.")
    parser.add_argument("--hash-algorithms", default="md5,sha1,sha256",
                        help="Comma-separated list of hash algorithms to use.")

    # Verbosity and behavior
    parser.add_argument("--verbose", "-v", action="count", default=0,
                        help="Increase verbosity (can be used multiple times, e.g. -vv).")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress all output except errors and analysis results.")
    parser.add_argument("--exit-on-detection", action="store_true",
                        help="Exit with code 2 if any threats are detected.")

    args = parser.parse_args()

    # Set logging level based on verbosity
    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose == 0:
        logger.setLevel(logging.INFO)
    elif args.verbose == 1:
        logger.setLevel(logging.DEBUG)
    else:  # args.verbose >= 2
        logger.setLevel(logging.DEBUG)
        # Enable more verbose error reporting
        logging.getLogger().setLevel(logging.DEBUG)

    # Prepare forensic operation logging context
    operation_details = {
        "tool": "signature_checker",
        "file_path": args.file,
        "checks_requested": {
            "malware_db": args.check_signatures or args.full_analysis,
            "yara": bool(args.yara_rules) or args.full_analysis,
            "code_signing": args.verify_signature or args.full_analysis,
            "reputation": args.check_reputation or args.full_analysis
        },
        "output_path": args.output,
        "output_format": args.output_format,
        "case_id": args.case_id,
        "analyst": args.analyst,
        "evidence_id": args.evidence_id
    }

    # Start operation logging
    log_forensic_operation("signature_check_start", True, operation_details, level=logging.INFO)

    # Validate input file path
    is_valid, validation_msg = validate_path(args.file, must_be_file=True, check_read=True)
    if not is_valid:
        logger.error(f"Input file validation failed: {validation_msg}")
        operation_details["error"] = validation_msg
        log_forensic_operation("signature_check_error", False, operation_details, level=logging.ERROR)
        return 1

    # Prepare analysis results structure
    analysis_results: Dict[str, Any] = {
        "file_path": args.file,
        "analysis_timestamp": datetime.now().isoformat(),
        "analysis_summary": {},
    }

    # Add file metadata
    try:
        file_stat = os.stat(args.file)
        analysis_results["file_metadata"] = {
            "size_bytes": file_stat.st_size,
            "last_modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat()
        }
    except (OSError, IOError) as e:
        logger.warning(f"Could not get file metadata: {e}")

    # Parse hash algorithms
    hash_algorithms = [alg.strip().lower() for alg in args.hash_algorithms.split(',')]

    # Calculate file hashes for reporting and verification
    try:
        file_hashes = calculate_multiple_hashes(args.file, hash_algorithms)
        analysis_results["file_hashes"] = file_hashes
    except Exception as e:
        logger.error(f"Error calculating file hashes: {e}")
        file_hashes = {}
        analysis_results["file_hashes"] = {}
        analysis_results["errors"] = analysis_results.get("errors", []) + [f"Hash calculation error: {e}"]

    # Initialize common components if available
    db_manager = None
    yara_scanner = None

    # Determine signature database path
    db_path = args.db_path or DEFAULT_SIGNATURE_DB_PATH

    if SIGNATURE_DB_AVAILABLE:
        try:
            logger.debug(f"Initializing SignatureDBManager with root: {db_path}")
            db_manager = SignatureDBManager(db_root=db_path)
        except Exception as e:
            logger.error(f"Failed to initialize SignatureDBManager: {e}", exc_info=True)
            analysis_results["errors"] = analysis_results.get("errors", []) + [f"SignatureDB initialization error: {e}"]

    if YARA_SCANNER_AVAILABLE:
        try:
            logger.debug("Initializing YaraScanner.")
            yara_scanner = YaraScanner()
        except Exception as e:
            logger.error(f"Failed to initialize YaraScanner: {e}", exc_info=True)
            analysis_results["errors"] = analysis_results.get("errors", []) + [f"YARA scanner initialization error: {e}"]

    # Perform requested analysis
    run_all = args.full_analysis

    # --- Check malware signatures ---
    if args.check_signatures or run_all:
        logger.info(f"Checking malware signatures for: {args.file}")
        analysis_results["malware_signature_check"] = check_malware_signatures(args.file, db_manager)

    # --- Run YARA scan ---
    if args.yara_rules or run_all:
        rules_path = args.yara_rules or DEFAULT_YARA_RULES_PATH
        logger.info(f"Scanning with YARA rules from: {rules_path}")
        analysis_results["yara_scan"] = scan_with_yara(args.file, yara_scanner, rules_path)

    # --- Verify code signature ---
    if args.verify_signature or run_all:
        logger.info(f"Verifying code signature for: {args.file}")
        analysis_results["code_signature_verification"] = verify_code_signature(args.file, db_manager)

    # --- Check reputation ---
    if args.check_reputation or run_all:
        logger.info(f"Checking reputation for: {args.file}")
        analysis_results["reputation_check"] = check_reputation(args.file, file_hashes)

    # --- Generate Summary ---
    summary = {}

    # Collect status information from each check
    if "malware_signature_check" in analysis_results:
        summary["malware_db_status"] = analysis_results["malware_signature_check"]["status"]
    if "yara_scan" in analysis_results:
        summary["yara_scan_status"] = analysis_results["yara_scan"]["status"]
    if "code_signature_verification" in analysis_results:
        summary["code_signing_status"] = analysis_results["code_signature_verification"]["status"]
    if "reputation_check" in analysis_results:
        summary["reputation_status"] = analysis_results["reputation_check"]["status"]

    # Calculate overall risk score and level
    if analysis_results:
        risk_score, risk_level = get_risk_score(analysis_results)
        summary["overall_risk_score"] = risk_score
        summary["overall_risk_level"] = risk_level

    analysis_results["analysis_summary"] = summary

    # Update evidence tracking if applicable
    if EVIDENCE_TRACKING_AVAILABLE and args.evidence_id and args.case_id:
        logger.info(f"Updating evidence record: {args.evidence_id}")
        update_evidence_record(args.evidence_id, args.case_id, args.analyst or "unknown", analysis_results)

    # --- Save or Print Results ---
    report_saved = False
    if args.output:
        logger.info(f"Saving analysis results to: {args.output} in {args.output_format} format.")
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(args.output))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Use the save function to save the report
        report_saved = save_analysis_report(analysis_results, args.output, format=args.output_format)

        if not report_saved:
            logger.error(f"Failed to save report to {args.output}")
            # Fall back to printing
            if args.output_format == 'json':
                print(json.dumps(analysis_results, indent=4, default=str))
            elif args.output_format == 'csv':
                print(format_results_csv(analysis_results))
            else:
                print(format_results_text(analysis_results))
    else:
        # Print to stdout based on format
        if args.output_format == 'json':
            print(json.dumps(analysis_results, indent=4, default=str))
        elif args.output_format == 'csv':
            print(format_results_csv(analysis_results))
        elif args.output_format == 'yaml':
            try:
                print(yaml.dump(analysis_results, default_flow_style=False))
            except ImportError:
                logger.error("PyYAML not installed, falling back to text format.")
                print(format_results_text(analysis_results))
        else:
            print(format_results_text(analysis_results))

    # Final forensic log with summary
    operation_details["summary"] = summary
    log_forensic_operation("signature_check_complete", True, operation_details, level=logging.INFO)

    # Determine exit code
    exit_code = 0

    # Check for any analysis errors
    if any(v.get("status") == "error" for k, v in analysis_results.items()
           if isinstance(v, dict) and 'status' in v):
        exit_code = 1
    # Check for detections if requested
    elif args.exit_on_detection and any(
        v.get("status") == "detected" for k, v in analysis_results.items()
        if isinstance(v, dict) and 'status' in v
    ):
        exit_code = 2
        logger.warning("Security threats detected in the analyzed file")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
