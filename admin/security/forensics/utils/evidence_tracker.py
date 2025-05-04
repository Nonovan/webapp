"""
Evidence Management Utilities for the Forensic Analysis Toolkit.

This module provides functions for registering, tracking, and managing digital
evidence throughout the forensic lifecycle. It ensures proper documentation of
evidence handling, maintains chain of custody records, and facilitates
consistent metadata management.

Core functionalities include:
- Registering new evidence items with unique identifiers and metadata
- Tracking access and handling actions for each evidence item
- Retrieving evidence details and chain of custody history
- Storing evidence metadata securely and persistently
- Verifying evidence integrity through hash validation
- Managing evidence relationships and transfers
"""

import json
import os
import uuid
import hashlib
import logging
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Tuple

# Attempt to import forensic-specific logging and crypto utilities
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation
except ImportError:
    logging.warning("Forensic logging utility not found. Using standard logger.")
    def log_forensic_operation(operation: str, success: bool, details: Optional[Dict] = None):
        level = logging.INFO if success else logging.ERROR
        log_msg = f"Forensic Operation: {operation}, Success: {success}"
        if details:
            log_msg += f", Details: {details}"
        logging.log(level, log_msg)

try:
    from admin.security.forensics.utils.crypto import calculate_file_hash, verify_file_hash
    CRYPTO_VERIFICATION_AVAILABLE = True
except ImportError:
    logging.warning("Forensic crypto utility not found. Hash calculation unavailable.")
    CRYPTO_VERIFICATION_AVAILABLE = False
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        logging.error("calculate_file_hash function is unavailable.")
        return None
    def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        logging.error("verify_file_hash function is unavailable.")
        return False

# Attempt to import additional utilities
try:
    from admin.security.forensics.utils.validation_utils import validate_path
    PATH_VALIDATION_AVAILABLE = True
except ImportError:
    logging.warning("Validation utilities not found. Using basic validation.")
    PATH_VALIDATION_AVAILABLE = False
    def validate_path(path_str: str, **kwargs) -> Tuple[bool, str]:
        return True, "Path validation unavailable"

# Attempt to import constants
try:
    from admin.security.forensics.utils.forensic_constants import (
        EVIDENCE_METADATA_DIR, DEFAULT_HASH_ALGORITHM, CHAIN_OF_CUSTODY_FILENAME,
        DEFAULT_SECURE_FILE_PERMS
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    DEFAULT_EVIDENCE_METADATA_DIR = "/secure/forensics/metadata" # Example default
    DEFAULT_EVIDENCE_METADATA_DIR = "/secure/forensics/metadata"  # Example default
    FALLBACK_HASH_ALGORITHM = "sha256"
    FALLBACK_CHAIN_OF_CUSTODY_FILENAME = "chain_of_custody.jsonl" # JSON Lines format
    FALLBACK_SECURE_FILE_PERMS = 0o600 # Read/write for owner only

logger = logging.getLogger(__name__)

# Ensure metadata directory exists
try:
    if not os.path.exists(EVIDENCE_METADATA_DIR):
        os.makedirs(EVIDENCE_METADATA_DIR, mode=0o700, exist_ok=True)
    # Set permissions securely if directory exists
    else:
        os.chmod(EVIDENCE_METADATA_DIR, 0o700)
except (OSError, PermissionError) as e:
    logger.critical(f"Failed to create or secure evidence metadata directory: {e}")
    # Continue anyway - might be valid in some testing scenarios

# --- Basic Path and Storage Functions ---

def _get_case_metadata_dir(case_id: str) -> str:
    """
    Constructs the path to the metadata directory for a specific case.

    Args:
        case_id: The case identifier.

    Returns:
        The path to the case's metadata directory.

    Raises:
        ValueError: If the case ID is invalid.
    """
    safe_case_id = "".join(c for c in case_id if c.isalnum() or c in ('-', '_')).rstrip()
    if not safe_case_id:
        raise ValueError("Invalid case ID provided.")
    return os.path.join(EVIDENCE_METADATA_DIR, safe_case_id)

def _get_evidence_metadata_path(case_id: str, evidence_id: str) -> str:
    """
    Constructs the path to the metadata file for a specific evidence item.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.

    Returns:
        The path to the evidence metadata file.
    """
    case_dir = _get_case_metadata_dir(case_id)
    return os.path.join(case_dir, f"{evidence_id}.json")

def _get_chain_of_custody_path(case_id: str) -> str:
    """
    Constructs the path to the chain of custody log file for a specific case.

    Args:
        case_id: The case identifier.

    Returns:
        The path to the chain of custody log file.
    """
    case_dir = _get_case_metadata_dir(case_id)
    return os.path.join(case_dir, CHAIN_OF_CUSTODY_FILENAME)

def _generate_evidence_id() -> str:
    """
    Generates a unique identifier for an evidence item.

    Returns:
        A UUID string as the evidence identifier.
    """
    return str(uuid.uuid4())

def _ensure_case_directory(case_id: str) -> bool:
    """
    Ensures the case metadata directory exists and has proper permissions.

    Args:
        case_id: The case identifier.

    Returns:
        True if the directory exists or was created successfully, False otherwise.
    """
    try:
        case_dir = _get_case_metadata_dir(case_id)
        if not os.path.exists(case_dir):
            os.makedirs(case_dir, mode=0o700, exist_ok=True)
        else:
            os.chmod(case_dir, 0o700)  # Ensure proper permissions
        return True
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to create or secure case directory for {case_id}: {e}")
        return False

def _secure_write_json(data: Dict[str, Any], file_path: str) -> bool:
    """
    Securely writes JSON data to a file with proper permissions.

    Args:
        data: The data to write.
        file_path: The path to write to.

    Returns:
        True if successful, False otherwise.
    """
    tmp_path = f"{file_path}.tmp"
    try:
        # Write to temp file first
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        # Set secure permissions
        os.chmod(tmp_path, DEFAULT_SECURE_FILE_PERMS)

        # Atomically replace the original file
        if os.path.exists(file_path):
            os.unlink(file_path)  # Remove existing file if present
        os.rename(tmp_path, file_path)
        return True

    except (OSError, PermissionError, ValueError) as e:
        logger.error(f"Failed to securely write to {file_path}: {e}")
        # Clean up temp file if it exists
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return False

# --- Main API Functions ---

def register_evidence(
    case_id: str,
    evidence_description: str,
    evidence_type: str,
    source_identifier: str,
    acquisition_method: str,
    acquisition_tool: str,
    analyst: str,
    file_path: Optional[str] = None,
    acquisition_timestamp: Optional[datetime] = None,
    initial_hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
    classification: str = "Unclassified",
    retention_period: Optional[str] = None
) -> Optional[str]:
    """
    Registers a new piece of evidence and creates its initial metadata record.

    Args:
        case_id: The identifier for the case this evidence belongs to.
        evidence_description: A brief description of the evidence.
        evidence_type: The type of evidence (e.g., 'disk_image', 'memory_dump', 'log_file').
        source_identifier: Identifier of the source system/device.
        acquisition_method: Method used for acquisition (e.g., 'live_acquisition', 'dd').
        acquisition_tool: Tool used for acquisition (e.g., 'FTK Imager', 'dd', 'custom_script').
        analyst: The analyst performing the registration.
        file_path: Optional path to the evidence file for initial hashing.
        acquisition_timestamp: Optional timestamp of acquisition (defaults to now).
        initial_hash_algorithm: Algorithm for the initial hash (defaults to SHA256).
        classification: Security classification of the evidence.
        retention_period: How long the evidence should be retained.

    Returns:
        The unique evidence ID if registration is successful, None otherwise.
    """
    # Validate inputs
    if not case_id or not evidence_type or not analyst:
        logger.error("Missing required fields for evidence registration")
        log_forensic_operation("register_evidence", False, {"error": "Missing required fields"})
        return None

    if file_path and PATH_VALIDATION_AVAILABLE:
        is_valid, message = validate_path(file_path, check_exists=True)
        if not is_valid:
            logger.error(f"Invalid file path: {message}")
            log_forensic_operation("register_evidence", False, {"error": f"Invalid file path: {message}"})
            return None

    if file_path and not os.path.exists(file_path):
        logger.error(f"Evidence file does not exist: {file_path}")
        log_forensic_operation("register_evidence", False, {"error": f"File does not exist: {file_path}"})
        return None

    # Create evidence ID and set timestamps
    evidence_id = _generate_evidence_id()
    timestamp = acquisition_timestamp or datetime.now(timezone.utc)
    timestamp_iso = timestamp.isoformat()

    # Try to calculate hash if file path is provided
    initial_hash = None
    file_size = None
    if file_path:
        try:
            initial_hash = calculate_file_hash(file_path, initial_hash_algorithm)
            if initial_hash is None:
                logger.warning(f"Failed to calculate initial hash for {file_path}")
                # Proceeding without hash, but log it
            else:
                # Get file size for additional metadata
                file_size = os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"Error calculating initial hash for {file_path}: {e}")
            # Proceeding without hash

    # Create the metadata record
    metadata = {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "description": evidence_description,
        "evidence_type": evidence_type,
        "source_identifier": source_identifier,
        "acquisition_method": acquisition_method,
        "acquisition_tool": acquisition_tool,
        "acquisition_analyst": analyst,
        "acquisition_timestamp": timestamp_iso,
        "registration_timestamp": datetime.now(timezone.utc).isoformat(),
        "initial_hashes": {initial_hash_algorithm: initial_hash} if initial_hash else {},
        "original_file_path": file_path,  # Store original path if provided
        "current_location": file_path,  # Assume initial location is the file path
        "classification": classification,
        "retention_period": retention_period,
        "tags": [],
        "related_evidence": [],
        "integrity_verified": bool(initial_hash),  # Mark as verified if we have a hash
        "state": "active"
    }

    # Add file size if available
    if file_size is not None:
        metadata["file_size_bytes"] = file_size

    # Ensure directory exists and save metadata
    if not _ensure_case_directory(case_id):
        log_forensic_operation("register_evidence", False, {"case_id": case_id, "error": "Failed to create/secure case directory"})
        return None

    try:
        metadata_path = _get_evidence_metadata_path(case_id, evidence_id)

        # Write metadata securely
        if not _secure_write_json(metadata, metadata_path):
            raise OSError(f"Failed to securely write metadata to {metadata_path}")

        # Log initial chain of custody entry
        track_access(
            case_id=case_id,
            evidence_id=evidence_id,
            analyst=analyst,
            action="register_and_acquire",
            purpose="Initial evidence registration and acquisition",
            timestamp=timestamp,
            details={
                "acquisition_method": acquisition_method,
                "acquisition_tool": acquisition_tool,
                "initial_hash": initial_hash,
                "hash_algorithm": initial_hash_algorithm,
                "classification": classification
            }
        )

        log_forensic_operation("register_evidence", True, {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "evidence_type": evidence_type,
            "has_hash": initial_hash is not None
        })
        return evidence_id

    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Failed to register evidence for case {case_id}: {e}")
        log_forensic_operation("register_evidence", False, {"case_id": case_id, "error": str(e)})
        return None

def track_access(
    case_id: str,
    evidence_id: str,
    analyst: str,
    action: str,
    purpose: str,
    timestamp: Optional[datetime] = None,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Tracks an access or handling action for a piece of evidence in the chain of custody log.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.
        analyst: The analyst performing the action.
        action: The action performed (e.g., 'access', 'copy', 'analyze', 'transfer', 'verify_hash').
        purpose: The reason for the action.
        timestamp: Optional timestamp of the action (defaults to now).
        details: Optional dictionary with additional details about the action.

    Returns:
        True if the tracking entry was successfully logged, False otherwise.
    """
    if not case_id or not evidence_id or not analyst or not action:
        logger.error("Missing required fields for tracking evidence access")
        return False

    log_entry = {
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "evidence_id": evidence_id,
        "case_id": case_id,
        "analyst": analyst,
        "action": action,
        "purpose": purpose,
        "details": details or {}
    }

    try:
        if not _ensure_case_directory(case_id):
            raise OSError(f"Failed to ensure case directory for {case_id}")

        coc_path = _get_chain_of_custody_path(case_id)

        # Append to JSON Lines file with secure permissions
        with open(coc_path, 'a', encoding='utf-8') as f:
            json.dump(log_entry, f)
            f.write('\n')

        # Ensure file has correct permissions
        os.chmod(coc_path, DEFAULT_SECURE_FILE_PERMS)

        log_forensic_operation("track_evidence_access", True, {
            "evidence_id": evidence_id,
            "action": action,
            "analyst": analyst
        })
        return True
    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Failed to track access for evidence {evidence_id}: {e}")
        log_forensic_operation("track_evidence_access", False, {"evidence_id": evidence_id, "error": str(e)})
        return False

def track_analysis(
    case_id: str,
    evidence_id: str,
    analyst: str,
    action: str,
    purpose: str,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None
) -> bool:
    """
    Tracks an analysis operation performed on evidence in the chain of custody log.

    This function is similar to track_access but specifically designed for
    recording analysis activities and findings for forensic evidence.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.
        analyst: The analyst performing the analysis.
        action: The type of analysis performed (e.g., 'static_analysis', 'memory_analysis').
        purpose: The reason for the analysis or investigation objective.
        details: Optional dictionary with additional details about the analysis findings.
        timestamp: Optional timestamp of when the analysis was performed (defaults to now).

    Returns:
        True if the tracking entry was successfully logged, False otherwise.
    """
    if not case_id or not evidence_id or not analyst or not action:
        logger.error("Missing required fields for tracking evidence analysis")
        return False

    log_entry = {
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "evidence_id": evidence_id,
        "case_id": case_id,
        "analyst": analyst,
        "action": action,
        "purpose": purpose,
        "analysis_type": "forensic_analysis",
        "details": details or {}
    }

    try:
        if not _ensure_case_directory(case_id):
            raise OSError(f"Failed to ensure case directory for {case_id}")

        coc_path = _get_chain_of_custody_path(case_id)

        # Append to JSON Lines file with secure permissions
        with open(coc_path, 'a', encoding='utf-8') as f:
            json.dump(log_entry, f)
            f.write('\n')

        # Ensure file has correct permissions
        os.chmod(coc_path, DEFAULT_SECURE_FILE_PERMS)

        log_forensic_operation("track_evidence_analysis", True, {
            "evidence_id": evidence_id,
            "action": action,
            "analyst": analyst
        })
        return True
    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Failed to track analysis for evidence {evidence_id}: {e}")
        log_forensic_operation("track_evidence_analysis", False, {"evidence_id": evidence_id, "error": str(e)})
        return False


def register_analysis_result(
    case_id: str,
    evidence_id: str,
    analyst: str,
    tool: str,
    result_type: str,
    findings: Dict[str, Any],
    risk_level: str = "unknown"
) -> bool:
    """
    Registers analysis results for an evidence item and updates its metadata.

    Args:
        case_id: The case identifier.
        evidence_id: The evidence identifier.
        analyst: The analyst who performed the analysis.
        tool: The tool used for analysis.
        result_type: The type of analysis performed.
        findings: Dictionary containing analysis findings.
        risk_level: Risk level determined from analysis (e.g., "low", "medium", "high", "critical").

    Returns:
        True if registration was successful, False otherwise.
    """
    if not case_id or not evidence_id or not analyst:
        logger.error("Missing required fields for registering analysis results")
        log_forensic_operation("register_analysis_result", False,
                              {"error": "Missing required fields"})
        return False

    try:
        # Get current evidence details
        evidence = get_evidence_details(case_id, evidence_id)
        if not evidence:
            logger.error(f"Cannot register analysis results: evidence {evidence_id} not found")
            log_forensic_operation("register_analysis_result", False,
                                  {"evidence_id": evidence_id, "error": "Evidence not found"})
            return False

        # Prepare analysis entry
        analysis_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst": analyst,
            "tool": tool,
            "result_type": result_type,
            "risk_level": risk_level,
            "findings": findings
        }

        # Update evidence metadata with analysis results
        analysis_history = evidence.get("analysis_history", [])
        analysis_history.append(analysis_entry)

        updates = {
            "analysis_history": analysis_history,
            "last_analysis": {
                "timestamp": analysis_entry["timestamp"],
                "tool": tool,
                "result_type": result_type,
                "risk_level": risk_level,
                "analyst": analyst
            }
        }

        # If this is a high-risk finding, tag it
        if risk_level in ["high", "critical"]:
            tags = evidence.get("tags", [])
            if f"risk:{risk_level}" not in tags:
                tags.append(f"risk:{risk_level}")
                updates["tags"] = tags

        # Update the evidence record
        success = update_evidence_details(
            case_id=case_id,
            evidence_id=evidence_id,
            updates=updates,
            analyst=analyst
        )

        if success:
            # Also track this as an analysis activity
            track_analysis(
                case_id=case_id,
                evidence_id=evidence_id,
                analyst=analyst,
                action=f"{tool}_analysis",
                purpose=f"Performed {result_type} analysis",
                details={
                    "tool": tool,
                    "result_type": result_type,
                    "risk_level": risk_level,
                    "findings_summary": {k: v for k, v in findings.items()
                                         if k in ["risk_level", "risk_score", "suspicious_processes",
                                                 "suspicious_commands", "risk_factors"]}
                }
            )

        log_forensic_operation("register_analysis_result", success, {
            "evidence_id": evidence_id,
            "tool": tool,
            "result_type": result_type,
            "risk_level": risk_level
        })
        return success

    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Failed to register analysis results for evidence {evidence_id}: {e}")
        log_forensic_operation("register_analysis_result", False,
                              {"evidence_id": evidence_id, "error": str(e)})
        return False


def get_evidence_details(case_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves the metadata for a specific evidence item.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.

    Returns:
        A dictionary containing the evidence metadata, or None if not found or error occurs.
    """
    if not case_id or not evidence_id:
        logger.error("Missing required fields to retrieve evidence details")
        return None

    try:
        metadata_path = _get_evidence_metadata_path(case_id, evidence_id)
        if not os.path.exists(metadata_path):
            logger.warning(f"Metadata file not found for evidence {evidence_id} in case {case_id}")
            return None

        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        log_forensic_operation("get_evidence_details", True, {"evidence_id": evidence_id})
        return metadata
    except (OSError, ValueError, json.JSONDecodeError) as e:
        logger.error(f"Failed to retrieve details for evidence {evidence_id}: {e}")
        log_forensic_operation("get_evidence_details", False, {"evidence_id": evidence_id, "error": str(e)})
        return None

def update_evidence_details(case_id: str, evidence_id: str, updates: Dict[str, Any], analyst: str) -> bool:
    """
    Updates specific fields in the evidence metadata.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.
        updates: A dictionary of fields to update (e.g., {"current_location": "/new/path", "tags": ["important"]}).
        analyst: The analyst performing the update.

    Returns:
        True if the update was successful, False otherwise.
    """
    if not case_id or not evidence_id or not updates or not analyst:
        logger.error("Missing required fields for updating evidence details")
        return False

    metadata = get_evidence_details(case_id, evidence_id)
    if not metadata:
        logger.error(f"Cannot update evidence {evidence_id}: metadata not found")
        return False

    original_metadata = metadata.copy() # For logging changes
    changed_fields = {}

    # Apply updates, ensuring critical fields are not overwritten accidentally
    protected_fields = {
        "evidence_id", "case_id", "acquisition_timestamp",
        "registration_timestamp", "acquisition_analyst",
        "initial_hashes"
    }

    for key, value in updates.items():
        if key not in protected_fields:
            if metadata.get(key) != value:
                changed_fields[key] = {"old": metadata.get(key), "new": value}
            metadata[key] = value
        else:
            logger.warning(f"Attempted to update protected field '{key}' for evidence {evidence_id}. Skipping.")

    if not changed_fields:
        logger.info(f"No changes detected for evidence {evidence_id}. Update skipped.")
        return True # No changes needed, considered successful

    metadata["last_updated_timestamp"] = datetime.now(timezone.utc).isoformat()
    metadata["last_updated_by"] = analyst

    try:
        metadata_path = _get_evidence_metadata_path(case_id, evidence_id)

        # Write updated metadata securely
        if not _secure_write_json(metadata, metadata_path):
            raise OSError(f"Failed to securely write metadata to {metadata_path}")

        # Log the update in the chain of custody
        track_access(
            case_id=case_id,
            evidence_id=evidence_id,
            analyst=analyst,
            action="update_metadata",
            purpose="Updating evidence details",
            details={"updated_fields": changed_fields}
        )
        log_forensic_operation("update_evidence_details", True, {
            "evidence_id": evidence_id,
            "updated_fields": list(changed_fields.keys())
        })
        return True
    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Failed to update metadata for evidence {evidence_id}: {e}")
        log_forensic_operation("update_evidence_details", False, {"evidence_id": evidence_id, "error": str(e)})
        return False

def get_chain_of_custody(case_id: str, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves the chain of custody log for a case, optionally filtered by evidence ID.

    Args:
        case_id: The case identifier.
        evidence_id: Optional. If provided, filters the log for this specific evidence item.

    Returns:
        A list of chain of custody log entries (dictionaries). Returns empty list on error or if not found.
    """
    if not case_id:
        logger.error("Case ID is required to retrieve chain of custody")
        return []

    entries = []
    try:
        coc_path = _get_chain_of_custody_path(case_id)
        if not os.path.exists(coc_path):
            logger.info(f"Chain of custody file not found for case {case_id}")
            return []

        with open(coc_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    entry = json.loads(line)
                    if evidence_id is None or entry.get("evidence_id") == evidence_id:
                        entries.append(entry)
                except json.JSONDecodeError:
                    logger.warning(f"Skipping invalid JSON at line {line_num} in {coc_path}: {line}")

        log_forensic_operation("get_chain_of_custody", True, {"case_id": case_id, "evidence_id": evidence_id})
        # Sort by timestamp just in case entries were appended out of order
        entries.sort(key=lambda x: x.get("timestamp", ""))
        return entries
    except (OSError, ValueError) as e:
        logger.error(f"Failed to retrieve chain of custody for case {case_id}: {e}")
        log_forensic_operation("get_chain_of_custody", False, {"case_id": case_id, "error": str(e)})
        return []

# --- New Enhanced Functions ---

def verify_evidence_integrity(
    case_id: str,
    evidence_id: str,
    analyst: str,
    file_path: Optional[str] = None
) -> bool:
    """
    Verifies the integrity of evidence by comparing its current hash with the original hash.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.
        analyst: The analyst performing the verification.
        file_path: Optional path to the evidence file. If None, uses the current_location from metadata.

    Returns:
        True if integrity is verified, False otherwise.
    """
    if not CRYPTO_VERIFICATION_AVAILABLE:
        logger.warning("Crypto verification functions unavailable. Cannot verify evidence integrity.")
        log_forensic_operation("verify_evidence_integrity", False, {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "error": "Crypto verification unavailable"
        })
        return False

    metadata = get_evidence_details(case_id, evidence_id)
    if not metadata:
        logger.error(f"Cannot verify evidence {evidence_id}: metadata not found")
        return False

    # Get initial hash information
    initial_hashes = metadata.get("initial_hashes", {})
    if not initial_hashes:
        logger.error(f"Evidence {evidence_id} has no initial hash for verification")
        log_forensic_operation("verify_evidence_integrity", False, {
            "evidence_id": evidence_id,
            "error": "No initial hash available"
        })
        return False

    # Use first available hash algorithm
    algorithm = next(iter(initial_hashes.keys()), None)
    initial_hash = initial_hashes.get(algorithm)

    if not algorithm or not initial_hash:
        logger.error(f"Invalid hash information for evidence {evidence_id}")
        return False

    # Determine file path to verify
    verify_path = file_path or metadata.get("current_location")
    if not verify_path:
        logger.error(f"No file path available for verification of evidence {evidence_id}")
        return False

    if not os.path.exists(verify_path):
        logger.error(f"Evidence file not found for verification: {verify_path}")
        log_forensic_operation("verify_evidence_integrity", False, {
            "evidence_id": evidence_id,
            "error": f"File not found: {verify_path}"
        })
        return False

    # Verify the hash
    start_time = datetime.now(timezone.utc)
    is_verified = verify_file_hash(verify_path, initial_hash, algorithm)
    end_time = datetime.now(timezone.utc)

    # Log the verification result
    verification_result = {
        "verified": is_verified,
        "algorithm": algorithm,
        "file_path": verify_path,
        "verification_time": start_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds()
    }

    track_access(
        case_id=case_id,
        evidence_id=evidence_id,
        analyst=analyst,
        action="verify_integrity",
        purpose="Verify evidence file integrity",
        timestamp=end_time,
        details=verification_result
    )

    # Update evidence metadata with verification status
    update_evidence_details(
        case_id=case_id,
        evidence_id=evidence_id,
        analyst=analyst,
        updates={
            "integrity_verified": is_verified,
            "last_verification": {
                "timestamp": end_time.isoformat(),
                "result": is_verified,
                "verified_by": analyst
            }
        }
    )

    log_forensic_operation("verify_evidence_integrity", is_verified, {
        "evidence_id": evidence_id,
        "algorithm": algorithm,
        "path": verify_path
    })

    return is_verified

def transfer_evidence(
    case_id: str,
    evidence_id: str,
    analyst: str,
    new_location: str,
    transfer_reason: str,
    copy_method: str = "secure_copy",
    verify_after_transfer: bool = True
) -> bool:
    """
    Records the physical or logical transfer of evidence to a new location.

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.
        analyst: The analyst performing the transfer.
        new_location: The new location of the evidence file.
        transfer_reason: The reason for the transfer.
        copy_method: The method used to copy the evidence.
        verify_after_transfer: Whether to verify the evidence integrity after transfer.

    Returns:
        True if the transfer was successfully recorded, False otherwise.
    """
    metadata = get_evidence_details(case_id, evidence_id)
    if not metadata:
        logger.error(f"Cannot transfer evidence {evidence_id}: metadata not found")
        return False

    # Record the previous location
    previous_location = metadata.get("current_location")

    if previous_location == new_location:
        logger.warning(f"Evidence {evidence_id} is already at location {new_location}")
        return False

    # Track the transfer in the chain of custody
    transfer_tracked = track_access(
        case_id=case_id,
        evidence_id=evidence_id,
        analyst=analyst,
        action="transfer",
        purpose=transfer_reason,
        details={
            "from_location": previous_location,
            "to_location": new_location,
            "copy_method": copy_method
        }
    )

    if not transfer_tracked:
        logger.error(f"Failed to record transfer of evidence {evidence_id}")
        return False

    # Update the evidence location in metadata
    update_success = update_evidence_details(
        case_id=case_id,
        evidence_id=evidence_id,
        updates={"current_location": new_location},
        analyst=analyst
    )

    if not update_success:
        logger.error(f"Failed to update location for evidence {evidence_id}")
        return False

    # Verify integrity if requested and possible
    if verify_after_transfer and CRYPTO_VERIFICATION_AVAILABLE:
        verification_result = verify_evidence_integrity(
            case_id=case_id,
            evidence_id=evidence_id,
            analyst=analyst,
            file_path=new_location
        )

        if not verification_result:
            logger.error(f"Integrity verification failed after transfer of evidence {evidence_id}")
            # Still return True as the transfer was recorded, but it failed verification

    log_forensic_operation("transfer_evidence", True, {
        "evidence_id": evidence_id,
        "from": previous_location,
        "to": new_location
    })

    return True

def link_related_evidence(
    case_id: str,
    primary_evidence_id: str,
    related_evidence_id: str,
    analyst: str,
    relationship_type: str,
    description: Optional[str] = None
) -> bool:
    """
    Establishes a relationship between two evidence items.

    Args:
        case_id: The case identifier.
        primary_evidence_id: The primary evidence item ID.
        related_evidence_id: The related evidence item ID.
        analyst: The analyst establishing the relationship.
        relationship_type: The type of relationship (e.g., 'derived', 'parent', 'child').
        description: Optional description of the relationship.

    Returns:
        True if relationship was successfully recorded, False otherwise.
    """
    # Get metadata for both evidence items
    primary_metadata = get_evidence_details(case_id, primary_evidence_id)
    related_metadata = get_evidence_details(case_id, related_evidence_id)

    if not primary_metadata or not related_metadata:
        logger.error(f"Cannot link evidence: one or both evidence items not found")
        return False

    # Create relationship objects
    relationship = {
        "evidence_id": related_evidence_id,
        "relationship_type": relationship_type,
        "established_by": analyst,
        "established_timestamp": datetime.now(timezone.utc).isoformat()
    }
    if description:
        relationship["description"] = description

    reverse_relationship = {
        "evidence_id": primary_evidence_id,
        "relationship_type": f"reverse_{relationship_type}",
        "established_by": analyst,
        "established_timestamp": datetime.now(timezone.utc).isoformat()
    }
    if description:
        reverse_relationship["description"] = description

    # Update primary evidence
    primary_related = primary_metadata.get("related_evidence", [])

    # Avoid duplicates
    existing_relationship = False
    for rel in primary_related:
        if rel.get("evidence_id") == related_evidence_id and rel.get("relationship_type") == relationship_type:
            existing_relationship = True
            break

    if not existing_relationship:
        primary_related.append(relationship)
        primary_success = update_evidence_details(
            case_id=case_id,
            evidence_id=primary_evidence_id,
            updates={"related_evidence": primary_related},
            analyst=analyst
        )
    else:
        primary_success = True  # Relationship already exists

    # Update related evidence
    related_related = related_metadata.get("related_evidence", [])

    # Avoid duplicates
    existing_reverse = False
    for rel in related_related:
        if rel.get("evidence_id") == primary_evidence_id and rel.get("relationship_type") == reverse_relationship["relationship_type"]:
            existing_reverse = True
            break

    if not existing_reverse:
        related_related.append(reverse_relationship)
        related_success = update_evidence_details(
            case_id=case_id,
            evidence_id=related_evidence_id,
            updates={"related_evidence": related_related},
            analyst=analyst
        )
    else:
        related_success = True  # Relationship already exists

    # Log the relationship in the chain of custody
    track_access(
        case_id=case_id,
        evidence_id=primary_evidence_id,
        analyst=analyst,
        action="link_evidence",
        purpose=f"Link to related evidence {related_evidence_id}",
        details={
            "related_evidence_id": related_evidence_id,
            "relationship_type": relationship_type,
            "description": description
        }
    )

    success = primary_success and related_success
    log_forensic_operation("link_related_evidence", success, {
        "primary_id": primary_evidence_id,
        "related_id": related_evidence_id,
        "relationship": relationship_type
    })

    return success

def search_evidence_by_criteria(
    case_id: str,
    criteria: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Searches for evidence items matching specified criteria.

    Args:
        case_id: The case identifier.
        criteria: Dictionary of search criteria (e.g., {"evidence_type": "memory_dump", "tags": ["important"]})

    Returns:
        List of evidence metadata dictionaries matching the criteria.
    """
    results = []

    # Ensure case directory exists
    case_dir = _get_case_metadata_dir(case_id)
    if not os.path.exists(case_dir):
        logger.info(f"No metadata directory found for case {case_id}")
        return []

    try:
        # Get all evidence files in the case directory
        evidence_files = [f for f in os.listdir(case_dir) if f.endswith('.json')]

        for file_name in evidence_files:
            file_path = os.path.join(case_dir, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)

                # Check if the evidence meets all criteria
                matches = True
                for key, value in criteria.items():
                    if key not in metadata:
                        matches = False
                        break

                    metadata_value = metadata.get(key)

                    # Special handling for list fields (any match)
                    if isinstance(metadata_value, list) and isinstance(value, list):
                        # Check if any value in the criteria is in the metadata list
                        if not any(v in metadata_value for v in value):
                            matches = False
                            break
                    # Special handling for list fields (single value)
                    elif isinstance(metadata_value, list):
                        if value not in metadata_value:
                            matches = False
                            break
                    # Direct comparison for other fields
                    elif metadata_value != value:
                        matches = False
                        break

                if matches:
                    results.append(metadata)

            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Error loading metadata from {file_path}: {e}")
                continue

    except OSError as e:
        logger.error(f"Error searching evidence in case {case_id}: {e}")
        return []

    log_forensic_operation("search_evidence_by_criteria", True, {
        "case_id": case_id,
        "criteria": str(criteria),
        "results_count": len(results)
    })

    return results

def get_all_case_evidence(case_id: str) -> List[Dict[str, Any]]:
    """
    Returns metadata for all evidence items in a case.

    Args:
        case_id: The case identifier.

    Returns:
        List of evidence metadata dictionaries.
    """
    # Use search with empty criteria to get all evidence
    return search_evidence_by_criteria(case_id, {})

def change_evidence_state(
    case_id: str,
    evidence_id: str,
    new_state: str,
    analyst: str,
    reason: str,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Changes the state of an evidence item (e.g., active, archived, destroyed).

    Args:
        case_id: The case identifier.
        evidence_id: The unique identifier of the evidence item.
        new_state: The new state (e.g., 'active', 'archived', 'destroyed').
        analyst: The analyst making the change.
        reason: The reason for changing the state.
        details: Optional additional details about the state change.

    Returns:
        True if the state was successfully changed, False otherwise.
    """
    # Valid states to enforce consistency
    valid_states = {"active", "archived", "in_review", "destroyed", "transferred", "sealed"}

    if new_state not in valid_states:
        logger.error(f"Invalid evidence state: {new_state}")
        return False

    metadata = get_evidence_details(case_id, evidence_id)
    if not metadata:
        logger.error(f"Cannot change state of evidence {evidence_id}: metadata not found")
        return False

    current_state = metadata.get("state", "active")

    # Validate state transitions
    if current_state == "destroyed" and new_state != "destroyed":
        logger.error(f"Cannot change state from 'destroyed' to '{new_state}'")
        return False

    # Record state change in chain of custody
    state_change_tracked = track_access(
        case_id=case_id,
        evidence_id=evidence_id,
        analyst=analyst,
        action="change_state",
        purpose=reason,
        details={
            "from_state": current_state,
            "to_state": new_state,
            **(details or {})
        }
    )

    if not state_change_tracked:
        logger.error(f"Failed to record state change for evidence {evidence_id}")
        return False

    # Update the evidence state in metadata
    state_update = {
        "state": new_state,
        "state_change_history": metadata.get("state_change_history", []) + [{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from_state": current_state,
            "to_state": new_state,
            "changed_by": analyst,
            "reason": reason
        }]
    }

    update_success = update_evidence_details(
        case_id=case_id,
        evidence_id=evidence_id,
        updates=state_update,
        analyst=analyst
    )

    log_forensic_operation("change_evidence_state", update_success, {
        "evidence_id": evidence_id,
        "from_state": current_state,
        "to_state": new_state
    })

    return update_success


def list_evidence_by_case(case_id: str, filter_criteria: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Lists all evidence items for a specific case, with optional filtering.

    Args:
        case_id: The case identifier.
        filter_criteria: Optional dictionary of criteria to filter evidence by.

    Returns:
        List of evidence metadata dictionaries.
    """
    if not case_id:
        logger.error("Missing required case_id for listing evidence")
        log_forensic_operation("list_evidence_by_case", False, {"error": "Missing case_id"})
        return []

    if filter_criteria is None:
        filter_criteria = {}

    try:
        # Get all evidence for the case
        all_evidence = search_evidence_by_criteria(case_id, filter_criteria)

        log_forensic_operation("list_evidence_by_case", True, {
            "case_id": case_id,
            "filter_applied": bool(filter_criteria),
            "evidence_count": len(all_evidence)
        })

        return all_evidence
    except Exception as e:
        logger.error(f"Error listing evidence for case {case_id}: {e}")
        log_forensic_operation("list_evidence_by_case", False, {"case_id": case_id, "error": str(e)})
        return []


def create_evidence_container(
    case_id: str,
    evidence_ids: List[str],
    analyst: str,
    output_path: Optional[str] = None,
    container_type: str = "zip",
    include_metadata: bool = True,
    encryption_password: Optional[str] = None
) -> Optional[str]:
    """
    Creates a container (archive) with multiple evidence items for transfer or storage.

    Args:
        case_id: The case identifier.
        evidence_ids: List of evidence IDs to include in the container.
        analyst: The analyst creating the container.
        output_path: Optional path where the container should be saved (default: temp directory)
        container_type: Type of container to create ("zip", "tar", "7z")
        include_metadata: Whether to include evidence metadata files
        encryption_password: Optional encryption password for the container

    Returns:
        Path to the created container file, or None if creation failed.
    """
    if not case_id or not evidence_ids or not analyst:
        logger.error("Missing required parameters for creating evidence container")
        log_forensic_operation("create_evidence_container", False, {
            "error": "Missing required parameters"
        })
        return None

    if container_type not in ["zip", "tar", "7z"]:
        logger.error(f"Unsupported container type: {container_type}")
        log_forensic_operation("create_evidence_container", False, {
            "error": f"Unsupported container type: {container_type}"
        })
        return None

    try:
        # Create a timestamp for the container filename
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Create a temporary directory for staging the container contents
        import tempfile
        staging_dir = tempfile.mkdtemp(prefix=f"evidence_container_{case_id}_", dir=TEMP_DIR_FORENSICS)
        os.chmod(staging_dir, DEFAULT_SECURE_DIR_PERMS)

        # Create a metadata directory in the staging area
        metadata_dir = os.path.join(staging_dir, "metadata")
        os.makedirs(metadata_dir, mode=DEFAULT_SECURE_DIR_PERMS, exist_ok=True)

        # Create an evidence directory in the staging area
        evidence_dir = os.path.join(staging_dir, "evidence")
        os.makedirs(evidence_dir, mode=DEFAULT_SECURE_DIR_PERMS, exist_ok=True)

        # Track evidence items included in container
        included_evidence = []
        excluded_evidence = []
        evidence_manifest = {
            "case_id": case_id,
            "container_created_at": datetime.now(timezone.utc).isoformat(),
            "container_created_by": analyst,
            "evidence_items": []
        }

        # Add each evidence item to the container
        for evidence_id in evidence_ids:
            metadata = get_evidence_details(case_id, evidence_id)
            if not metadata:
                logger.warning(f"Evidence {evidence_id} metadata not found, skipping")
                excluded_evidence.append(evidence_id)
                continue

            # Get the current location of the evidence file
            source_path = metadata.get("current_location")
            if not source_path or not os.path.exists(source_path):
                logger.warning(f"Evidence file not found for {evidence_id}, skipping")
                excluded_evidence.append(evidence_id)
                continue

            # Copy the evidence file to the staging area
            evidence_filename = os.path.basename(source_path)
            dest_path = os.path.join(evidence_dir, f"{evidence_id}_{evidence_filename}")

            try:
                shutil.copy2(source_path, dest_path)
                os.chmod(dest_path, DEFAULT_READ_ONLY_FILE_PERMS)
                included_evidence.append(evidence_id)

                # Include metadata if requested
                if include_metadata:
                    metadata_path = os.path.join(metadata_dir, f"{evidence_id}.json")
                    with open(metadata_path, 'w', encoding='utf-8') as f:
                        json.dump(metadata, f, indent=2)
                    os.chmod(metadata_path, DEFAULT_READ_ONLY_FILE_PERMS)

                # Add to manifest
                evidence_manifest["evidence_items"].append({
                    "evidence_id": evidence_id,
                    "original_path": source_path,
                    "container_path": f"evidence/{evidence_id}_{evidence_filename}",
                    "metadata_included": include_metadata,
                    "hash_algorithm": next(iter(metadata.get("initial_hashes", {}))),
                    "hash_value": next(iter(metadata.get("initial_hashes", {}).values())),
                    "description": metadata.get("description", "")
                })
            except Exception as e:
                logger.error(f"Error copying evidence {evidence_id}: {e}")
                excluded_evidence.append(evidence_id)

        # Write the manifest file
        manifest_path = os.path.join(metadata_dir, "container_manifest.json")
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(evidence_manifest, f, indent=2)
        os.chmod(manifest_path, DEFAULT_READ_ONLY_FILE_PERMS)

        # Create the container file
        if not output_path:
            output_path = os.path.join(
                TEMP_DIR_FORENSICS,
                f"evidence_container_{case_id}_{timestamp}.{container_type}"
            )

        if container_type == "zip":
            import zipfile
            compression = zipfile.ZIP_DEFLATED
            encryption = zipfile.ZIP_AES if encryption_password else None

            with zipfile.ZipFile(output_path, 'w', compression=compression) as zf:
                # Walk the staging directory and add all files
                for root, _, files in os.walk(staging_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Get path relative to staging directory
                        rel_path = os.path.relpath(file_path, staging_dir)
                        zf.write(file_path, rel_path, compress_type=compression)

        elif container_type == "tar":
            import tarfile
            with tarfile.open(output_path, "w:gz") as tar:
                # Change to staging directory and add everything
                current_dir = os.getcwd()
                os.chdir(staging_dir)
                try:
                    for item in os.listdir('.'):
                        tar.add(item)
                finally:
                    os.chdir(current_dir)

        elif container_type == "7z":
            # For 7z, we need to use subprocess to call the 7z command
            import subprocess
            cmd = ["7z", "a", output_path]

            if encryption_password:
                cmd.extend(["-p" + encryption_password])

            cmd.append(os.path.join(staging_dir, "*"))

            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Calculate the hash for the container
        container_hash = calculate_file_hash(output_path)

        # Track container creation in chain of custody for each included evidence
        for evidence_id in included_evidence:
            track_access(
                case_id=case_id,
                evidence_id=evidence_id,
                analyst=analyst,
                action="container_inclusion",
                purpose="Evidence included in container package",
                details={
                    "container_path": output_path,
                    "container_hash": container_hash,
                    "container_type": container_type,
                    "encryption": bool(encryption_password)
                }
            )

        # Log the container creation
        log_forensic_operation("create_evidence_container", True, {
            "case_id": case_id,
            "evidence_count": len(included_evidence),
            "excluded_count": len(excluded_evidence),
            "container_path": output_path,
            "container_hash": container_hash,
            "container_type": container_type,
            "encryption": bool(encryption_password)
        })

        # Clean up the staging directory
        shutil.rmtree(staging_dir)

        return output_path

    except Exception as e:
        logger.error(f"Error creating evidence container for case {case_id}: {e}")
        log_forensic_operation("create_evidence_container", False, {
            "case_id": case_id,
            "error": str(e)
        })
        return None


def export_chain_of_custody(
    case_id: str,
    evidence_id: Optional[str] = None,
    output_path: Optional[str] = None,
    format: str = "pdf",
    include_signatures: bool = True
) -> Optional[str]:
    """
    Exports the chain of custody log for a case or specific evidence item.

    Args:
        case_id: The case identifier.
        evidence_id: Optional evidence ID to export custody for a specific item.
        output_path: Optional path to save the exported file.
        format: Output format ('pdf', 'html', 'json', 'csv', 'text').
        include_signatures: Whether to include signature fields in the export.

    Returns:
        Path to the exported file, or None if export failed.
    """
    if not case_id:
        logger.error("Missing required case_id for exporting chain of custody")
        log_forensic_operation("export_chain_of_custody", False, {"error": "Missing case_id"})
        return None

    if format not in ["pdf", "html", "json", "csv", "text"]:
        logger.error(f"Unsupported export format: {format}")
        log_forensic_operation("export_chain_of_custody", False, {"error": f"Unsupported format: {format}"})
        return None

    try:
        # Get the chain of custody entries
        custody_entries = get_chain_of_custody(case_id, evidence_id)
        if not custody_entries:
            logger.warning(f"No chain of custody entries found for case {case_id}{f', evidence {evidence_id}' if evidence_id else ''}")
            return None

        # Get case details if available
        case_details = None
        if os.path.exists(_get_case_metadata_dir(case_id)):
            try:
                case_info_path = os.path.join(_get_case_metadata_dir(case_id), "case_info.json")
                if os.path.exists(case_info_path):
                    with open(case_info_path, 'r', encoding='utf-8') as f:
                        case_details = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load case details: {e}")

        # Get evidence details if applicable
        evidence_details = None
        if evidence_id:
            evidence_details = get_evidence_details(case_id, evidence_id)

        # Generate a timestamp for the filename
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Determine output path if not provided
        if not output_path:
            evidence_suffix = f"_{evidence_id}" if evidence_id else ""
            output_path = os.path.join(
                TEMP_DIR_FORENSICS,
                f"chain_of_custody_{case_id}{evidence_suffix}_{timestamp}.{format}"
            )

        # Prepare the export data
        export_data = {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "entries": custody_entries,
            "case_details": case_details,
            "evidence_details": evidence_details,
            "include_signatures": include_signatures
        }

        # Export based on format
        if format == "json":
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)

        elif format == "csv":
            import csv
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "Timestamp", "Evidence ID", "Analyst", "Action",
                    "Purpose", "Details"
                ])
                # Write entries
                for entry in custody_entries:
                    writer.writerow([
                        entry.get("timestamp", ""),
                        entry.get("evidence_id", ""),
                        entry.get("analyst", ""),
                        entry.get("action", ""),
                        entry.get("purpose", ""),
                        json.dumps(entry.get("details", {}))
                    ])

        elif format == "text":
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"Chain of Custody Report\n")
                f.write(f"Case ID: {case_id}\n")
                if evidence_id:
                    f.write(f"Evidence ID: {evidence_id}\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")

                if evidence_details:
                    f.write("Evidence Information:\n")
                    f.write(f"Description: {evidence_details.get('description', 'N/A')}\n")
                    f.write(f"Type: {evidence_details.get('evidence_type', 'N/A')}\n")
                    f.write(f"Acquisition Date: {evidence_details.get('acquisition_timestamp', 'N/A')}\n")
                    f.write(f"Acquired By: {evidence_details.get('acquisition_analyst', 'N/A')}\n\n")

                f.write("Chain of Custody Log:\n")
                f.write("-" * 80 + "\n")
                for entry in custody_entries:
                    f.write(f"Timestamp: {entry.get('timestamp', '')}\n")
                    f.write(f"Analyst: {entry.get('analyst', '')}\n")
                    f.write(f"Action: {entry.get('action', '')}\n")
                    f.write(f"Purpose: {entry.get('purpose', '')}\n")
                    details = entry.get("details", {})
                    if details:
                        f.write("Details:\n")
                        for key, value in details.items():
                            f.write(f"  {key}: {value}\n")
                    f.write("-" * 80 + "\n")

                if include_signatures:
                    f.write("\nSignatures:\n\n")
                    f.write("Report Generated By: ____________________________  Date: ____________\n\n")
                    f.write("Reviewed By: ________________________________  Date: ____________\n\n")

        elif format == "html" or format == "pdf":
            # Create HTML version (for both HTML and PDF formats)
            from datetime import datetime
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Chain of Custody Report - Case {case_id}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2 {{ color: #2c3e50; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .signature-line {{ border-top: 1px solid black; margin-top: 70px; width: 300px; }}
                    .header {{ display: flex; justify-content: space-between; }}
                    .evidence-info {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #ddd; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Chain of Custody Report</h1>
                    <div>
                        <p><strong>Generated:</strong> {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                    </div>
                </div>
                <div>
                    <p><strong>Case ID:</strong> {case_id}</p>
                    {f'<p><strong>Evidence ID:</strong> {evidence_id}</p>' if evidence_id else ''}
                </div>
            """

            if evidence_details:
                html_content += f"""
                <h2>Evidence Information</h2>
                <div class="evidence-info">
                    <p><strong>Description:</strong> {evidence_details.get('description', 'N/A')}</p>
                    <p><strong>Type:</strong> {evidence_details.get('evidence_type', 'N/A')}</p>
                    <p><strong>Acquisition Date:</strong> {evidence_details.get('acquisition_timestamp', 'N/A')}</p>
                    <p><strong>Acquired By:</strong> {evidence_details.get('acquisition_analyst', 'N/A')}</p>
                    <p><strong>Classification:</strong> {evidence_details.get('classification', 'N/A')}</p>
                </div>
                """

            html_content += """
                <h2>Chain of Custody Log</h2>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>Evidence ID</th>
                        <th>Analyst</th>
                        <th>Action</th>
                        <th>Purpose</th>
                        <th>Details</th>
                    </tr>
            """

            for entry in custody_entries:
                details_str = "<ul>"
                for key, value in entry.get("details", {}).items():
                    details_str += f"<li><strong>{key}:</strong> {value}</li>"
                details_str += "</ul>"

                html_content += f"""
                    <tr>
                        <td>{entry.get('timestamp', '')}</td>
                        <td>{entry.get('evidence_id', '')}</td>
                        <td>{entry.get('analyst', '')}</td>
                        <td>{entry.get('action', '')}</td>
                        <td>{entry.get('purpose', '')}</td>
                        <td>{details_str}</td>
                    </tr>
                """

            html_content += """
                </table>
            """

            if include_signatures:
                html_content += """
                <h2>Signatures</h2>
                <div>
                    <div>
                        <p class="signature-line"></p>
                        <p>Report Generated By</p>
                    </div>
                    <div>
                        <p class="signature-line"></p>
                        <p>Date</p>
                    </div>
                    <div>
                        <p class="signature-line"></p>
                        <p>Reviewed By</p>
                    </div>
                    <div>
                        <p class="signature-line"></p>
                        <p>Date</p>
                    </div>
                </div>
                """

            html_content += """
                </body>
                </html>
            """

            # For HTML format, write directly to file
            if format == "html":
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)

            # For PDF format, convert HTML to PDF
            else:  # format == "pdf"
                try:
                    # Try to use weasyprint if available
                    try:
                        from weasyprint import HTML
                        HTML(string=html_content).write_pdf(output_path)
                    except ImportError:
                        # Fall back to pdfkit if weasyprint is not available
                        import pdfkit
                        pdfkit.from_string(html_content, output_path)
                except Exception as pdf_error:
                    logger.error(f"Error creating PDF: {pdf_error}. Falling back to HTML.")
                    # If PDF conversion fails, fall back to HTML
                    html_path = output_path.replace('.pdf', '.html')
                    with open(html_path, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    log_forensic_operation("export_chain_of_custody", False, {
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "error": f"PDF conversion failed: {str(pdf_error)}",
                        "fallback": "HTML format"
                    })
                    return html_path

        # Set proper file permissions
        os.chmod(output_path, DEFAULT_READ_ONLY_FILE_PERMS)

        # Log the export operation
        log_forensic_operation("export_chain_of_custody", True, {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "format": format,
            "output_path": output_path,
            "entry_count": len(custody_entries)
        })

        return output_path

    except Exception as e:
        logger.error(f"Error exporting chain of custody for case {case_id}: {e}")
        log_forensic_operation("export_chain_of_custody", False, {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "error": str(e)
        })
        return None


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    TEST_CASE_ID = "INCIDENT-TEST-001"
    TEST_FILE = "dummy_evidence.bin"
    TEST_ANALYST = "test_analyst"

    # Create a dummy evidence file
    try:
        with open(TEST_FILE, "wb") as f:
            f.write(os.urandom(1024)) # 1KB dummy data
    except OSError as e:
        logger.error(f"Failed to create dummy file {TEST_FILE}: {e}")
        exit(1)

    print(f"--- Registering Evidence ---")
    evidence_id = register_evidence(
        case_id=TEST_CASE_ID,
        evidence_description="Dummy binary file for testing",
        evidence_type="binary_file",
        source_identifier="test_system",
        acquisition_method="test_creation",
        acquisition_tool="python_script",
        analyst=TEST_ANALYST,
        file_path=TEST_FILE,
        classification="Test-Confidential"
    )

    if evidence_id:
        print(f"Evidence registered successfully. ID: {evidence_id}")

        print(f"\n--- Getting Evidence Details ---")
        details = get_evidence_details(TEST_CASE_ID, evidence_id)
        if details:
            print(json.dumps(details, indent=2))
        else:
            print("Failed to retrieve evidence details.")

        print(f"\n--- Tracking Access ---")
        access_tracked = track_access(
            case_id=TEST_CASE_ID,
            evidence_id=evidence_id,
            analyst="reviewer_analyst",
            action="access",
            purpose="Initial review of evidence metadata"
        )
        print(f"Access tracking successful: {access_tracked}")

        analysis_tracked = track_access(
            case_id=TEST_CASE_ID,
            evidence_id=evidence_id,
            analyst=TEST_ANALYST,
            action="analyze",
            purpose="Performed basic string analysis",
            details={"tool_used": "strings", "findings": "No significant strings found"}
        )
        print(f"Analysis tracking successful: {analysis_tracked}")

        print(f"\n--- Updating Evidence Details ---")
        update_success = update_evidence_details(
            case_id=TEST_CASE_ID,
            evidence_id=evidence_id,
            updates={"tags": ["test_case", "dummy_data"], "current_location": "/secure/evidence/processed/" + TEST_FILE},
            analyst="updater_analyst"
        )
        print(f"Update successful: {update_success}")

        print(f"\n--- Getting Updated Evidence Details ---")
        updated_details = get_evidence_details(TEST_CASE_ID, evidence_id)
        if updated_details:
            print(json.dumps(updated_details, indent=2))
        else:
            print("Failed to retrieve updated evidence details.")

        # Test new functionality
        if CRYPTO_VERIFICATION_AVAILABLE:
            print(f"\n--- Verifying Evidence Integrity ---")
            verified = verify_evidence_integrity(
                case_id=TEST_CASE_ID,
                evidence_id=evidence_id,
                analyst=TEST_ANALYST,
                file_path=TEST_FILE
            )
            print(f"Integrity verification result: {verified}")

        # Create a second evidence item for relationship testing
        second_file = "related_evidence.bin"
        try:
            with open(second_file, "wb") as f:
                f.write(os.urandom(512))  # 512 bytes of random data

            second_evidence_id = register_evidence(
                case_id=TEST_CASE_ID,
                evidence_description="Related evidence file",
                evidence_type="binary_file",
                source_identifier="test_system",
                acquisition_method="test_creation",
                acquisition_tool="python_script",
                analyst=TEST_ANALYST,
                file_path=second_file
            )

            if second_evidence_id:
                print(f"\n--- Linking Related Evidence ---")
                link_result = link_related_evidence(
                    case_id=TEST_CASE_ID,
                    primary_evidence_id=evidence_id,
                    related_evidence_id=second_evidence_id,
                    analyst=TEST_ANALYST,
                    relationship_type="derived",
                    description="Derived from original evidence"
                )
                print(f"Link evidence result: {link_result}")

                # Check the relationship was recorded
                primary_metadata = get_evidence_details(TEST_CASE_ID, evidence_id)
                if primary_metadata and "related_evidence" in primary_metadata:
                    print("Relationship recorded in primary evidence:")
                    print(json.dumps(primary_metadata["related_evidence"], indent=2))
        except Exception as e:
            print(f"Error during relationship testing: {e}")
        finally:
            if os.path.exists(second_file):
                os.remove(second_file)

        print(f"\n--- Changing Evidence State ---")
        state_change_result = change_evidence_state(
            case_id=TEST_CASE_ID,
            evidence_id=evidence_id,
            new_state="archived",
            analyst=TEST_ANALYST,
            reason="Evidence analysis complete"
        )
        print(f"State change result: {state_change_result}")

        print(f"\n--- Getting Chain of Custody ---")
        coc = get_chain_of_custody(TEST_CASE_ID, evidence_id)
        if coc:
            print(f"Chain of Custody for {evidence_id}:")
            for entry in coc:
                print(f"  - {entry['timestamp']} | {entry['analyst']} | {entry['action']} | {entry['purpose']}")
        else:
            print("Failed to retrieve chain of custody.")

        print(f"\n--- Getting Full Case Chain of Custody ---")
        full_coc = get_chain_of_custody(TEST_CASE_ID)
        if full_coc:
            print(f"Full Chain of Custody for Case {TEST_CASE_ID}:")
            for entry in full_coc:
                print(f"  - {entry['timestamp']} | EvID: {entry.get('evidence_id', 'N/A')} | {entry['analyst']} | {entry['action']}")
        else:
            print("Failed to retrieve full case chain of custody.")

    else:
        print("Evidence registration failed.")

    # Clean up dummy file and metadata (optional)
    try:
        os.remove(TEST_FILE)
        # Be careful with recursive deletion in production code!
        # import shutil
        # case_meta_dir = _get_case_metadata_dir(TEST_CASE_ID)
        # if os.path.exists(case_meta_dir):
        #     shutil.rmtree(case_meta_dir)
        #     print(f"\nCleaned up test metadata directory: {case_meta_dir}")
    except OSError as e:
        logger.warning(f"Cleanup failed: {e}")
