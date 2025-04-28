"""
Evidence Management Utilities for the Forensic Analysis Toolkit.

This module provides functions for registering, tracking, and managing digital
evidence throughout the forensic lifecycle. It ensures proper documentation of
evidence handling, maintains chain of custody records, and facilitates
consistent metadata management.

Core functionalities include:
- Registering new evidence items with unique identifiers and metadata.
- Tracking access and handling actions for each evidence item.
- Retrieving evidence details and chain of custody history.
- Storing evidence metadata securely and persistently.
"""

import json
import os
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

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
    from admin.security.forensics.utils.crypto import calculate_file_hash
except ImportError:
    logging.warning("Forensic crypto utility not found. Hash calculation unavailable.")
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        logging.error("calculate_file_hash function is unavailable.")
        return None

# Attempt to import constants
try:
    from admin.security.forensics.utils.forensic_constants import (
        EVIDENCE_METADATA_DIR, DEFAULT_HASH_ALGORITHM, CHAIN_OF_CUSTODY_FILENAME
    )
except ImportError:
    logging.warning("Forensic constants not found. Using default values.")
    EVIDENCE_METADATA_DIR = "/secure/forensics/metadata" # Example default
    DEFAULT_HASH_ALGORITHM = "sha256"
    CHAIN_OF_CUSTODY_FILENAME = "chain_of_custody.jsonl" # JSON Lines format

logger = logging.getLogger(__name__)

# Ensure metadata directory exists
os.makedirs(EVIDENCE_METADATA_DIR, exist_ok=True)

def _get_case_metadata_dir(case_id: str) -> str:
    """Constructs the path to the metadata directory for a specific case."""
    safe_case_id = "".join(c for c in case_id if c.isalnum() or c in ('-', '_')).rstrip()
    if not safe_case_id:
        raise ValueError("Invalid case ID provided.")
    return os.path.join(EVIDENCE_METADATA_DIR, safe_case_id)

def _get_evidence_metadata_path(case_id: str, evidence_id: str) -> str:
    """Constructs the path to the metadata file for a specific evidence item."""
    case_dir = _get_case_metadata_dir(case_id)
    return os.path.join(case_dir, f"{evidence_id}.json")

def _get_chain_of_custody_path(case_id: str) -> str:
    """Constructs the path to the chain of custody log file for a specific case."""
    case_dir = _get_case_metadata_dir(case_id)
    return os.path.join(case_dir, CHAIN_OF_CUSTODY_FILENAME)

def _generate_evidence_id() -> str:
    """Generates a unique identifier for an evidence item."""
    return str(uuid.uuid4())

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
    initial_hash_algorithm: str = DEFAULT_HASH_ALGORITHM
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

    Returns:
        The unique evidence ID if registration is successful, None otherwise.
    """
    evidence_id = _generate_evidence_id()
    timestamp = acquisition_timestamp or datetime.now(timezone.utc)
    timestamp_iso = timestamp.isoformat()

    initial_hash = None
    if file_path:
        try:
            initial_hash = calculate_file_hash(file_path, initial_hash_algorithm)
            if initial_hash is None:
                logger.warning(f"Failed to calculate initial hash for {file_path}")
                # Proceeding without hash, but log it
        except Exception as e:
            logger.error(f"Error calculating initial hash for {file_path}: {e}")
            # Proceeding without hash

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
        "original_file_path": file_path, # Store original path if provided
        "current_location": file_path, # Assume initial location is the file path
        "tags": [],
        "related_evidence": []
    }

    try:
        case_dir = _get_case_metadata_dir(case_id)
        os.makedirs(case_dir, exist_ok=True)
        metadata_path = _get_evidence_metadata_path(case_id, evidence_id)

        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

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
                "hash_algorithm": initial_hash_algorithm
            }
        )

        log_forensic_operation("register_evidence", True, {"evidence_id": evidence_id, "case_id": case_id})
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
        coc_path = _get_chain_of_custody_path(case_id)
        case_dir = os.path.dirname(coc_path)
        os.makedirs(case_dir, exist_ok=True) # Ensure directory exists

        # Append to JSON Lines file
        with open(coc_path, 'a', encoding='utf-8') as f:
            json.dump(log_entry, f)
            f.write('\n')

        log_forensic_operation("track_evidence_access", True, {"evidence_id": evidence_id, "action": action, "analyst": analyst})
        return True
    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Failed to track access for evidence {evidence_id}: {e}")
        log_forensic_operation("track_evidence_access", False, {"evidence_id": evidence_id, "error": str(e)})
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
    metadata = get_evidence_details(case_id, evidence_id)
    if not metadata:
        return False

    original_metadata = metadata.copy() # For logging changes
    changed_fields = {}

    # Apply updates, ensuring critical fields are not overwritten accidentally
    protected_fields = {"evidence_id", "case_id", "acquisition_timestamp", "registration_timestamp", "acquisition_analyst"}
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
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        # Log the update in the chain of custody
        track_access(
            case_id=case_id,
            evidence_id=evidence_id,
            analyst=analyst,
            action="update_metadata",
            purpose="Updating evidence details",
            details={"updated_fields": changed_fields}
        )
        log_forensic_operation("update_evidence_details", True, {"evidence_id": evidence_id, "updated_fields": list(changed_fields.keys())})
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
    entries = []
    try:
        coc_path = _get_chain_of_custody_path(case_id)
        if not os.path.exists(coc_path):
            logger.info(f"Chain of custody file not found for case {case_id}")
            return []

        with open(coc_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if evidence_id is None or entry.get("evidence_id") == evidence_id:
                        entries.append(entry)
                except json.JSONDecodeError:
                    logger.warning(f"Skipping invalid JSON line in {coc_path}: {line.strip()}")

        log_forensic_operation("get_chain_of_custody", True, {"case_id": case_id, "evidence_id": evidence_id})
        # Sort by timestamp just in case entries were appended out of order
        entries.sort(key=lambda x: x.get("timestamp", ""))
        return entries
    except (OSError, ValueError) as e:
        logger.error(f"Failed to retrieve chain of custody for case {case_id}: {e}")
        log_forensic_operation("get_chain_of_custody", False, {"case_id": case_id, "error": str(e)})
        return []

# Example usage
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
        file_path=TEST_FILE
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
