#!/usr/bin/env python3
"""
Evidence Collection Module

This module provides functions for collecting digital evidence during security incident
investigations. It implements forensically sound evidence acquisition methods to ensure
proper chain of custody and evidence integrity are maintained throughout the collection process.

The module supports various evidence types defined in EvidenceType, including memory dumps,
disk images, logs, network captures, and more. Evidence is collected with proper hashing
and integrity verification to maintain admissibility.
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Set

# Initialize logging
logger = logging.getLogger(__name__)

# Try importing from core forensic utilities if available
try:
    from admin.security.forensics.utils import (
        calculate_file_hash,
        verify_file_hash,
        create_secure_temp_file,
        secure_delete,
        verify_evidence_integrity
    )
    from admin.security.forensics.utils.evidence_tracker import (
        register_evidence,
        track_access,
        get_evidence_details,
        update_evidence_details,
        get_chain_of_custody,
        create_evidence_container
    )
    FORENSIC_UTILS_AVAILABLE = True
    logger.debug("Forensic utilities loaded")
except ImportError:
    FORENSIC_UTILS_AVAILABLE = False
    logger.warning("Forensic utilities not available, using minimal functionality")

try:
    from admin.security.forensics.live_response import (
        update_evidence_integrity_baseline,
        verify_evidence_integrity as verify_directory_integrity
    )
    LIVE_RESPONSE_AVAILABLE = True
    logger.debug("Live response capabilities loaded")
except ImportError:
    LIVE_RESPONSE_AVAILABLE = False
    logger.warning("Live response utilities not available, using minimal functionality")

# Import from parent package with relative imports
from .incident_constants import EvidenceType, IncidentType
from . import (
    DEFAULT_EVIDENCE_DIR,
    EVIDENCE_ENCRYPTION,
    EVIDENCE_COMPRESSION,
    EVIDENCE_RETENTION_DAYS,
    EvidenceCollectionError,
    sanitize_incident_id,
    create_evidence_directory
)

# Constants
DEFAULT_HASH_ALGORITHM = "sha256"

class Evidence:
    """Class representing a piece of digital evidence."""

    def __init__(
        self,
        evidence_id: str,
        incident_id: str,
        path: str,
        evidence_type: str,
        description: Optional[str] = None,
        hash_value: Optional[str] = None,
        hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
        analyst: Optional[str] = None,
        collection_timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize an evidence object.

        Args:
            evidence_id: Unique identifier for the evidence
            incident_id: Related incident ID
            path: Path to the evidence file or directory
            evidence_type: Type of evidence (from EvidenceType constants)
            description: Description of the evidence
            hash_value: Cryptographic hash of the evidence
            hash_algorithm: Algorithm used for hashing
            analyst: Name of the analyst collecting the evidence
            collection_timestamp: When the evidence was collected
            metadata: Additional metadata about the evidence
        """
        self.evidence_id = evidence_id
        self.incident_id = incident_id
        self.path = path
        self.evidence_type = evidence_type
        self.description = description
        self.hash_value = hash_value
        self.hash_algorithm = hash_algorithm
        self.analyst = analyst
        self.collection_timestamp = collection_timestamp or datetime.datetime.now().isoformat()
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence object to a dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "incident_id": self.incident_id,
            "path": self.path,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "hash": {self.hash_algorithm: self.hash_value} if self.hash_value else {},
            "analyst": self.analyst,
            "collection_timestamp": self.collection_timestamp,
            "metadata": self.metadata
        }

    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the evidence.

        Returns:
            bool: True if integrity check passes, False otherwise
        """
        if not os.path.exists(self.path):
            logger.error(f"Evidence file not found: {self.path}")
            return False

        if os.path.isdir(self.path):
            if LIVE_RESPONSE_AVAILABLE and self.metadata.get("integrity_baseline"):
                verified, _ = verify_directory_integrity(
                    evidence_dir=self.path,
                    baseline_path=self.metadata.get("integrity_baseline")
                )
                return verified
            return True  # Can't verify directories without baseline
        else:
            if not self.hash_value:
                # Calculate hash if not already present
                self.hash_value = calculate_hash(self.path, self.hash_algorithm)
                return True

            current_hash = calculate_hash(self.path, self.hash_algorithm)
            return current_hash == self.hash_value

class EvidenceCollector:
    """
    Utility for collecting and managing incident evidence.

    This class handles the collection, documentation, and preservation of
    digital evidence during security incidents, maintaining proper chain
    of custody and integrity throughout the process.
    """

    def __init__(
        self,
        incident_id: str,
        evidence_dir: Optional[str] = None,
        analyst: Optional[str] = None,
        retention_period: Optional[str] = None,
        classification: str = "Confidential"
    ):
        """
        Initialize the evidence collector.

        Args:
            incident_id: Identifier for the incident
            evidence_dir: Base directory for evidence (default: system evidence dir)
            analyst: Person collecting evidence
            retention_period: How long to retain evidence
            classification: Security classification of the evidence
        """
        self.incident_id = sanitize_incident_id(incident_id)
        self.analyst = analyst or os.environ.get("USER", "unknown")
        self.retention_period = retention_period or f"{EVIDENCE_RETENTION_DAYS}d"
        self.classification = classification

        # Set up evidence directory
        if evidence_dir:
            self.evidence_dir = Path(evidence_dir)
        else:
            try:
                self.evidence_dir = create_evidence_directory(incident_id)
            except EvidenceCollectionError:
                # Fall back to temp directory if we can't create in normal location
                temp_dir = Path(tempfile.gettempdir()) / f"ir_evidence_{incident_id}"
                temp_dir.mkdir(parents=True, exist_ok=True)
                self.evidence_dir = temp_dir
                logger.warning(f"Using temporary directory for evidence: {temp_dir}")

        # Enforce existence
        os.makedirs(self.evidence_dir, exist_ok=True)

        # List for tracking collected evidence
        self.collected_evidence: List[Evidence] = []

        # Metadata about this collection
        self.collection_metadata = {
            "incident_id": incident_id,
            "started_at": datetime.datetime.now().isoformat(),
            "analyst": self.analyst,
            "hostname": self._get_hostname(),
            "classification": classification,
            "evidence_items": []
        }

        # Create case manifest
        self._create_case_manifest()

        logger.info(f"Initialized evidence collection for incident {incident_id} in {self.evidence_dir}")

    def collect_file(
        self,
        file_path: str,
        evidence_type: str,
        description: Optional[str] = None
    ) -> Optional[str]:
        """
        Collect and register a file as evidence.

        Args:
            file_path: Path to the file to collect
            evidence_type: Type of evidence (from EvidenceType)
            description: Description of the evidence

        Returns:
            Evidence ID if successful, None otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        if not os.path.isfile(file_path):
            logger.error(f"Not a file: {file_path}")
            return None

        # Create type-specific directory
        type_dir = os.path.join(self.evidence_dir, evidence_type)
        os.makedirs(type_dir, exist_ok=True)

        # Create timestamped filename to prevent collisions
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = os.path.basename(file_path)
        dest_path = os.path.join(type_dir, f"{timestamp}_{basename}")

        try:
            # Copy the file securely
            if FORENSIC_UTILS_AVAILABLE:
                # Use secure copy with memory-safe operations
                shutil.copy2(file_path, dest_path)
                os.chmod(dest_path, 0o400)  # Read-only
                file_hash = calculate_file_hash(dest_path, DEFAULT_HASH_ALGORITHM)
            else:
                # Basic copy if specialized utilities aren't available
                shutil.copy2(file_path, dest_path)
                os.chmod(dest_path, 0o400)  # Read-only
                file_hash = calculate_hash(dest_path)

            # Generate unique evidence ID
            evidence_id = f"EV-{self.incident_id}-{timestamp}-{basename[:10]}"

            # Register with forensic evidence tracker if available
            if FORENSIC_UTILS_AVAILABLE:
                try:
                    registered_id = register_evidence(
                        case_id=self.incident_id,
                        evidence_description=description or f"File evidence: {basename}",
                        evidence_type=evidence_type,
                        source_identifier=file_path,
                        acquisition_method="file_copy",
                        acquisition_tool="incident_response_kit.collect_evidence",
                        analyst=self.analyst,
                        file_path=dest_path,
                        initial_hash_algorithm=DEFAULT_HASH_ALGORITHM,
                        classification=self.classification,
                        retention_period=self.retention_period
                    )
                    if registered_id:
                        evidence_id = registered_id
                except Exception as e:
                    logger.warning(f"Failed to register evidence with tracking system: {e}")

            # Create evidence metadata file
            metadata_path = f"{dest_path}.metadata.json"
            metadata = {
                "evidence_id": evidence_id,
                "incident_id": self.incident_id,
                "description": description or f"File evidence: {basename}",
                "evidence_type": evidence_type,
                "source_identifier": file_path,
                "acquisition_method": "file_copy",
                "acquisition_tool": "incident_response_kit.collect_evidence",
                "analyst": self.analyst,
                "acquisition_timestamp": datetime.datetime.now().isoformat(),
                "hash": {DEFAULT_HASH_ALGORITHM: file_hash},
                "classification": self.classification,
                "integrity_verified": True
            }

            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            os.chmod(metadata_path, 0o400)  # Read-only

            # Create evidence object
            evidence = Evidence(
                evidence_id=evidence_id,
                incident_id=self.incident_id,
                path=dest_path,
                evidence_type=evidence_type,
                description=description or f"File evidence: {basename}",
                hash_value=file_hash,
                hash_algorithm=DEFAULT_HASH_ALGORITHM,
                analyst=self.analyst,
                metadata={
                    "original_path": file_path,
                    "file_size": os.path.getsize(dest_path),
                    "collection_method": "file_copy"
                }
            )

            # Add to collection and update manifest
            self.collected_evidence.append(evidence)
            self._add_to_manifest(evidence)

            logger.info(f"Collected file evidence {evidence_id}: {basename} as {evidence_type}")
            return evidence_id

        except Exception as e:
            logger.error(f"Error collecting {file_path}: {e}", exc_info=True)
            # Clean up if collection failed
            if os.path.exists(dest_path):
                os.unlink(dest_path)
            return None

    def collect_directory(
        self,
        directory_path: str,
        evidence_type: str,
        description: Optional[str] = None,
        create_baseline: bool = True
    ) -> Optional[str]:
        """
        Collect and register a directory as evidence.

        Args:
            directory_path: Path to the directory to collect
            evidence_type: Type of evidence
            description: Description of the evidence
            create_baseline: Whether to create an integrity baseline

        Returns:
            Evidence ID if successful, None otherwise
        """
        if not os.path.isdir(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            return None

        # Create type-specific directory
        type_dir = os.path.join(self.evidence_dir, evidence_type)
        os.makedirs(type_dir, exist_ok=True)

        # Create timestamped directory name to prevent collisions
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = os.path.basename(directory_path.rstrip('/'))
        dest_dir = os.path.join(type_dir, f"{timestamp}_{basename}")

        try:
            # Copy the directory
            shutil.copytree(directory_path, dest_dir)

            # Make files read-only
            for root, _, files in os.walk(dest_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    os.chmod(file_path, 0o400)  # Read-only

            # Create integrity baseline if requested and available
            baseline_path = None
            if create_baseline and LIVE_RESPONSE_AVAILABLE:
                try:
                    success, baseline_path = update_evidence_integrity_baseline(
                        evidence_dir=dest_dir,
                        hash_algorithm=DEFAULT_HASH_ALGORITHM,
                        case_id=self.incident_id,
                        examiner=self.analyst
                    )
                    if not success:
                        logger.warning(f"Failed to create integrity baseline for {dest_dir}")
                        baseline_path = None
                except Exception as e:
                    logger.warning(f"Error creating integrity baseline: {e}")
                    baseline_path = None

            # Generate unique evidence ID
            evidence_id = f"EV-{self.incident_id}-{timestamp}-dir-{basename[:10]}"

            # Register with forensic evidence tracker if available
            if FORENSIC_UTILS_AVAILABLE:
                try:
                    registered_id = register_evidence(
                        case_id=self.incident_id,
                        evidence_description=description or f"Directory evidence: {basename}",
                        evidence_type=evidence_type,
                        source_identifier=directory_path,
                        acquisition_method="directory_copy",
                        acquisition_tool="incident_response_kit.collect_evidence",
                        analyst=self.analyst,
                        file_path=dest_dir,
                        classification=self.classification,
                        retention_period=self.retention_period
                    )
                    if registered_id:
                        evidence_id = registered_id
                except Exception as e:
                    logger.warning(f"Failed to register evidence with tracking system: {e}")

            # Create evidence metadata file
            metadata_path = os.path.join(dest_dir, "evidence_metadata.json")
            metadata = {
                "evidence_id": evidence_id,
                "incident_id": self.incident_id,
                "description": description or f"Directory evidence: {basename}",
                "evidence_type": evidence_type,
                "source_identifier": directory_path,
                "acquisition_method": "directory_copy",
                "acquisition_tool": "incident_response_kit.collect_evidence",
                "analyst": self.analyst,
                "acquisition_timestamp": datetime.datetime.now().isoformat(),
                "integrity_baseline": baseline_path,
                "classification": self.classification
            }

            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            os.chmod(metadata_path, 0o400)  # Read-only

            # Create evidence object
            evidence = Evidence(
                evidence_id=evidence_id,
                incident_id=self.incident_id,
                path=dest_dir,
                evidence_type=evidence_type,
                description=description or f"Directory evidence: {basename}",
                analyst=self.analyst,
                metadata={
                    "original_path": directory_path,
                    "integrity_baseline": baseline_path,
                    "collection_method": "directory_copy"
                }
            )

            # Add to collection and update manifest
            self.collected_evidence.append(evidence)
            self._add_to_manifest(evidence)

            logger.info(f"Collected directory evidence {evidence_id}: {basename} as {evidence_type}")
            return evidence_id

        except Exception as e:
            logger.error(f"Error collecting directory {directory_path}: {e}", exc_info=True)
            # Clean up if collection failed
            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)
            return None

    def collect_command_output(
        self,
        command: Union[str, List[str]],
        evidence_type: str,
        description: Optional[str] = None,
        shell: bool = False,
        timeout: int = 60,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> Optional[str]:
        """
        Run a command and collect its output as evidence.

        Args:
            command: Command to run (string or list of arguments)
            evidence_type: Type of evidence
            description: Description of the evidence
            shell: Whether to run the command in a shell
            timeout: Timeout in seconds
            working_dir: Working directory for the command
            env: Environment variables for the command

        Returns:
            Evidence ID if successful, None otherwise
        """
        # Create type-specific directory
        type_dir = os.path.join(self.evidence_dir, evidence_type)
        os.makedirs(type_dir, exist_ok=True)

        # Create timestamped filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        cmd_str = command if isinstance(command, str) else ' '.join(command)
        safe_name = ''.join(c if c.isalnum() else '_' for c in cmd_str)[:50]  # Sanitize and limit length
        dest_path = os.path.join(type_dir, f"{timestamp}_command_{safe_name}.txt")

        try:
            # Run command and capture output
            logger.info(f"Running command: {cmd_str}")
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                env=env
            )

            # Format output with metadata
            output = (
                f"Command: {cmd_str}\n"
                f"Exit Code: {result.returncode}\n"
                f"Executed At: {datetime.datetime.now().isoformat()}\n"
                f"Shell: {shell}\n"
                f"Timeout: {timeout}\n"
                f"Working Directory: {working_dir or 'default'}\n"
                f"\n--- STANDARD OUTPUT ---\n{result.stdout}\n"
                f"\n--- STANDARD ERROR ---\n{result.stderr}\n"
            )

            # Write output to file
            with open(dest_path, 'w') as f:
                f.write(output)

            # Set file permissions
            os.chmod(dest_path, 0o400)  # Read-only

            # Calculate hash
            file_hash = calculate_hash(dest_path)

            # Generate unique evidence ID
            evidence_id = f"EV-{self.incident_id}-{timestamp}-cmd-{safe_name[:10]}"

            # Register with forensic evidence tracker if available
            if FORENSIC_UTILS_AVAILABLE:
                try:
                    registered_id = register_evidence(
                        case_id=self.incident_id,
                        evidence_description=description or f"Command output: {cmd_str}",
                        evidence_type=evidence_type,
                        source_identifier=cmd_str,
                        acquisition_method="command_execution",
                        acquisition_tool="incident_response_kit.collect_evidence",
                        analyst=self.analyst,
                        file_path=dest_path,
                        initial_hash_algorithm=DEFAULT_HASH_ALGORITHM,
                        classification=self.classification,
                        retention_period=self.retention_period
                    )
                    if registered_id:
                        evidence_id = registered_id
                except Exception as e:
                    logger.warning(f"Failed to register evidence with tracking system: {e}")

            # Create evidence metadata file
            metadata_path = f"{dest_path}.metadata.json"
            metadata = {
                "evidence_id": evidence_id,
                "incident_id": self.incident_id,
                "description": description or f"Command output: {cmd_str}",
                "evidence_type": evidence_type,
                "source_identifier": cmd_str,
                "acquisition_method": "command_execution",
                "acquisition_tool": "incident_response_kit.collect_evidence",
                "analyst": self.analyst,
                "acquisition_timestamp": datetime.datetime.now().isoformat(),
                "command": cmd_str,
                "exit_code": result.returncode,
                "shell": shell,
                "hash": {DEFAULT_HASH_ALGORITHM: file_hash},
                "classification": self.classification
            }

            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            os.chmod(metadata_path, 0o400)  # Read-only

            # Create evidence object
            evidence = Evidence(
                evidence_id=evidence_id,
                incident_id=self.incident_id,
                path=dest_path,
                evidence_type=evidence_type,
                description=description or f"Command output: {cmd_str}",
                hash_value=file_hash,
                hash_algorithm=DEFAULT_HASH_ALGORITHM,
                analyst=self.analyst,
                metadata={
                    "command": cmd_str,
                    "exit_code": result.returncode,
                    "shell": shell,
                    "timeout": timeout,
                    "collection_method": "command_execution"
                }
            )

            # Add to collection and update manifest
            self.collected_evidence.append(evidence)
            self._add_to_manifest(evidence)

            logger.info(f"Collected command output evidence {evidence_id}")
            return evidence_id

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
            return None
        except Exception as e:
            logger.error(f"Error collecting command output: {e}", exc_info=True)
            # Clean up if collection failed
            if os.path.exists(dest_path):
                os.unlink(dest_path)
            return None

    def create_evidence_package(
        self,
        output_path: Optional[str] = None,
        format: str = "zip",
        include_chain: bool = True,
        encrypt: bool = False,
        password: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a package of all collected evidence.

        Args:
            output_path: Where to store the package (default: evidence dir)
            format: Package format (zip, tar, or directory)
            include_chain: Whether to include chain of custody
            encrypt: Whether to encrypt the package
            password: Password for encryption if encrypt is True

        Returns:
            Path to the created package if successful, None otherwise
        """
        if not self.collected_evidence:
            logger.error("No evidence has been collected to package")
            return None

        # Use forensic evidence tracker if available
        if FORENSIC_UTILS_AVAILABLE and format in ["zip", "tar.gz", "7z"]:
            try:
                evidence_ids = [item.evidence_id for item in self.collected_evidence]
                container_path = create_evidence_container(
                    case_id=self.incident_id,
                    evidence_ids=evidence_ids,
                    analyst=self.analyst,
                    output_path=output_path,
                    container_type=format,
                    include_metadata=True,
                    encryption_password=password if encrypt else None
                )
                if container_path:
                    logger.info(f"Created evidence package at {container_path}")
                    return container_path
                else:
                    raise Exception("Failed to create evidence container")
            except Exception as e:
                logger.error(f"Error creating evidence package using tracker: {e}")
                # Fall back to manual packaging

        # Set default output path if not provided
        if not output_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.evidence_dir, f"evidence_package_{timestamp}.{format}")

        try:
            # Create temporary directory for packaging
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create directory structure
                evidence_dir = os.path.join(temp_dir, "evidence")
                os.makedirs(evidence_dir)

                metadata_dir = os.path.join(temp_dir, "metadata")
                os.makedirs(metadata_dir)

                # Copy evidence files
                for evidence in self.collected_evidence:
                    src_path = evidence.path
                    if os.path.exists(src_path):
                        if os.path.isdir(src_path):
                            dest_dir = os.path.join(evidence_dir, evidence.evidence_id)
                            shutil.copytree(src_path, dest_dir)
                        else:
                            dest_file = os.path.join(
                                evidence_dir,
                                f"{evidence.evidence_id}_{os.path.basename(src_path)}"
                            )
                            shutil.copy2(src_path, dest_file)

                # Create package metadata
                package_metadata = {
                    "incident_id": self.incident_id,
                    "created_at": datetime.datetime.now().isoformat(),
                    "created_by": self.analyst,
                    "evidence_count": len(self.collected_evidence),
                    "evidence_items": [e.to_dict() for e in self.collected_evidence],
                    "package_format": format
                }

                with open(os.path.join(metadata_dir, "package_manifest.json"), 'w') as f:
                    json.dump(package_metadata, f, indent=2)

                # Include chain of custody if requested
                if include_chain and FORENSIC_UTILS_AVAILABLE:
                    # Collect chain of custody for each evidence item
                    chain_of_custody = {}
                    for evidence in self.collected_evidence:
                        try:
                            coc = get_chain_of_custody(self.incident_id, evidence.evidence_id)
                            if coc:
                                chain_of_custody[evidence.evidence_id] = coc
                        except Exception as e:
                            logger.warning(f"Could not get chain of custody for {evidence.evidence_id}: {e}")

                    if chain_of_custody:
                        with open(os.path.join(metadata_dir, "chain_of_custody.json"), 'w') as f:
                            json.dump(chain_of_custody, f, indent=2)

                # Create package based on format
                if format == "zip":
                    import zipfile

                    if encrypt and password:
                        try:
                            import pyminizip
                            # Create encrypted zip
                            file_list = []
                            for root, _, files in os.walk(temp_dir):
                                for file in files:
                                    abs_path = os.path.join(root, file)
                                    rel_path = os.path.relpath(abs_path, temp_dir)
                                    file_list.append((abs_path, rel_path))

                            pyminizip.compress_multiple(
                                [f[0] for f in file_list],
                                [f[1] for f in file_list],
                                output_path,
                                password,
                                9  # Compression level
                            )
                        except ImportError:
                            logger.warning("pyminizip not available, creating unencrypted zip")
                            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                                for root, _, files in os.walk(temp_dir):
                                    for file in files:
                                        abs_path = os.path.join(root, file)
                                        rel_path = os.path.relpath(abs_path, temp_dir)
                                        zipf.write(abs_path, rel_path)
                    else:
                        # Create standard zip
                        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                            for root, _, files in os.walk(temp_dir):
                                for file in files:
                                    abs_path = os.path.join(root, file)
                                    rel_path = os.path.relpath(abs_path, temp_dir)
                                    zipf.write(abs_path, rel_path)

                elif format == "tar":
                    import tarfile
                    with tarfile.open(output_path, "w:gz") as tar:
                        tar.add(temp_dir, arcname="evidence_package")

                elif format == "directory":
                    if os.path.exists(output_path):
                        shutil.rmtree(output_path)
                    shutil.copytree(temp_dir, output_path)

                logger.info(f"Created evidence package at {output_path}")
                return output_path

        except Exception as e:
            logger.error(f"Error creating evidence package: {e}", exc_info=True)
            return None

    def verify_evidence_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of all collected evidence.

        Returns:
            Dictionary with verification results
        """
        results = {
            "verified": [],
            "modified": [],
            "missing": [],
            "errors": []
        }

        for evidence in self.collected_evidence:
            if not os.path.exists(evidence.path):
                results["missing"].append({
                    "evidence_id": evidence.evidence_id,
                    "path": evidence.path,
                    "error": "Evidence file not found"
                })
                continue

            try:
                # Handle directory evidence with integrity baseline
                if os.path.isdir(evidence.path) and LIVE_RESPONSE_AVAILABLE:
                    baseline_path = evidence.metadata.get("integrity_baseline")
                    if baseline_path and os.path.exists(baseline_path):
                        integrity_verified, integrity_details = verify_directory_integrity(
                            evidence_dir=evidence.path,
                            baseline_path=baseline_path
                        )

                        if integrity_verified:
                            results["verified"].append({
                                "evidence_id": evidence.evidence_id,
                                "path": evidence.path,
                                "type": "directory",
                                "details": integrity_details.get("summary", {})
                            })
                        else:
                            results["modified"].append({
                                "evidence_id": evidence.evidence_id,
                                "path": evidence.path,
                                "type": "directory",
                                "details": integrity_details
                            })
                        continue

                # For file evidence, check hash if available
                if os.path.isfile(evidence.path) and evidence.hash_value:
                    current_hash = calculate_hash(evidence.path, evidence.hash_algorithm)

                    if current_hash == evidence.hash_value:
                        results["verified"].append({
                            "evidence_id": evidence.evidence_id,
                            "path": evidence.path,
                            "type": "file"
                        })
                    else:
                        results["modified"].append({
                            "evidence_id": evidence.evidence_id,
                            "path": evidence.path,
                            "type": "file",
                            "original_hash": evidence.hash_value,
                            "current_hash": current_hash
                        })
                # Use evidence tracker for verification if available
                elif FORENSIC_UTILS_AVAILABLE:
                    try:
                        verified = verify_evidence_integrity(
                            case_id=self.incident_id,
                            evidence_id=evidence.evidence_id,
                            analyst=self.analyst,
                            file_path=evidence.path
                        )

                        if verified:
                            results["verified"].append({
                                "evidence_id": evidence.evidence_id,
                                "path": evidence.path,
                                "type": "tracked"
                            })
                        else:
                            results["modified"].append({
                                "evidence_id": evidence.evidence_id,
                                "path": evidence.path,
                                "type": "tracked",
                                "error": "Failed integrity verification"
                            })
                    except Exception as e:
                        results["errors"].append({
                            "evidence_id": evidence.evidence_id,
                            "path": evidence.path,
                            "error": f"Error verifying with tracker: {str(e)}"
                        })
                else:
                    # Can't verify without hash
                    results["errors"].append({
                        "evidence_id": evidence.evidence_id,
                        "path": evidence.path,
                        "error": "No hash or tracking available for verification"
                    })
            except Exception as e:
                results["errors"].append({
                    "evidence_id": evidence.evidence_id,
                    "path": evidence.path,
                    "error": str(e)
                })

        # Add summary
        results["summary"] = {
            "total": len(self.collected_evidence),
            "verified": len(results["verified"]),
            "modified": len(results["modified"]),
            "missing": len(results["missing"]),
            "errors": len(results["errors"])
        }

        return results

    def _create_case_manifest(self) -> None:
        """Create a manifest file for this case."""
        manifest_path = os.path.join(self.evidence_dir, "case_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(self.collection_metadata, f, indent=2)

        # Set restrictive permissions
        os.chmod(manifest_path, 0o600)

    def _update_case_manifest(self) -> None:
        """Update the case manifest with current collection metadata."""
        manifest_path = os.path.join(self.evidence_dir, "case_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(self.collection_metadata, f, indent=2)

    def _add_to_manifest(self, evidence: Evidence) -> None:
        """Add evidence to the case manifest."""
        evidence_dict = evidence.to_dict()
        self.collection_metadata["evidence_items"].append(evidence_dict)
        self._update_case_manifest()

    def _get_hostname(self) -> str:
        """Get system hostname safely."""
        try:
            return os.uname().nodename
        except AttributeError:
            # Fallback for Windows
            try:
                import socket
                return socket.gethostname()
            except:
                return "unknown"


def collect_evidence(
    incident_id: str,
    target: str,
    output_dir: Optional[str] = None,
    collect: Optional[List[str]] = None,
    analyst: Optional[str] = None
) -> Dict[str, Any]:
    """
    Collect evidence from a target system.

    This function provides the main entry point for evidence collection,
    allowing other modules to invoke collection operations.

    Args:
        incident_id: Identifier for the incident
        target: Target to collect from (hostname, IP, file path)
        output_dir: Where to store collected evidence
        collect: List of evidence types to collect
        analyst: Person collecting evidence

    Returns:
        Dictionary with collection results
    """
    results = {
        "status": "initialized",
        "incident_id": incident_id,
        "target": target,
        "collected_evidence": [],
        "errors": []
    }

    try:
        # Initialize collector
        collector = EvidenceCollector(
            incident_id=incident_id,
            evidence_dir=output_dir,
            analyst=analyst
        )

        # Default to a basic set of evidence types if none specified
        if not collect:
            collect = ["logs", "system_info", "process_list", "network_connections"]

        # Track what was successfully collected
        collected = []

        # Collect based on evidence type
        for evidence_type in collect:
            try:
                # System info
                if evidence_type == "system_info":
                    if sys.platform == "win32":
                        collector.collect_command_output(
                            command=["systeminfo"],
                            evidence_type=EvidenceType.SYSTEM_STATE,
                            description="System information"
                        )
                    else:
                        collector.collect_command_output(
                            command=["uname", "-a"],
                            evidence_type=EvidenceType.SYSTEM_STATE,
                            description="System kernel information"
                        )
                        collector.collect_command_output(
                            command=["cat", "/etc/os-release"],
                            evidence_type=EvidenceType.SYSTEM_STATE,
                            description="OS version information"
                        )
                    collected.append(evidence_type)

                # Process list
                elif evidence_type == "process_list":
                    if sys.platform == "win32":
                        collector.collect_command_output(
                            command=["tasklist", "/v"],
                            evidence_type=EvidenceType.SYSTEM_STATE,
                            description="Running process list"
                        )
                    else:
                        collector.collect_command_output(
                            command=["ps", "aux"],
                            evidence_type=EvidenceType.SYSTEM_STATE,
                            description="Running process list"
                        )
                    collected.append(evidence_type)

                # Network connections
                elif evidence_type == "network_connections":
                    if sys.platform == "win32":
                        collector.collect_command_output(
                            command=["netstat", "-ano"],
                            evidence_type=EvidenceType.NETWORK_CAPTURE,
                            description="Active network connections"
                        )
                    else:
                        collector.collect_command_output(
                            command=["netstat", "-tuplan"],
                            evidence_type=EvidenceType.NETWORK_CAPTURE,
                            description="Active network connections"
                        )
                    collected.append(evidence_type)

                # Logs
                elif evidence_type == "logs":
                    if sys.platform == "win32":
                        # Windows Event logs collected differently
                        pass
                    else:
                        # Common log files on Unix-like systems
                        log_paths = [
                            "/var/log/syslog",
                            "/var/log/auth.log",
                            "/var/log/secure",
                            "/var/log/messages"
                        ]

                        for log_path in log_paths:
                            if os.path.exists(log_path) and os.access(log_path, os.R_OK):
                                collector.collect_file(
                                    file_path=log_path,
                                    evidence_type=EvidenceType.LOG_FILE,
                                    description=f"System log file: {os.path.basename(log_path)}"
                                )
                    collected.append(evidence_type)

                # Other evidence types can be added here
                # elif evidence_type == "memory":
                #   ...

                else:
                    results["errors"].append(f"Unknown evidence type: {evidence_type}")

            except Exception as e:
                results["errors"].append(f"Error collecting {evidence_type}: {str(e)}")

        # Verify evidence integrity
        verification_results = collector.verify_evidence_integrity()

        # Update results
        results.update({
            "status": "completed" if collected else "no_evidence_collected",
            "collector": collector.analyst,
            "evidence_dir": str(collector.evidence_dir),
            "collected": collected,
            "collected_evidence": [e.to_dict() for e in collector.collected_evidence],
            "verification": verification_results,
            "timestamp": datetime.datetime.now().isoformat()
        })

    except Exception as e:
        results.update({
            "status": "error",
            "error_message": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        })
        logger.error(f"Error during evidence collection: {e}", exc_info=True)

    return results


def calculate_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Calculate cryptographic hash for a file.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm to use

    Returns:
        Hash value as a hexadecimal string
    """
    # Use helper function if available
    if FORENSIC_UTILS_AVAILABLE:
        try:
            return calculate_file_hash(file_path, algorithm)
        except:
            pass

    # Fallback implementation
    hash_func = getattr(hashlib, algorithm.lower())()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def main():
    """
    Main function for command-line operation.

    This provides a standalone command-line evidence collection tool.
    """
    parser = argparse.ArgumentParser(description="Digital Evidence Collection Tool")

    # Case and basic options
    parser.add_argument("--incident-id", required=True, help="Incident identifier")
    parser.add_argument("--output-dir", help="Output directory for evidence")
    parser.add_argument("--analyst", help="Name of the person collecting evidence")
    parser.add_argument("--classification", default="Confidential",
                       help="Security classification of evidence")

    # Collection options
    collection_group = parser.add_argument_group("Evidence Collection")
    collection_group.add_argument("--system-info", action="store_true",
                                help="Collect system information")
    collection_group.add_argument("--process-list", action="store_true",
                                help="Collect process information")
    collection_group.add_argument("--network", action="store_true",
                                help="Collect network evidence")
    collection_group.add_argument("--logs", action="store_true",
                                help="Collect log files")
    collection_group.add_argument("--memory", action="store_true",
                                help="Collect memory evidence")
    collection_group.add_argument("--file", action="append",
                                help="Specific file to collect (can be used multiple times)")
    collection_group.add_argument("--directory", action="append",
                                help="Directory to collect (can be used multiple times)")
    collection_group.add_argument("--command", action="append",
                                help="Command to run and collect output (can be used multiple times)")
    collection_group.add_argument("--target",
                                help="Target system to collect from (default: local)")

    # Package options
    package_group = parser.add_argument_group("Evidence Packaging")
    package_group.add_argument("--create-package", action="store_true",
                              help="Create evidence package")
    package_group.add_argument("--package-format", choices=["zip", "tar", "directory"],
                              default="zip", help="Format for evidence package")
    package_group.add_argument("--package-output",
                              help="Output path for package")
    package_group.add_argument("--encrypt", action="store_true",
                              help="Encrypt the package")
    package_group.add_argument("--password",
                              help="Password for encrypted package")

    args = parser.parse_args()

    # Initialize collector
    collector = EvidenceCollector(
        incident_id=args.incident_id,
        evidence_dir=args.output_dir,
        analyst=args.analyst,
        classification=args.classification
    )

    print(f"Starting evidence collection for incident {args.incident_id}")
    print(f"Evidence will be stored in {collector.evidence_dir}")

    # Track if we've collected anything
    collected = False

    # Process collection requests
    if args.system_info:
        print("Collecting system information...")
        if sys.platform == "win32":
            collector.collect_command_output(
                command=["systeminfo"],
                evidence_type=EvidenceType.SYSTEM_STATE,
                description="System information"
            )
        else:
            collector.collect_command_output(
                command=["uname", "-a"],
                evidence_type=EvidenceType.SYSTEM_STATE,
                description="System kernel information"
            )
            if os.path.exists("/etc/os-release"):
                collector.collect_command_output(
                    command=["cat", "/etc/os-release"],
                    evidence_type=EvidenceType.SYSTEM_STATE,
                    description="OS version information"
                )
        collected = True

    if args.process_list:
        print("Collecting process information...")
        if sys.platform == "win32":
            collector.collect_command_output(
                command=["tasklist", "/v"],
                evidence_type=EvidenceType.SYSTEM_STATE,
                description="Running process list"
            )
        else:
            collector.collect_command_output(
                command=["ps", "aux"],
                evidence_type=EvidenceType.SYSTEM_STATE,
                description="Running process list"
            )

            # Additional process details on Unix systems
            if os.path.exists("/usr/sbin/lsof") and os.access("/usr/sbin/lsof", os.X_OK):
                collector.collect_command_output(
                    command=["lsof", "-n"],
                    evidence_type=EvidenceType.SYSTEM_STATE,
                    description="Open files and processes"
                )

            if os.path.exists("/sbin/lsmod") and os.access("/sbin/lsmod", os.X_OK):
                collector.collect_command_output(
                    command=["lsmod"],
                    evidence_type=EvidenceType.SYSTEM_STATE,
                    description="Loaded kernel modules"
                )
        collected = True

    if args.network:
        print("Collecting network information...")
        if sys.platform == "win32":
            collector.collect_command_output(
                command=["netstat", "-ano"],
                evidence_type=EvidenceType.NETWORK_CAPTURE,
                description="Active network connections"
            )
        else:
            collector.collect_command_output(
                command=["netstat", "-tuplan"],
                evidence_type=EvidenceType.NETWORK_CAPTURE,
                description="Active network connections"
            )

            # Additional network details on Unix systems
            if os.path.exists("/sbin/ifconfig") and os.access("/sbin/ifconfig", os.X_OK):
                collector.collect_command_output(
                    command=["ifconfig", "-a"],
                    evidence_type=EvidenceType.NETWORK_CAPTURE,
                    description="Network interface configuration"
                )
            elif os.path.exists("/sbin/ip") and os.access("/sbin/ip", os.X_OK):
                collector.collect_command_output(
                    command=["ip", "addr"],
                    evidence_type=EvidenceType.NETWORK_CAPTURE,
                    description="Network interface configuration"
                )

            if os.path.exists("/sbin/route") and os.access("/sbin/route", os.X_OK):
                collector.collect_command_output(
                    command=["route", "-n"],
                    evidence_type=EvidenceType.NETWORK_CAPTURE,
                    description="Routing table"
                )

            if os.path.exists("/usr/sbin/arp") and os.access("/usr/sbin/arp", os.X_OK):
                collector.collect_command_output(
                    command=["arp", "-a"],
                    evidence_type=EvidenceType.NETWORK_CAPTURE,
                    description="ARP cache"
                )

            # Attempt network capture if tcpdump is available
            if os.path.exists("/usr/sbin/tcpdump") and os.access("/usr/sbin/tcpdump", os.X_OK):
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                capture_file = os.path.join(collector.evidence_dir, f"network_capture_{timestamp}.pcap")

                print("Capturing network traffic (10 second sample)...")
                try:
                    # Run tcpdump for 10 seconds
                    process = subprocess.Popen(
                        ["tcpdump", "-i", "any", "-s", "0", "-w", capture_file],
                        stderr=subprocess.PIPE
                    )

                    # Wait for 10 seconds
                    import time
                    time.sleep(10)

                    # Stop tcpdump
                    process.terminate()
                    process.wait(timeout=5)

                    if os.path.exists(capture_file) and os.path.getsize(capture_file) > 0:
                        collector.collect_file(
                            file_path=capture_file,
                            evidence_type=EvidenceType.NETWORK_CAPTURE,
                            description="Network traffic capture (10 second sample)"
                        )
                except Exception as e:
                    print(f"Network capture failed: {e}")

        collected = True

    if args.logs:
        print("Collecting log files...")
        if sys.platform == "win32":
            # Windows Event logs
            try:
                log_dir = os.path.join(collector.evidence_dir, "event_logs")
                os.makedirs(log_dir, exist_ok=True)

                # Export Windows Event logs
                for log_name in ["System", "Application", "Security"]:
                    output_file = os.path.join(log_dir, f"{log_name}.evtx")
                    collector.collect_command_output(
                        command=["wevtutil", "epl", log_name, output_file],
                        evidence_type=EvidenceType.LOG_FILE,
                        description=f"{log_name} event log"
                    )
            except Exception as e:
                print(f"Failed to collect Windows event logs: {e}")
        else:
            # Unix-like systems have log files
            log_paths = [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages",
                "/var/log/dmesg"
            ]

            for log_path in log_paths:
                if os.path.exists(log_path) and os.access(log_path, os.R_OK):
                    collector.collect_file(
                        file_path=log_path,
                        evidence_type=EvidenceType.LOG_FILE,
                        description=f"System log file: {os.path.basename(log_path)}"
                    )
        collected = True

    # Handle memory acquisition if requested
    if args.memory:
        print("Attempting memory acquisition...")
        if sys.platform == "win32":
            # Windows memory acquisition
            try:
                # Check for winpmem or other tools
                winpmem_path = shutil.which("winpmem.exe")
                if winpmem_path:
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    memory_file = os.path.join(collector.evidence_dir, f"memory_dump_{timestamp}.raw")

                    collector.collect_command_output(
                        command=[winpmem_path, memory_file],
                        evidence_type=EvidenceType.MEMORY_DUMP,
                        description="Full memory dump using winpmem",
                        timeout=3600  # Allow up to an hour for memory dumps
                    )
                    collected = True
                else:
                    print("Memory acquisition tool not found (winpmem.exe)")
            except Exception as e:
                print(f"Memory acquisition failed: {e}")
        else:
            # Linux/macOS memory acquisition
            memory_tools = [
                "/usr/bin/avml",  # Linux memory acquisition
                "/usr/sbin/lime-commander",  # LiME memory acquisition tool
                "/usr/bin/osxpmem"  # macOS memory acquisition
            ]

            memory_tool = None
            for tool in memory_tools:
                if os.path.exists(tool) and os.access(tool, os.X_OK):
                    memory_tool = tool
                    break

            if memory_tool:
                try:
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    memory_file = os.path.join(collector.evidence_dir, f"memory_dump_{timestamp}.raw")

                    # Use appropriate command based on the tool
                    cmd = [memory_tool]
                    if os.path.basename(memory_tool) == "avml":
                        cmd.append(memory_file)
                    else:
                        cmd.extend(["-o", memory_file])

                    print(f"Running {memory_tool} to capture memory...")
                    collector.collect_command_output(
                        command=cmd,
                        evidence_type=EvidenceType.MEMORY_DUMP,
                        description=f"Memory acquisition using {os.path.basename(memory_tool)}",
                        timeout=3600  # Allow up to an hour for memory dumps
                    )
                    collected = True
                except Exception as e:
                    print(f"Memory acquisition failed: {e}")
            else:
                print("No memory acquisition tools found")

    # Collect specific files if requested
    if args.file:
        for file_path in args.file:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                print(f"Collecting file: {file_path}")
                collector.collect_file(
                    file_path=file_path,
                    evidence_type=EvidenceType.CONFIGURATION,
                    description=f"User-specified file: {os.path.basename(file_path)}"
                )
                collected = True
            else:
                print(f"File not found or not accessible: {file_path}")

    # Collect directories if requested
    if args.directory:
        for dir_path in args.directory:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                print(f"Collecting directory: {dir_path}")
                collector.collect_directory(
                    directory_path=dir_path,
                    evidence_type=EvidenceType.CONFIGURATION,
                    description=f"User-specified directory: {os.path.basename(dir_path)}"
                )
                collected = True
            else:
                print(f"Directory not found or not accessible: {dir_path}")

    # Run and collect output from commands if requested
    if args.command:
        for cmd in args.command:
            print(f"Running command: {cmd}")
            collector.collect_command_output(
                command=cmd,
                evidence_type=EvidenceType.SYSTEM_STATE,
                description=f"User-specified command: {cmd}",
                shell=True
            )
            collected = True

    if not collected:
        print("No evidence was collected. Use options like --memory, --logs, --file, etc.")
        return 1

    # Verify evidence integrity
    print("\nVerifying evidence integrity...")
    verification_results = collector.verify_evidence_integrity()

    # Print verification summary
    print(f"\nEvidence verification summary:")
    print(f"  Total evidence items: {verification_results['summary']['total']}")
    print(f"  Verified: {verification_results['summary']['verified']}")
    print(f"  Modified: {verification_results['summary']['modified']}")
    print(f"  Missing: {verification_results['summary']['missing']}")
    print(f"  Errors: {verification_results['summary']['errors']}")

    if verification_results['summary']['modified'] > 0:
        print("\nWARNING: Some evidence items appear to have been modified!")
        for item in verification_results["modified"]:
            print(f"  - {item['evidence_id']}: {item['path']}")

    if verification_results['summary']['missing'] > 0:
        print("\nWARNING: Some evidence items are missing!")
        for item in verification_results["missing"]:
            print(f"  - {item['evidence_id']}: {item['path']}")

    # Create evidence package if requested
    if args.create_package:
        print("\nCreating evidence package...")
        package_path = collector.create_evidence_package(
            output_path=args.package_output,
            format=args.package_format,
            include_chain=True,
            encrypt=args.encrypt,
            password=args.password
        )

        if package_path:
            print(f"\nEvidence package created: {package_path}")
        else:
            print("\nFailed to create evidence package")
            return 1

    # Save verification results
    verification_path = os.path.join(collector.evidence_dir, "verification_results.json")
    with open(verification_path, 'w') as f:
        json.dump(verification_results, f, indent=2)

    print(f"\nEvidence collection for incident {args.incident_id} complete.")
    print(f"Evidence stored in: {collector.evidence_dir}")
    print(f"Total evidence items: {len(collector.collected_evidence)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
