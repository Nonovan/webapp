#!/usr/bin/env python3
"""
Evidence Collection Utility

This script provides a command-line interface for collecting, registering, and managing
digital evidence during security incident investigations. It handles evidence collection
from various sources while maintaining proper chain of custody and evidence integrity.

Features:
- Collection from multiple evidence sources (memory, disk, network, logs)
- Automatic evidence registration with metadata
- Cryptographic integrity verification
- Chain of custody tracking
- Secure evidence storage and handling
- Evidence container creation for transport
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
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("evidence_collector")

# Try to import required modules with fallbacks for minimal functionality
try:
    from admin.security.forensics.utils.evidence_tracker import (
        register_evidence,
        track_access,
        get_evidence_details,
        update_evidence_details,
        get_chain_of_custody,
        create_evidence_container,
        verify_evidence_integrity
    )
    EVIDENCE_TRACKING_AVAILABLE = True
except ImportError:
    logger.warning("Evidence tracking module not available, using minimal functionality")
    EVIDENCE_TRACKING_AVAILABLE = False

try:
    from admin.security.forensics.utils.file_utils import (
        secure_copy,
        get_file_metadata,
        set_file_read_only,
        create_file_evidence_record
    )
    FILE_UTILS_AVAILABLE = True
except ImportError:
    logger.warning("Forensic file utilities not available, using basic file operations")
    FILE_UTILS_AVAILABLE = False

try:
    from admin.security.forensics.live_response import (
        update_evidence_integrity_baseline,
        verify_evidence_integrity as verify_evidence_directory_integrity
    )
    LIVE_RESPONSE_AVAILABLE = True
except ImportError:
    logger.warning("Live response module not available")
    LIVE_RESPONSE_AVAILABLE = False

# Constants
DEFAULT_EVIDENCE_DIR = os.environ.get("FORENSICS_EVIDENCE_DIR", "/secure/evidence")
DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_CASE_PREFIX = "CASE"


class EvidenceCollector:
    """Evidence collection and management utility."""

    def __init__(self, case_id: str, evidence_dir: Optional[str] = None,
                 analyst: Optional[str] = None, retention_period: Optional[str] = None,
                 classification: str = "Confidential"):
        """
        Initialize the evidence collector.

        Args:
            case_id: Identifier for the case/incident
            evidence_dir: Base directory for evidence storage
            analyst: Name of the analyst performing collection
            retention_period: How long to retain the evidence
            classification: Security classification of the evidence
        """
        self.case_id = case_id
        self.evidence_dir = evidence_dir or os.path.join(DEFAULT_EVIDENCE_DIR, case_id)
        self.analyst = analyst or os.environ.get("USER", "unknown_analyst")
        self.retention_period = retention_period
        self.classification = classification
        self.collected_evidence = []

        # Ensure evidence directory exists
        os.makedirs(self.evidence_dir, exist_ok=True)

        # Set basic metadata about the collection
        self.collection_metadata = {
            "case_id": case_id,
            "started_at": datetime.datetime.now().isoformat(),
            "analyst": self.analyst,
            "hostname": os.uname().nodename,
            "classification": classification,
            "evidence_items": []
        }

        # Create case manifest
        self._create_case_manifest()

        logger.info(f"Initialized evidence collection for case {case_id} in {self.evidence_dir}")

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

    def _calculate_hash(self, file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
        """
        Calculate the hash of a file.

        Args:
            file_path: Path to the file
            algorithm: Hashing algorithm to use

        Returns:
            Hash digest as a hexadecimal string
        """
        hash_func = getattr(hashlib, algorithm.lower())()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    def collect_file(self, file_path: str, evidence_type: str,
                     description: Optional[str] = None) -> Optional[str]:
        """
        Collect and register a file as evidence.

        Args:
            file_path: Path to the file to collect
            evidence_type: Type of evidence (e.g., "log", "memory_dump", "disk_image")
            description: Description of the evidence

        Returns:
            Evidence ID if successful, None otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        # Create type-specific directory
        type_dir = os.path.join(self.evidence_dir, evidence_type)
        os.makedirs(type_dir, exist_ok=True)

        # Create timestamped filename to prevent collisions
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = os.path.basename(file_path)
        dest_path = os.path.join(type_dir, f"{timestamp}_{basename}")

        try:
            # If forensic file utilities are available, use them
            if FILE_UTILS_AVAILABLE:
                success = secure_copy(file_path, dest_path, verify_hash=True, read_only=True)
                if not success:
                    raise OSError(f"Secure copy failed for {file_path}")

                metadata = get_file_metadata(dest_path, include_extended=True)
                file_hash = metadata.get("hash", {}).get(DEFAULT_HASH_ALGORITHM)
            else:
                # Basic copy if specialized utilities aren't available
                shutil.copy2(file_path, dest_path)
                os.chmod(dest_path, 0o400)  # Read-only
                file_hash = self._calculate_hash(dest_path)

            # Register evidence in tracking system if available
            if EVIDENCE_TRACKING_AVAILABLE:
                evidence_id = register_evidence(
                    case_id=self.case_id,
                    evidence_description=description or f"File evidence: {basename}",
                    evidence_type=evidence_type,
                    source_identifier=file_path,
                    acquisition_method="file_copy",
                    acquisition_tool="collect_evidence.py",
                    analyst=self.analyst,
                    file_path=dest_path,
                    initial_hash_algorithm=DEFAULT_HASH_ALGORITHM,
                    classification=self.classification,
                    retention_period=self.retention_period
                )
            else:
                # Create basic evidence ID if tracking system not available
                timestamp_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                evidence_id = f"EV-{timestamp_id}-{basename}"

                # Create basic metadata file
                meta_path = f"{dest_path}.metadata.json"
                metadata = {
                    "evidence_id": evidence_id,
                    "case_id": self.case_id,
                    "description": description or f"File evidence: {basename}",
                    "evidence_type": evidence_type,
                    "source_identifier": file_path,
                    "acquisition_method": "file_copy",
                    "acquisition_tool": "collect_evidence.py",
                    "analyst": self.analyst,
                    "acquisition_timestamp": datetime.datetime.now().isoformat(),
                    "hash": {DEFAULT_HASH_ALGORITHM: file_hash},
                    "classification": self.classification
                }

                with open(meta_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                os.chmod(meta_path, 0o400)  # Read-only

            # Add to collected evidence list
            evidence_item = {
                "evidence_id": evidence_id,
                "description": description or f"File evidence: {basename}",
                "type": evidence_type,
                "path": dest_path,
                "original_path": file_path,
                "hash": {DEFAULT_HASH_ALGORITHM: file_hash},
                "collected_at": datetime.datetime.now().isoformat()
            }

            self.collected_evidence.append(evidence_item)
            self.collection_metadata["evidence_items"].append(evidence_item)
            self._update_case_manifest()

            logger.info(f"Collected evidence {evidence_id}: {basename} as {evidence_type}")
            return evidence_id

        except Exception as e:
            logger.error(f"Error collecting {file_path}: {str(e)}")
            # Clean up if collection failed
            if os.path.exists(dest_path):
                os.unlink(dest_path)
            return None

    def collect_directory(self, directory_path: str, evidence_type: str,
                          description: Optional[str] = None,
                          create_baseline: bool = True) -> Optional[str]:
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

        # Create timestamped directory name
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
                success, baseline_path = update_evidence_integrity_baseline(
                    evidence_dir=dest_dir,
                    hash_algorithm=DEFAULT_HASH_ALGORITHM,
                    case_id=self.case_id,
                    examiner=self.analyst
                )
                if not success:
                    logger.warning(f"Failed to create integrity baseline for {dest_dir}")

            # Register evidence in tracking system if available
            if EVIDENCE_TRACKING_AVAILABLE:
                evidence_id = register_evidence(
                    case_id=self.case_id,
                    evidence_description=description or f"Directory evidence: {basename}",
                    evidence_type=evidence_type,
                    source_identifier=directory_path,
                    acquisition_method="directory_copy",
                    acquisition_tool="collect_evidence.py",
                    analyst=self.analyst,
                    file_path=dest_dir,
                    classification=self.classification,
                    retention_period=self.retention_period
                )
            else:
                # Create basic evidence ID if tracking system not available
                timestamp_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                evidence_id = f"EV-{timestamp_id}-{basename}"

                # Create basic metadata file
                meta_path = os.path.join(dest_dir, "evidence_metadata.json")
                metadata = {
                    "evidence_id": evidence_id,
                    "case_id": self.case_id,
                    "description": description or f"Directory evidence: {basename}",
                    "evidence_type": evidence_type,
                    "source_identifier": directory_path,
                    "acquisition_method": "directory_copy",
                    "acquisition_tool": "collect_evidence.py",
                    "analyst": self.analyst,
                    "acquisition_timestamp": datetime.datetime.now().isoformat(),
                    "integrity_baseline": baseline_path,
                    "classification": self.classification
                }

                with open(meta_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                os.chmod(meta_path, 0o400)  # Read-only

            # Add to collected evidence list
            evidence_item = {
                "evidence_id": evidence_id,
                "description": description or f"Directory evidence: {basename}",
                "type": evidence_type,
                "path": dest_dir,
                "original_path": directory_path,
                "integrity_baseline": baseline_path,
                "collected_at": datetime.datetime.now().isoformat()
            }

            self.collected_evidence.append(evidence_item)
            self.collection_metadata["evidence_items"].append(evidence_item)
            self._update_case_manifest()

            logger.info(f"Collected directory evidence {evidence_id}: {basename} as {evidence_type}")
            return evidence_id

        except Exception as e:
            logger.error(f"Error collecting directory {directory_path}: {str(e)}")
            # Clean up if collection failed
            if os.path.exists(dest_dir):
                shutil.rmtree(dest_dir)
            return None

    def collect_command_output(self, command: Union[str, List[str]], evidence_type: str,
                              description: Optional[str] = None, shell: bool = False) -> Optional[str]:
        """
        Run a command and collect its output as evidence.

        Args:
            command: Command to run (string or list of arguments)
            evidence_type: Type of evidence
            description: Description of the evidence
            shell: Whether to run the command in a shell

        Returns:
            Evidence ID if successful, None otherwise
        """
        import subprocess

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
                text=True
            )

            # Write output to file
            with open(dest_path, 'w') as f:
                f.write(f"Command: {cmd_str}\n")
                f.write(f"Exit Code: {result.returncode}\n")
                f.write(f"Standard Output:\n{result.stdout}\n")
                f.write(f"Standard Error:\n{result.stderr}\n")

            # Set file permissions
            os.chmod(dest_path, 0o400)  # Read-only

            # Calculate hash
            file_hash = self._calculate_hash(dest_path)

            # Register evidence in tracking system if available
            if EVIDENCE_TRACKING_AVAILABLE:
                evidence_id = register_evidence(
                    case_id=self.case_id,
                    evidence_description=description or f"Command output: {cmd_str}",
                    evidence_type=evidence_type,
                    source_identifier=cmd_str,
                    acquisition_method="command_execution",
                    acquisition_tool="collect_evidence.py",
                    analyst=self.analyst,
                    file_path=dest_path,
                    initial_hash_algorithm=DEFAULT_HASH_ALGORITHM,
                    classification=self.classification,
                    retention_period=self.retention_period
                )
            else:
                # Create basic evidence ID if tracking system not available
                timestamp_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                evidence_id = f"EV-{timestamp_id}-command"

                # Create basic metadata file
                meta_path = f"{dest_path}.metadata.json"
                metadata = {
                    "evidence_id": evidence_id,
                    "case_id": self.case_id,
                    "description": description or f"Command output: {cmd_str}",
                    "evidence_type": evidence_type,
                    "source_identifier": cmd_str,
                    "acquisition_method": "command_execution",
                    "acquisition_tool": "collect_evidence.py",
                    "analyst": self.analyst,
                    "acquisition_timestamp": datetime.datetime.now().isoformat(),
                    "command": cmd_str,
                    "exit_code": result.returncode,
                    "shell": shell,
                    "hash": {DEFAULT_HASH_ALGORITHM: file_hash},
                    "classification": self.classification
                }

                with open(meta_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                os.chmod(meta_path, 0o400)  # Read-only

            # Add to collected evidence list
            evidence_item = {
                "evidence_id": evidence_id,
                "description": description or f"Command output: {cmd_str}",
                "type": evidence_type,
                "path": dest_path,
                "command": cmd_str,
                "exit_code": result.returncode,
                "hash": {DEFAULT_HASH_ALGORITHM: file_hash},
                "collected_at": datetime.datetime.now().isoformat()
            }

            self.collected_evidence.append(evidence_item)
            self.collection_metadata["evidence_items"].append(evidence_item)
            self._update_case_manifest()

            logger.info(f"Collected command output evidence {evidence_id}")
            return evidence_id

        except Exception as e:
            logger.error(f"Error collecting command output: {str(e)}")
            # Clean up if collection failed
            if os.path.exists(dest_path):
                os.unlink(dest_path)
            return None

    def create_evidence_package(self, output_path: Optional[str] = None,
                               format: str = "zip", include_chain: bool = True,
                               encrypt: bool = False, password: Optional[str] = None) -> Optional[str]:
        """
        Create an evidence package for all collected evidence.

        Args:
            output_path: Where to save the package (default: in evidence dir)
            format: Package format ("zip", "tar", or "directory")
            include_chain: Whether to include chain of custody
            encrypt: Whether to encrypt the package
            password: Encryption password if encrypting

        Returns:
            Path to the created package if successful, None otherwise
        """
        if not self.collected_evidence:
            logger.error("No evidence has been collected to package")
            return None

        # Use evidence_tracker if available
        if EVIDENCE_TRACKING_AVAILABLE and format in ["zip", "tar.gz", "7z"]:
            try:
                evidence_ids = [item["evidence_id"] for item in self.collected_evidence]
                container_path = create_evidence_container(
                    case_id=self.case_id,
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
                logger.error(f"Error creating evidence package using tracker: {str(e)}")
                # Fall back to manual packaging

        # Manual packaging if evidence_tracker not available or failed
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
                for item in self.collected_evidence:
                    src_path = item["path"]
                    if os.path.exists(src_path):
                        if os.path.isdir(src_path):
                            dest_dir = os.path.join(evidence_dir, item["evidence_id"])
                            shutil.copytree(src_path, dest_dir)
                        else:
                            dest_file = os.path.join(evidence_dir, f"{item['evidence_id']}_{os.path.basename(src_path)}")
                            shutil.copy2(src_path, dest_file)

                # Create package metadata
                package_metadata = {
                    "case_id": self.case_id,
                    "created_at": datetime.datetime.now().isoformat(),
                    "created_by": self.analyst,
                    "evidence_count": len(self.collected_evidence),
                    "evidence_items": self.collected_evidence,
                    "package_format": format
                }

                with open(os.path.join(metadata_dir, "package_manifest.json"), 'w') as f:
                    json.dump(package_metadata, f, indent=2)

                # Include chain of custody if requested
                if include_chain and EVIDENCE_TRACKING_AVAILABLE:
                    # Collect chain of custody for each evidence item
                    chain_of_custody = {}
                    for item in self.collected_evidence:
                        item_id = item["evidence_id"]
                        coc = get_chain_of_custody(self.case_id, item_id)
                        if coc:
                            chain_of_custody[item_id] = coc

                    if chain_of_custody:
                        with open(os.path.join(metadata_dir, "chain_of_custody.json"), 'w') as f:
                            json.dump(chain_of_custody, f, indent=2)

                # Create package based on format
                if format == "zip":
                    import zipfile
                    import tempfile

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
            logger.error(f"Error creating evidence package: {str(e)}")
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

        for item in self.collected_evidence:
            evidence_id = item.get("evidence_id")
            path = item.get("path")

            if not path or not os.path.exists(path):
                results["missing"].append({
                    "evidence_id": evidence_id,
                    "path": path,
                    "error": "Evidence file not found"
                })
                continue

            try:
                # Handle directory evidence with integrity baseline
                if os.path.isdir(path) and LIVE_RESPONSE_AVAILABLE and item.get("integrity_baseline"):
                    integrity_verified, integrity_details = verify_evidence_directory_integrity(
                        evidence_dir=path,
                        baseline_path=item.get("integrity_baseline")
                    )

                    if integrity_verified:
                        results["verified"].append({
                            "evidence_id": evidence_id,
                            "path": path,
                            "type": "directory",
                            "details": integrity_details.get("summary", {})
                        })
                    else:
                        results["modified"].append({
                            "evidence_id": evidence_id,
                            "path": path,
                            "type": "directory",
                            "details": integrity_details
                        })
                    continue

                # For file evidence, check hash if available
                if "hash" in item and DEFAULT_HASH_ALGORITHM in item["hash"]:
                    original_hash = item["hash"][DEFAULT_HASH_ALGORITHM]
                    current_hash = self._calculate_hash(path)

                    if current_hash == original_hash:
                        results["verified"].append({
                            "evidence_id": evidence_id,
                            "path": path,
                            "type": "file"
                        })
                    else:
                        results["modified"].append({
                            "evidence_id": evidence_id,
                            "path": path,
                            "type": "file",
                            "original_hash": original_hash,
                            "current_hash": current_hash
                        })
                # Use evidence tracker if no hash available but ID is
                elif EVIDENCE_TRACKING_AVAILABLE and evidence_id:
                    verified = verify_evidence_integrity(
                        case_id=self.case_id,
                        evidence_id=evidence_id,
                        analyst=self.analyst,
                        file_path=path
                    )

                    if verified:
                        results["verified"].append({
                            "evidence_id": evidence_id,
                            "path": path,
                            "type": "tracked"
                        })
                    else:
                        results["modified"].append({
                            "evidence_id": evidence_id,
                            "path": path,
                            "type": "tracked",
                            "error": "Failed integrity verification"
                        })
                else:
                    # Can't verify without hash or tracking
                    results["errors"].append({
                        "evidence_id": evidence_id,
                        "path": path,
                        "error": "No hash or tracking available for verification"
                    })

            except Exception as e:
                results["errors"].append({
                    "evidence_id": evidence_id,
                    "path": path,
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


def generate_case_id(prefix: str = DEFAULT_CASE_PREFIX) -> str:
    """
    Generate a unique case ID.

    Args:
        prefix: Prefix for the case ID

    Returns:
        Case ID string
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M")
    return f"{prefix}-{timestamp}"


def collect_system_info() -> Dict[str, Any]:
    """
    Collect basic system information.

    Returns:
        Dictionary with system information
    """
    import platform

    info = {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "time": datetime.datetime.now().isoformat(),
        "timezone": datetime.datetime.now().astimezone().tzname()
    }

    # Try to get network info
    try:
        import socket
        info["ip_addresses"] = []
        for interface in socket.getaddrinfo(socket.gethostname(), None):
            addr = interface[4][0]
            # Skip loopback addresses
            if not addr.startswith("127.") and not addr.startswith("::1"):
                info["ip_addresses"].append(addr)
    except:
        pass

    return info


def main():
    """Main function for the evidence collection script."""
    parser = argparse.ArgumentParser(description="Digital Evidence Collection Tool")

    # Case and basic options
    parser.add_argument("--case-id", help="Case identifier (generated if not provided)")
    parser.add_argument("--output-dir", help="Output directory for evidence")
    parser.add_argument("--analyst", help="Name of the person collecting evidence")
    parser.add_argument("--classification", default="Confidential", help="Security classification of evidence")

    # Collection options
    collection_group = parser.add_argument_group("Evidence Collection")
    collection_group.add_argument("--memory", action="store_true", help="Collect memory evidence")
    collection_group.add_argument("--filesystem", help="Collect files/directories as evidence")
    collection_group.add_argument("--logs", action="store_true", help="Collect log files")
    collection_group.add_argument("--network", action="store_true", help="Collect network evidence")
    collection_group.add_argument("--process-list", action="store_true", help="Collect process information")
    collection_group.add_argument("--file", action="append", help="Specific file to collect (can be used multiple times)")
    collection_group.add_argument("--directory", action="append", help="Directory to collect (can be used multiple times)")
    collection_group.add_argument("--command", action="append", help="Command to run and collect output (can be used multiple times)")

    # Package options
    package_group = parser.add_argument_group("Evidence Packaging")
    package_group.add_argument("--create-package", action="store_true", help="Create evidence package")
    package_group.add_argument("--package-format", choices=["zip", "tar", "directory"], default="zip",
                              help="Format for evidence package")
    package_group.add_argument("--package-output", help="Output path for package")
    package_group.add_argument("--encrypt", action="store_true", help="Encrypt the package")
    package_group.add_argument("--password", help="Password for encrypted package")

    args = parser.parse_args()

    # Generate or use provided case ID
    case_id = args.case_id or generate_case_id()

    # Initialize collector
    collector = EvidenceCollector(
        case_id=case_id,
        evidence_dir=args.output_dir,
        analyst=args.analyst,
        classification=args.classification
    )

    print(f"Starting evidence collection for case {case_id}")

    # Collect system information
    system_info = collect_system_info()
    system_info_path = os.path.join(collector.evidence_dir, "system_info.json")
    with open(system_info_path, 'w') as f:
        json.dump(system_info, f, indent=2)
    collector.collect_file(
        file_path=system_info_path,
        evidence_type="system_info",
        description="System information at collection start"
    )

    # Process collection requests
    collected = False

    # Collect memory if requested
    if args.memory:
        print("Collecting memory evidence...")

        # Determine if we have appropriate tools
        memory_tools = [
            "/usr/bin/avml",                  # Linux memory acquisition
            "/usr/sbin/lime-commander",       # LiME memory acquisition tool
            "/usr/bin/osxpmem",               # macOS memory acquisition
            "/usr/bin/memory-acquisition.py", # Custom memory tool
        ]

        memory_tool = None
        for tool in memory_tools:
            if os.path.exists(tool) and os.access(tool, os.X_OK):
                memory_tool = tool
                break

        if memory_tool:
            # Create memory dump file
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            memory_output = os.path.join(collector.evidence_dir, f"memory_{timestamp}.raw")

            try:
                # Run the memory acquisition tool
                print(f"Running {memory_tool} to capture memory...")
                cmd = [memory_tool, "-o", memory_output]

                if os.path.basename(memory_tool) == "avml":
                    cmd = [memory_tool, memory_output]
                elif os.path.basename(memory_tool) == "osxpmem":
                    cmd = [memory_tool, "-o", memory_output]

                result = collector.collect_command_output(
                    command=cmd,
                    evidence_type="memory",
                    description=f"Memory acquisition using {memory_tool}"
                )

                if result and os.path.exists(memory_output):
                    collector.collect_file(
                        file_path=memory_output,
                        evidence_type="memory",
                        description=f"Memory dump collected using {memory_tool}"
                    )
                    collected = True
            except Exception as e:
                logger.error(f"Memory collection failed: {str(e)}")
                print(f"Memory collection failed: {str(e)}")
        else:
            print("No memory acquisition tools found. Skipping memory collection.")

    # Collect process information if requested
    if args.process_list:
        print("Collecting process information...")

        # Determine command based on OS
        if sys.platform == "win32":
            cmd = ["tasklist", "/v"]
        else:  # Linux, macOS, etc.
            cmd = ["ps", "aux"]

        collector.collect_command_output(
            command=cmd,
            evidence_type="process_info",
            description="Running process list"
        )
        collected = True

        # Also collect additional process details
        if sys.platform != "win32":
            # Collect open files
            collector.collect_command_output(
                command=["lsof", "-n"],
                evidence_type="process_info",
                description="Open files and processes"
            )

            # Collect loaded kernel modules
            collector.collect_command_output(
                command=["lsmod"],
                evidence_type="process_info",
                description="Loaded kernel modules"
            )

    # Collect network information if requested
    if args.network:
        print("Collecting network information...")

        # Collect network connections
        if sys.platform == "win32":
            collector.collect_command_output(
                command=["netstat", "-ano"],
                evidence_type="network",
                description="Active network connections"
            )
        else:
            collector.collect_command_output(
                command=["netstat", "-tuplan"],
                evidence_type="network",
                description="Active network connections"
            )

            # Collect additional network information on Unix-like systems
            collector.collect_command_output(
                command=["ifconfig", "-a"],
                evidence_type="network",
                description="Network interface configuration"
            )

            collector.collect_command_output(
                command=["route", "-n"],
                evidence_type="network",
                description="Routing table"
            )

            collector.collect_command_output(
                command=["arp", "-a"],
                evidence_type="network",
                description="ARP cache"
            )

            # Attempt to capture network traffic if tcpdump is available
            if os.path.exists("/usr/sbin/tcpdump") and os.access("/usr/sbin/tcpdump", os.X_OK):
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                capture_file = os.path.join(collector.evidence_dir, f"network_capture_{timestamp}.pcap")

                print("Capturing network traffic (10 second sample)...")
                try:
                    import subprocess

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
                            evidence_type="network",
                            description="Network traffic capture (10 second sample)"
                        )
                except Exception as e:
                    logger.error(f"Network capture failed: {str(e)}")
                    print(f"Network capture failed: {str(e)}")

        collected = True

    # Collect log files if requested
    if args.logs:
        print("Collecting log files...")

        log_paths = []
        if sys.platform == "win32":
            # Windows Event logs are collected differently, using wevtutil
            collector.collect_command_output(
                command=["wevtutil", "epl", "System", os.path.join(collector.evidence_dir, "system.evtx")],
                evidence_type="logs",
                description="System event log"
            )
            collector.collect_command_output(
                command=["wevtutil", "epl", "Application", os.path.join(collector.evidence_dir, "application.evtx")],
                evidence_type="logs",
                description="Application event log"
            )
            collector.collect_command_output(
                command=["wevtutil", "epl", "Security", os.path.join(collector.evidence_dir, "security.evtx")],
                evidence_type="logs",
                description="Security event log"
            )
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
                    evidence_type="logs",
                    description=f"System log file: {os.path.basename(log_path)}"
                )

        collected = True

    # Collect specific files if requested
    if args.file:
        for file_path in args.file:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                print(f"Collecting file: {file_path}")
                collector.collect_file(
                    file_path=file_path,
                    evidence_type="file",
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
                    evidence_type="directory",
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
                evidence_type="command_output",
                description=f"User-specified command: {cmd}",
                shell=True
            )
            collected = True

    # Collect from filesystem path if specified
    if args.filesystem:
        path = args.filesystem
        if os.path.exists(path):
            print(f"Collecting from filesystem: {path}")
            if os.path.isfile(path):
                collector.collect_file(
                    file_path=path,
                    evidence_type="filesystem",
                    description=f"Filesystem evidence: {os.path.basename(path)}"
                )
            elif os.path.isdir(path):
                collector.collect_directory(
                    directory_path=path,
                    evidence_type="filesystem",
                    description=f"Filesystem evidence: {os.path.basename(path)}"
                )
            collected = True
        else:
            print(f"Filesystem path not found or not accessible: {path}")

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

    print(f"\nEvidence collection for case {case_id} complete.")
    print(f"Evidence stored in: {collector.evidence_dir}")
    print(f"Total evidence items: {len(collector.collected_evidence)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
