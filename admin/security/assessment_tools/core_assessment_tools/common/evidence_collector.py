"""
Evidence collection functionality for security assessment tools.

This module provides secure mechanisms for collecting, storing, and managing evidence
during security assessments. It ensures proper chain of custody, evidence integrity,
and secure storage of assessment findings evidence.

Features:
- Evidence collection for multiple types (screenshots, logs, configs, command output)
- Chain of custody tracking for all evidence actions
- Evidence integrity verification through cryptographic hashing
- Secure storage with proper access controls
- Evidence metadata management and search
- Evidence packaging for reporting
"""

import datetime
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union, BinaryIO, TextIO, cast, Generator

try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

from .data_types import Evidence
from .assessment_logging import get_assessment_logger, log_assessment_event

logger = logging.getLogger(__name__)

# Default configuration values
DEFAULT_EVIDENCE_BASE_DIR = os.environ.get("ASSESSMENT_EVIDENCE_DIR", "/tmp/assessment_evidence")
DEFAULT_EVIDENCE_PERMISSIONS = 0o700  # Owner read/write/execute only
DEFAULT_EVIDENCE_FILE_PERMISSIONS = 0o600  # Owner read/write only
DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_MAX_TEXT_SIZE = 1024 * 1024 * 5  # 5MB max for text evidence
DEFAULT_RETENTION_PERIOD = "90d"  # 90 days


class EvidenceType(str, Enum):
    """Types of evidence that can be collected."""

    SCREENSHOT = "screenshot"
    LOG = "log"
    CONFIG = "config"
    COMMAND_OUTPUT = "command_output"
    FILE = "file"
    NETWORK = "network"
    DATABASE = "database"
    TEXT = "text"


class EvidenceAction(str, Enum):
    """Types of actions that can be performed on evidence."""

    COLLECT = "collect"
    ACCESS = "access"
    MODIFY = "modify"
    VERIFY = "verify"
    EXPORT = "export"
    PACKAGE = "package"
    DELETE = "delete"


@dataclass
class CustodyEntry:
    """Chain of custody entry for evidence."""

    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    action: str = ""
    performed_by: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result


class EvidenceCollector:
    """
    Collects and manages evidence for security assessments.

    This class handles evidence collection, storage, and chain of custody
    tracking for different types of evidence like screenshots, logs,
    configuration files, and command output.
    """

    def __init__(
        self,
        assessment_id: str,
        target_id: str,
        assessor: str,
        evidence_base_dir: Optional[str] = None,
        retention_period: Optional[str] = None,
    ):
        """
        Initialize the evidence collector.

        Args:
            assessment_id: Unique identifier for the assessment
            target_id: Identifier for the target system
            assessor: Name or identifier of the person collecting evidence
            evidence_base_dir: Directory to store evidence, defaults to DEFAULT_EVIDENCE_BASE_DIR
            retention_period: How long to retain evidence, defaults to DEFAULT_RETENTION_PERIOD
        """
        self.assessment_id = assessment_id
        self.target_id = target_id
        self.assessor = assessor
        self.evidence_base_dir = evidence_base_dir or DEFAULT_EVIDENCE_BASE_DIR
        self.retention_period = retention_period or DEFAULT_RETENTION_PERIOD

        # Create a unique evidence directory for this assessment
        self.evidence_dir = os.path.join(
            self.evidence_base_dir,
            f"{assessment_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        # Set up logging
        self.logger = get_assessment_logger(f"evidence_collector_{assessment_id}")

        # Initialize evidence tracking
        self.evidence_items: List[Evidence] = []
        self.collected_evidence_paths: List[str] = []

        # Initialize directory structure
        self._initialize_evidence_directory()

        self.logger.info(f"Evidence collector initialized for assessment {assessment_id}")

    def _initialize_evidence_directory(self) -> None:
        """Create and secure the evidence directory structure."""
        try:
            # Create main evidence directory
            os.makedirs(self.evidence_dir, exist_ok=True)
            os.chmod(self.evidence_dir, DEFAULT_EVIDENCE_PERMISSIONS)

            # Create subdirectories for different evidence types
            for evidence_type in EvidenceType:
                type_dir = os.path.join(self.evidence_dir, evidence_type.value)
                os.makedirs(type_dir, exist_ok=True)
                os.chmod(type_dir, DEFAULT_EVIDENCE_PERMISSIONS)

            # Create metadata directory
            metadata_dir = os.path.join(self.evidence_dir, "metadata")
            os.makedirs(metadata_dir, exist_ok=True)
            os.chmod(metadata_dir, DEFAULT_EVIDENCE_PERMISSIONS)

            # Initialize evidence registry
            self._write_json_file(
                os.path.join(metadata_dir, "evidence_registry.json"),
                {
                    "assessment_id": self.assessment_id,
                    "target_id": self.target_id,
                    "created_at": datetime.datetime.now().isoformat(),
                    "created_by": self.assessor,
                    "evidence_items": [],
                    "retention_period": self.retention_period
                }
            )

            # Initialize chain of custody log
            self._write_json_file(
                os.path.join(metadata_dir, "chain_of_custody.json"),
                {
                    "assessment_id": self.assessment_id,
                    "entries": []
                }
            )

            self.logger.debug(f"Evidence directory initialized: {self.evidence_dir}")

        except (OSError, PermissionError) as e:
            self.logger.error(f"Failed to initialize evidence directory: {e}")
            raise

    def collect_screenshot(
        self,
        name: str,
        description: Optional[str] = None,
        source: Optional[Union[str, bytes, Path]] = None
    ) -> str:
        """
        Collect a screenshot as evidence.

        Args:
            name: Name of the screenshot
            description: Description of what the screenshot shows
            source: Path to existing screenshot file, or raw image data

        Returns:
            Evidence ID of the collected screenshot

        Raises:
            OSError: If screenshot cannot be saved
        """
        evidence_type = EvidenceType.SCREENSHOT

        # Create a unique ID for this evidence
        evidence_id = self._generate_evidence_id()

        # Determine file extension
        file_ext = ".png"
        if isinstance(source, str) and os.path.isfile(source):
            file_ext = os.path.splitext(source)[1] or file_ext

        # Create the evidence file path
        evidence_path = self._get_evidence_path(evidence_type, f"{evidence_id}{file_ext}")

        # Save the screenshot
        try:
            if source is None:
                # Try to capture screenshot directly if no source is provided
                if sys.platform == "darwin":
                    self._capture_macos_screenshot(evidence_path)
                elif sys.platform == "win32":
                    self._capture_windows_screenshot(evidence_path)
                elif sys.platform.startswith("linux"):
                    self._capture_linux_screenshot(evidence_path)
                else:
                    raise OSError(f"Automatic screenshot not supported on {sys.platform}")
            elif isinstance(source, (str, Path)) and os.path.isfile(str(source)):
                # Copy existing screenshot file
                shutil.copy2(str(source), evidence_path)
            elif isinstance(source, bytes) and HAS_PILLOW:
                # Save raw image data
                from io import BytesIO
                from PIL import Image
                Image.open(BytesIO(source)).save(evidence_path)
            else:
                raise ValueError("Unsupported screenshot source type")

            # Set proper permissions
            os.chmod(evidence_path, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Calculate hash for integrity verification
            file_hash = self._calculate_file_hash(evidence_path)

            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                title=name,
                description=description or f"Screenshot: {name}",
                evidence_type=evidence_type.value,
                file_path=evidence_path,
                collection_time=datetime.datetime.now(),
                collected_by=self.assessor,
                metadata={
                    "hash": file_hash,
                    "hash_algorithm": DEFAULT_HASH_ALGORITHM,
                    "platform": sys.platform,
                    "file_size": os.path.getsize(evidence_path),
                    "content_type": "image/" + file_ext.lstrip(".").lower()
                }
            )

            # Record evidence
            self._record_evidence(evidence)

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.COLLECT,
                details={"type": evidence_type.value, "name": name}
            )

            # Log collection
            self.logger.info(f"Collected screenshot evidence: {name} (ID: {evidence_id})")

            return evidence_id

        except Exception as e:
            self.logger.error(f"Failed to collect screenshot evidence {name}: {e}")
            if os.path.exists(evidence_path):
                os.unlink(evidence_path)
            raise

    def set_evidence_retention_period(self, evidence_id: str, retention_period: str) -> bool:
        """
        Set or update the retention period for specific evidence.

        Args:
            evidence_id: ID of the evidence
            retention_period: How long to retain the evidence (e.g., "90d", "1y")

        Returns:
            True if successful, False otherwise
        """
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            self.logger.warning(f"Evidence not found: {evidence_id}")
            return False

        metadata = evidence.metadata or {}
        old_retention = metadata.get("retention_period", self.retention_period)
        metadata["retention_period"] = retention_period

        # Update evidence
        evidence.metadata = metadata
        self._update_evidence(evidence)

        # Add chain of custody entry
        self._add_custody_entry(
            evidence_id=evidence_id,
            action="set_retention",
            details={
                "old_retention_period": old_retention,
                "new_retention_period": retention_period
            }
        )

        self.logger.info(f"Set retention period for evidence {evidence_id} to {retention_period}")
        return True

    def get_expired_evidence(self, current_time: Optional[datetime.datetime] = None) -> List[Evidence]:
        """
        Get list of evidence items that have exceeded their retention period.

        Args:
            current_time: Time to check against (defaults to now)

        Returns:
            List of expired evidence items
        """
        # Implementation would require retention period parsing logic
        # This is a placeholder for the concept
        pass

    def collect_file(
        self,
        file_path: Union[str, Path],
        evidence_type: Optional[EvidenceType] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
    ) -> str:
        """
        Collect a file as evidence.

        Args:
            file_path: Path to the file to collect
            evidence_type: Type of evidence if known, otherwise determined from file extension
            title: Title for this evidence
            description: Description of this evidence

        Returns:
            Evidence ID of the collected file

        Raises:
            OSError: If file cannot be read or saved
            ValueError: If file_path is not valid
        """
        if not os.path.isfile(file_path):
            raise ValueError(f"File not found: {file_path}")

        # Convert Path to string if needed
        file_path_str = str(file_path)

        # Determine evidence type if not provided
        if evidence_type is None:
            file_extension = os.path.splitext(file_path_str)[1].lower()
            if file_extension in (".log", ".txt"):
                evidence_type = EvidenceType.LOG
            elif file_extension in (".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml"):
                evidence_type = EvidenceType.CONFIG
            else:
                evidence_type = EvidenceType.FILE

        # Create a unique ID for this evidence
        evidence_id = self._generate_evidence_id()

        # Preserve file extension
        file_extension = os.path.splitext(file_path_str)[1]

        # Create the evidence file path
        evidence_file_name = f"{evidence_id}{file_extension}"
        evidence_path = self._get_evidence_path(evidence_type, evidence_file_name)

        try:
            # Copy the file to evidence storage
            shutil.copy2(file_path_str, evidence_path)

            # Set proper permissions
            os.chmod(evidence_path, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Calculate hash for integrity verification
            file_hash = self._calculate_file_hash(evidence_path)

            # Detect content type
            content_type = self._detect_content_type(file_path_str)

            # Use filename as title if not provided
            if not title:
                title = os.path.basename(file_path_str)

            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                title=title,
                description=description or f"File collected from {file_path_str}",
                evidence_type=evidence_type.value,
                file_path=evidence_path,
                collection_time=datetime.datetime.now(),
                collected_by=self.assessor,
                metadata={
                    "hash": file_hash,
                    "hash_algorithm": DEFAULT_HASH_ALGORITHM,
                    "original_path": file_path_str,
                    "file_size": os.path.getsize(evidence_path),
                    "content_type": content_type
                }
            )

            # Record evidence
            self._record_evidence(evidence)

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.COLLECT,
                details={
                    "type": evidence_type.value,
                    "original_path": file_path_str,
                    "name": title
                }
            )

            # Log collection
            self.logger.info(f"Collected file evidence: {title} (ID: {evidence_id})")

            return evidence_id

        except Exception as e:
            self.logger.error(f"Failed to collect file evidence {file_path_str}: {e}")
            if os.path.exists(evidence_path):
                os.unlink(evidence_path)
            raise

    def collect_command_output(
        self,
        command: Union[str, List[str]],
        title: Optional[str] = None,
        description: Optional[str] = None,
        shell: bool = False,
        timeout: int = 60,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        include_stderr: bool = True
    ) -> str:
        """
        Collect command output as evidence.

        Args:
            command: Command to execute (string or list of arguments)
            title: Title for this evidence
            description: Description of this evidence
            shell: Whether to execute command in a shell
            timeout: Timeout in seconds
            working_dir: Working directory for command execution
            env: Environment variables for command execution
            include_stderr: Whether to include stderr in output

        Returns:
            Evidence ID of the collected command output

        Raises:
            subprocess.SubprocessError: If command fails to execute
            subprocess.TimeoutExpired: If command times out
        """
        evidence_type = EvidenceType.COMMAND_OUTPUT

        # Create a unique ID for this evidence
        evidence_id = self._generate_evidence_id()

        # Format command for display and logging
        cmd_str = command if isinstance(command, str) else " ".join(command)

        # Use command as title if not provided
        if not title:
            title = cmd_str[:50] + ("..." if len(cmd_str) > 50 else "")

        # Create the evidence file path
        evidence_path = self._get_evidence_path(evidence_type, f"{evidence_id}.txt")

        try:
            # Execute command and capture output
            stderr_opt = subprocess.STDOUT if include_stderr else subprocess.PIPE
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                env=env
            )

            # Get command output
            output = result.stdout
            if not include_stderr and result.stderr:
                output += "\n\n-- STDERR --\n" + result.stderr

            # Add command metadata
            metadata = (
                f"Command: {cmd_str}\n"
                f"Exit Code: {result.returncode}\n"
                f"Executed At: {datetime.datetime.now().isoformat()}\n"
                f"Shell: {shell}\n"
                f"Working Dir: {working_dir or 'current directory'}\n\n"
                f"-- OUTPUT --\n{output}"
            )

            # Write output to evidence file
            with open(evidence_path, "w", encoding="utf-8") as f:
                f.write(metadata)

            # Set proper permissions
            os.chmod(evidence_path, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Calculate hash for integrity verification
            file_hash = self._calculate_file_hash(evidence_path)

            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                title=title,
                description=description or f"Output from command: {cmd_str}",
                evidence_type=evidence_type.value,
                file_path=evidence_path,
                collection_time=datetime.datetime.now(),
                collected_by=self.assessor,
                metadata={
                    "hash": file_hash,
                    "hash_algorithm": DEFAULT_HASH_ALGORITHM,
                    "command": cmd_str,
                    "shell": shell,
                    "exit_code": result.returncode,
                    "working_dir": working_dir,
                    "timeout": timeout,
                    "file_size": os.path.getsize(evidence_path),
                    "content_type": "text/plain"
                }
            )

            # Record evidence
            self._record_evidence(evidence)

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.COLLECT,
                details={
                    "type": evidence_type.value,
                    "command": cmd_str,
                    "exit_code": result.returncode
                }
            )

            # Log collection
            self.logger.info(f"Collected command output evidence: {title} (ID: {evidence_id})")

            return evidence_id

        except Exception as e:
            self.logger.error(f"Failed to collect command output evidence: {e}")
            if os.path.exists(evidence_path):
                os.unlink(evidence_path)
            raise

    def collect_database_evidence(
        self,
        query_result: Union[str, List[Dict[str, Any]]],
        source_database: str,
        query: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Collect database query results as evidence.

        Args:
            query_result: The query results as string or structured data
            source_database: Database source identifier
            query: Optional query that produced the results
            title: Title for this evidence
            description: Description of this evidence
            metadata: Additional metadata

        Returns:
            Evidence ID of the collected database evidence
        """
        evidence_type = EvidenceType.DATABASE
        evidence_id = self._generate_evidence_id()

        # Convert structured data to formatted text if needed
        if isinstance(query_result, list):
            content = json.dumps(query_result, indent=2)
        else:
            content = str(query_result)

        # Create evidence file path
        evidence_path = self._get_evidence_path(evidence_type, f"{evidence_id}.json")

        try:
            # Write content to evidence file
            with open(evidence_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Set proper permissions
            os.chmod(evidence_path, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Calculate hash for integrity verification
            file_hash = self._calculate_file_hash(evidence_path)

            # Prepare metadata
            combined_metadata = {
                "hash": file_hash,
                "hash_algorithm": DEFAULT_HASH_ALGORITHM,
                "source_database": source_database,
                "file_size": os.path.getsize(evidence_path),
                "content_type": "application/json"
            }

            if query:
                combined_metadata["query"] = query

            if metadata:
                combined_metadata.update(metadata)

            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                title=title or f"Database evidence: {source_database}",
                description=description or f"Database query results from {source_database}",
                evidence_type=evidence_type.value,
                file_path=evidence_path,
                collection_time=datetime.datetime.now(),
                collected_by=self.assessor,
                metadata=combined_metadata
            )

            # Record evidence
            self._record_evidence(evidence)

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.COLLECT,
                details={
                    "type": evidence_type.value,
                    "source_database": source_database,
                    "has_query": query is not None
                }
            )

            # Log collection
            self.logger.info(f"Collected database evidence from {source_database} (ID: {evidence_id})")

            return evidence_id

        except Exception as e:
            self.logger.error(f"Failed to collect database evidence: {e}")
            if os.path.exists(evidence_path):
                os.unlink(evidence_path)
            raise

    def add_text_evidence(
        self,
        text: str,
        title: str,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add text content as evidence.

        Args:
            text: Text content to add as evidence
            title: Title for this evidence
            description: Description of this evidence
            severity: Optional severity level
            metadata: Additional metadata for this evidence

        Returns:
            Evidence ID of the collected text

        Raises:
            ValueError: If text is too large
        """
        if len(text) > DEFAULT_MAX_TEXT_SIZE:
            raise ValueError(f"Text evidence too large ({len(text)} bytes > {DEFAULT_MAX_TEXT_SIZE} bytes)")

        evidence_type = EvidenceType.TEXT

        # Create a unique ID for this evidence
        evidence_id = self._generate_evidence_id()

        # Create the evidence file path
        evidence_path = self._get_evidence_path(evidence_type, f"{evidence_id}.txt")

        try:
            # Write text to evidence file
            with open(evidence_path, "w", encoding="utf-8") as f:
                f.write(text)

            # Set proper permissions
            os.chmod(evidence_path, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Calculate hash for integrity verification
            file_hash = self._calculate_file_hash(evidence_path)

            # Prepare metadata
            combined_metadata = {
                "hash": file_hash,
                "hash_algorithm": DEFAULT_HASH_ALGORITHM,
                "file_size": os.path.getsize(evidence_path),
                "content_type": "text/plain",
                "content_length": len(text)
            }

            # Add severity if provided
            if severity:
                combined_metadata["severity"] = severity

            # Add additional metadata
            if metadata:
                combined_metadata.update(metadata)

            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                title=title,
                description=description or title,
                evidence_type=evidence_type.value,
                content=text[:1000] + ("..." if len(text) > 1000 else ""),  # Add preview
                file_path=evidence_path,
                collection_time=datetime.datetime.now(),
                collected_by=self.assessor,
                metadata=combined_metadata
            )

            # Record evidence
            self._record_evidence(evidence)

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.COLLECT,
                details={
                    "type": evidence_type.value,
                    "title": title,
                    "severity": severity
                }
            )

            # Log collection
            self.logger.info(f"Collected text evidence: {title} (ID: {evidence_id})")

            return evidence_id

        except Exception as e:
            self.logger.error(f"Failed to collect text evidence {title}: {e}")
            if os.path.exists(evidence_path):
                os.unlink(evidence_path)
            raise

    def collect_network_capture(
        self,
        interface: Optional[str] = None,
        filter_expression: Optional[str] = None,
        duration: int = 60,
        max_size: Optional[int] = None,
        title: Optional[str] = None,
        description: Optional[str] = None
    ) -> str:
        """
        Collect network traffic capture as evidence.

        Args:
            interface: Network interface to capture on
            filter_expression: PCAP filter expression
            duration: Duration in seconds to capture
            max_size: Maximum file size in bytes
            title: Title for this evidence
            description: Description of this evidence

        Returns:
            Evidence ID of the collected capture

        Raises:
            OSError: If capture fails
            FileNotFoundError: If tcpdump is not available
        """
        evidence_type = EvidenceType.NETWORK

        # Check if tcpdump is available
        try:
            subprocess.run(["which", "tcpdump"], capture_output=True, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            raise FileNotFoundError("tcpdump is required for network capture but not available")

        # Create a unique ID for this evidence
        evidence_id = self._generate_evidence_id()

        # Create the evidence file path
        evidence_path = self._get_evidence_path(evidence_type, f"{evidence_id}.pcap")

        # Build tcpdump command
        cmd = ["tcpdump", "-w", evidence_path]

        # Add interface if specified
        if interface:
            cmd.extend(["-i", interface])

        # Add filter expression if specified
        if filter_expression:
            cmd.append(filter_expression)

        # Use description for default title if not provided
        if not title:
            title_parts = []
            if interface:
                title_parts.append(f"Interface: {interface}")
            if filter_expression:
                title_parts.append(f"Filter: {filter_expression}")
            title_parts.append(f"Duration: {duration}s")
            title = "Network Capture: " + ", ".join(title_parts)

        try:
            # Start tcpdump process
            self.logger.info(f"Starting network capture: {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Let it run for the specified duration
            try:
                stdout, stderr = process.communicate(timeout=duration)
            except subprocess.TimeoutExpired:
                # Expected timeout after duration
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            # Verify capture worked
            if not os.path.exists(evidence_path) or os.path.getsize(evidence_path) == 0:
                raise OSError("Network capture failed or produced empty file")

            # Set proper permissions
            os.chmod(evidence_path, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Calculate hash for integrity verification
            file_hash = self._calculate_file_hash(evidence_path)

            # Create evidence record
            evidence = Evidence(
                evidence_id=evidence_id,
                title=title,
                description=description or f"Network traffic capture: {interface or 'default interface'}",
                evidence_type=evidence_type.value,
                file_path=evidence_path,
                collection_time=datetime.datetime.now(),
                collected_by=self.assessor,
                metadata={
                    "hash": file_hash,
                    "hash_algorithm": DEFAULT_HASH_ALGORITHM,
                    "interface": interface,
                    "filter_expression": filter_expression,
                    "duration": duration,
                    "file_size": os.path.getsize(evidence_path),
                    "content_type": "application/vnd.tcpdump.pcap"
                }
            )

            # Record evidence
            self._record_evidence(evidence)

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.COLLECT,
                details={
                    "type": evidence_type.value,
                    "interface": interface,
                    "filter_expression": filter_expression,
                    "duration": duration
                }
            )

            # Log collection
            self.logger.info(f"Collected network capture evidence: {title} (ID: {evidence_id})")

            return evidence_id

        except Exception as e:
            self.logger.error(f"Failed to collect network capture evidence: {e}")
            if os.path.exists(evidence_path):
                os.unlink(evidence_path)
            raise

    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """
        Verify that evidence hasn't been tampered with by checking its hash.

        Args:
            evidence_id: ID of the evidence to verify

        Returns:
            True if integrity check passes, False otherwise
        """
        # Get evidence details
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            self.logger.warning(f"Evidence not found: {evidence_id}")
            return False

        # Check if evidence has a file path and hash
        if not evidence.file_path or not evidence.metadata.get("hash"):
            self.logger.warning(f"Evidence {evidence_id} missing file path or original hash")
            return False

        # Check if file exists
        if not os.path.isfile(evidence.file_path):
            self.logger.warning(f"Evidence file not found: {evidence.file_path}")
            return False

        # Calculate current hash
        current_hash = self._calculate_file_hash(evidence.file_path)
        original_hash = evidence.metadata.get("hash")

        # Compare hashes
        integrity_ok = current_hash == original_hash

        # Add chain of custody entry
        self._add_custody_entry(
            evidence_id=evidence_id,
            action=EvidenceAction.VERIFY,
            details={
                "original_hash": original_hash,
                "current_hash": current_hash,
                "verified": integrity_ok
            }
        )

        # Log verification
        if integrity_ok:
            self.logger.info(f"Evidence {evidence_id} integrity verified successfully")
        else:
            self.logger.warning(
                f"Evidence {evidence_id} integrity check failed: "
                f"hash mismatch (original: {original_hash}, current: {current_hash})"
            )

        return integrity_ok

    def export_evidence(
        self,
        evidence_id: str,
        destination: str,
        include_metadata: bool = True
    ) -> str:
        """
        Export evidence to a specified destination.

        Args:
            evidence_id: ID of the evidence to export
            destination: Destination path
            include_metadata: Whether to include metadata file

        Returns:
            Path to exported evidence

        Raises:
            ValueError: If evidence not found
            OSError: If export fails
        """
        # Get evidence details
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence not found: {evidence_id}")

        # Check if evidence has a file path
        if not evidence.file_path or not os.path.isfile(evidence.file_path):
            raise ValueError(f"Evidence file not found: {evidence_id}")

        # Create destination directory if it doesn't exist
        os.makedirs(os.path.dirname(destination), exist_ok=True)

        try:
            # Copy evidence file
            shutil.copy2(evidence.file_path, destination)

            # Write metadata if requested
            if include_metadata:
                metadata_path = f"{destination}.metadata.json"
                self._write_json_file(metadata_path, {
                    "evidence_id": evidence.evidence_id,
                    "title": evidence.title,
                    "description": evidence.description,
                    "evidence_type": evidence.evidence_type,
                    "collection_time": evidence.collection_time.isoformat(),
                    "collected_by": evidence.collected_by,
                    "metadata": evidence.metadata,
                    "exported_at": datetime.datetime.now().isoformat(),
                    "exported_by": self.assessor,
                    "assessment_id": self.assessment_id
                })

            # Add chain of custody entry
            self._add_custody_entry(
                evidence_id=evidence_id,
                action=EvidenceAction.EXPORT,
                details={
                    "destination": destination,
                    "include_metadata": include_metadata
                }
            )

            # Log export
            self.logger.info(f"Evidence {evidence_id} exported to {destination}")

            return destination

        except Exception as e:
            self.logger.error(f"Failed to export evidence {evidence_id}: {e}")
            raise OSError(f"Failed to export evidence: {e}")

    def create_evidence_package(
        self,
        evidence_ids: Optional[List[str]] = None,
        format: str = "zip",
        output_path: Optional[str] = None,
        include_metadata: bool = True
    ) -> str:
        """
        Create a package containing selected evidence items.

        Args:
            evidence_ids: List of evidence IDs to include, None for all
            format: Package format ('zip', 'tar', or 'directory')
            output_path: Path for the output package
            include_metadata: Whether to include metadata

        Returns:
            Path to the evidence package

        Raises:
            ValueError: If format is invalid
            OSError: If packaging fails
        """
        # Validate format
        if format not in ("zip", "tar", "directory"):
            raise ValueError(f"Invalid package format: {format}")

        # Get evidence to package
        if evidence_ids is None:
            # Include all evidence
            evidence_items = self.evidence_items
        else:
            # Include specified evidence
            evidence_items = []
            for evidence_id in evidence_ids:
                evidence = self._get_evidence_by_id(evidence_id)
                if evidence:
                    evidence_items.append(evidence)

        if not evidence_items:
            raise ValueError("No evidence items to package")

        # Create output path if not provided
        if not output_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            if format == "directory":
                output_path = f"evidence_package_{self.assessment_id}_{timestamp}"
            else:
                output_path = f"evidence_package_{self.assessment_id}_{timestamp}.{format}"

        try:
            # Create a temporary directory for staging
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create package structure
                package_dir = os.path.join(temp_dir, "evidence_package")
                os.makedirs(package_dir)

                # Create evidence directory
                evidence_dir = os.path.join(package_dir, "evidence")
                os.makedirs(evidence_dir)

                # Create metadata directory
                metadata_dir = os.path.join(package_dir, "metadata")
                os.makedirs(metadata_dir)

                # Copy evidence files
                for evidence in evidence_items:
                    if evidence.file_path and os.path.isfile(evidence.file_path):
                        # Create evidence type directory if it doesn't exist
                        type_dir = os.path.join(evidence_dir, evidence.evidence_type)
                        os.makedirs(type_dir, exist_ok=True)

                        # Determine file name
                        original_name = os.path.basename(evidence.file_path)
                        file_name = f"{evidence.evidence_id}_{original_name}"
                        destination = os.path.join(type_dir, file_name)

                        # Copy evidence file
                        shutil.copy2(evidence.file_path, destination)

                        # Write individual metadata if requested
                        if include_metadata:
                            metadata_file = os.path.join(metadata_dir, f"{evidence.evidence_id}.json")
                            self._write_json_file(metadata_file, {
                                "evidence_id": evidence.evidence_id,
                                "title": evidence.title,
                                "description": evidence.description,
                                "evidence_type": evidence.evidence_type,
                                "collection_time": evidence.collection_time.isoformat(),
                                "collected_by": evidence.collected_by,
                                "metadata": evidence.metadata,
                                "file_name": file_name
                            })

                # Write package manifest
                manifest_file = os.path.join(package_dir, "manifest.json")
                self._write_json_file(manifest_file, {
                    "assessment_id": self.assessment_id,
                    "target_id": self.target_id,
                    "package_created_at": datetime.datetime.now().isoformat(),
                    "package_created_by": self.assessor,
                    "evidence_count": len(evidence_items),
                    "evidence_ids": [evidence.evidence_id for evidence in evidence_items],
                    "package_format": format
                })

                # Create chain of custody log for the package
                coc_file = os.path.join(metadata_dir, "chain_of_custody.json")
                chain_entries = []
                for evidence in evidence_items:
                    # Get all custody entries for this evidence
                    entries = self._get_custody_entries(evidence.evidence_id)
                    chain_entries.extend([entry.to_dict() for entry in entries])
                self._write_json_file(coc_file, {
                    "assessment_id": self.assessment_id,
                    "entries": chain_entries
                })

                # Create package based on format
                if format == "directory":
                    if os.path.exists(output_path):
                        shutil.rmtree(output_path)
                    shutil.copytree(package_dir, output_path)

                elif format == "zip":
                    if os.path.exists(output_path):
                        os.unlink(output_path)
                    shutil.make_archive(
                        output_path.rsplit('.', 1)[0],
                        'zip',
                        root_dir=temp_dir,
                        base_dir="evidence_package"
                    )

                elif format == "tar":
                    if os.path.exists(output_path):
                        os.unlink(output_path)
                    shutil.make_archive(
                        output_path.rsplit('.', 1)[0],
                        'tar',
                        root_dir=temp_dir,
                        base_dir="evidence_package"
                    )

            # Add chain of custody entries for each evidence
            for evidence in evidence_items:
                self._add_custody_entry(
                    evidence_id=evidence.evidence_id,
                    action=EvidenceAction.PACKAGE,
                    details={
                        "package_path": output_path,
                        "package_format": format
                    }
                )

            # Log packaging
            self.logger.info(
                f"Created evidence package with {len(evidence_items)} items at {output_path}"
            )

            return output_path

        except Exception as e:
            self.logger.error(f"Failed to create evidence package: {e}")
            raise OSError(f"Failed to create evidence package: {e}")

    def get_evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        """
        Get evidence details by ID.

        Args:
            evidence_id: ID of the evidence to get

        Returns:
            Evidence object or None if not found
        """
        return self._get_evidence_by_id(evidence_id)

    def get_evidence_for_finding(self, finding_id: str) -> List[Evidence]:
        """
        Get evidence associated with a finding ID.

        Args:
            finding_id: Finding ID to search for

        Returns:
            List of evidence items related to the finding
        """
        finding_evidence = []
        for evidence in self.evidence_items:
            metadata = evidence.metadata or {}
            # Check if the finding ID is in the metadata
            if metadata.get("finding_id") == finding_id or finding_id in metadata.get("findings", []):
                finding_evidence.append(evidence)
        return finding_evidence

    def find_evidence(
        self,
        evidence_type: Optional[str] = None,
        title_contains: Optional[str] = None,
        metadata_contains: Optional[Dict[str, Any]] = None
    ) -> List[Evidence]:
        """
        Find evidence matching specified criteria.

        Args:
            evidence_type: Type of evidence to find
            title_contains: Text to search for in titles
            metadata_contains: Metadata key-value pairs to match

        Returns:
            List of matching evidence items
        """
        results = []

        for evidence in self.evidence_items:
            # Check evidence type
            if evidence_type and evidence.evidence_type != evidence_type:
                continue

            # Check title
            if title_contains and title_contains.lower() not in evidence.title.lower():
                continue

            # Check metadata
            if metadata_contains:
                match = True
                for key, value in metadata_contains.items():
                    if key not in evidence.metadata or evidence.metadata[key] != value:
                        match = False
                        break
                if not match:
                    continue

            # All checks passed
            results.append(evidence)

        return results

    def find_evidence_by_tags(self, tags: List[str], match_all: bool = False) -> List[Evidence]:
        """
        Find evidence by tags.

        Args:
            tags: List of tags to search for
            match_all: If True, all tags must match; if False, any tag match will be included

        Returns:
            List of evidence items with matching tags
        """
        results = []

        for evidence in self.evidence_items:
            metadata = evidence.metadata or {}
            evidence_tags = metadata.get("tags", [])

            if match_all:
                # All tags must be present
                if all(tag in evidence_tags for tag in tags):
                    results.append(evidence)
            else:
                # Any tag match is sufficient
                if any(tag in evidence_tags for tag in tags):
                    results.append(evidence)

        return results

    def get_custody_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """
        Get the chain of custody for evidence.

        Args:
            evidence_id: ID of the evidence

        Returns:
            List of custody entries
        """
        entries = self._get_custody_entries(evidence_id)
        return [entry.to_dict() for entry in entries]

    def add_finding_evidence_link(
        self,
        evidence_id: str,
        finding_id: str,
        finding_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Associate evidence with a finding.

        Args:
            evidence_id: ID of the evidence
            finding_id: ID of the finding
            finding_details: Additional details about the finding

        Returns:
            True if successful, False otherwise
        """
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            self.logger.warning(f"Evidence not found: {evidence_id}")
            return False

        # Update evidence metadata
        metadata = evidence.metadata or {}

        # Store finding ID directly and in findings list
        metadata["finding_id"] = finding_id
        if "findings" not in metadata:
            metadata["findings"] = []
        if finding_id not in metadata["findings"]:
            metadata["findings"].append(finding_id)

        # Add finding details if provided
        if finding_details:
            if "finding_details" not in metadata:
                metadata["finding_details"] = {}
            metadata["finding_details"][finding_id] = finding_details

        # Update evidence record
        evidence.metadata = metadata
        self._update_evidence(evidence)

        # Add chain of custody entry
        self._add_custody_entry(
            evidence_id=evidence_id,
            action="link_to_finding",
            details={
                "finding_id": finding_id
            }
        )

        self.logger.info(f"Linked evidence {evidence_id} to finding {finding_id}")
        return True

    def add_evidence_tags(self, evidence_id: str, tags: List[str]) -> bool:
        """
        Add tags to evidence for better organization and searching.

        Args:
            evidence_id: ID of the evidence to tag
            tags: List of tags to add

        Returns:
            True if successful, False otherwise
        """
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            self.logger.warning(f"Evidence not found: {evidence_id}")
            return False

        metadata = evidence.metadata or {}

        # Initialize tags list if it doesn't exist
        if "tags" not in metadata:
            metadata["tags"] = []

        # Add new tags (avoid duplicates)
        for tag in tags:
            if tag not in metadata["tags"]:
                metadata["tags"].append(tag)

        # Update evidence
        evidence.metadata = metadata
        self._update_evidence(evidence)

        # Add chain of custody entry
        self._add_custody_entry(
            evidence_id=evidence_id,
            action="tag",
            details={"tags_added": tags}
        )

        self.logger.info(f"Added tags {tags} to evidence {evidence_id}")
        return True

    def set_evidence_classification(self, evidence_id: str, classification: str) -> bool:
        """
        Set the security classification of evidence.

        Args:
            evidence_id: ID of the evidence
            classification: Security classification (e.g., "Public", "Confidential")

        Returns:
            True if successful, False otherwise
        """
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            self.logger.warning(f"Evidence not found: {evidence_id}")
            return False

        metadata = evidence.metadata or {}
        old_classification = metadata.get("classification", "Unclassified")
        metadata["classification"] = classification

        # Update evidence
        evidence.metadata = metadata
        self._update_evidence(evidence)

        # Add chain of custody entry
        self._add_custody_entry(
            evidence_id=evidence_id,
            action="classify",
            details={
                "old_classification": old_classification,
                "new_classification": classification
            }
        )

        self.logger.info(f"Changed classification of evidence {evidence_id} to {classification}")
        return True

    def add_evidence_note(
        self,
        evidence_id: str,
        note: str,
        note_type: str = "analysis"
    ) -> bool:
        """
        Add a note or annotation to evidence.

        Args:
            evidence_id: ID of the evidence
            note: Note text
            note_type: Type of note (analysis, observation, etc.)

        Returns:
            True if successful, False otherwise
        """
        evidence = self._get_evidence_by_id(evidence_id)
        if not evidence:
            self.logger.warning(f"Evidence not found: {evidence_id}")
            return False

        metadata = evidence.metadata or {}

        # Initialize notes list if it doesn't exist
        if "notes" not in metadata:
            metadata["notes"] = []

        # Add new note with timestamp
        note_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "analyst": self.assessor,
            "type": note_type,
            "content": note
        }

        metadata["notes"].append(note_entry)

        # Update evidence
        evidence.metadata = metadata
        self._update_evidence(evidence)

        # Add chain of custody entry
        self._add_custody_entry(
            evidence_id=evidence_id,
            action="add_note",
            details={"note_type": note_type}
        )

        self.logger.info(f"Added {note_type} note to evidence {evidence_id}")
        return True

    def finalize(self) -> List[Evidence]:
        """
        Finalize the evidence collection and return all collected evidence.

        This method should be called when all evidence collection is complete.
        It finalizes the evidence registry and returns all collected evidence.

        Returns:
            List of all collected evidence
        """
        # Ensure all metadata is up to date
        self._update_evidence_registry()

        # Create a summary report
        summary_path = os.path.join(self.evidence_dir, "metadata", "summary_report.json")
        self._write_json_file(summary_path, {
            "assessment_id": self.assessment_id,
            "target_id": self.target_id,
            "evidence_count": len(self.evidence_items),
            "evidence_types": list(set(evidence.evidence_type for evidence in self.evidence_items)),
            "collection_completed_at": datetime.datetime.now().isoformat(),
            "collector": self.assessor,
            "evidence_directory": self.evidence_dir,
            "evidence_ids": [evidence.evidence_id for evidence in self.evidence_items]
        })

        # Log finalization
        self.logger.info(f"Evidence collection finalized: {len(self.evidence_items)} items collected")

        # Return all evidence
        return list(self.evidence_items)

    def get_evidence_path(self) -> str:
        """
        Get the path to the evidence directory.

        Returns:
            Path to the evidence directory
        """
        return self.evidence_dir

    def _generate_evidence_id(self) -> str:
        """Generate a unique evidence ID."""
        base_id = f"ev-{self.assessment_id}-{uuid.uuid4().hex[:8]}"
        return base_id

    def _get_evidence_path(self, evidence_type: EvidenceType, file_name: str) -> str:
        """
        Get the path for storing evidence.

        Args:
            evidence_type: Type of evidence
            file_name: Name of the evidence file

        Returns:
            Full path for evidence file
        """
        return os.path.join(self.evidence_dir, evidence_type.value, file_name)

    def _calculate_file_hash(self, file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
        """
        Calculate cryptographic hash for a file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use

        Returns:
            Hexadecimal hash digest

        Raises:
            ValueError: If algorithm is not supported
            OSError: If file cannot be read
        """
        if algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Hash algorithm not supported: {algorithm}")

        h = hashlib.new(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)

        return h.hexdigest()

    def _detect_content_type(self, file_path: str) -> str:
        """
        Detect MIME type of a file.

        Args:
            file_path: Path to the file

        Returns:
            MIME type as string
        """
        # Simple extension-based detection
        extension = os.path.splitext(file_path)[1].lower()

        content_types = {
            ".txt": "text/plain",
            ".log": "text/plain",
            ".html": "text/html",
            ".htm": "text/html",
            ".xml": "application/xml",
            ".json": "application/json",
            ".yaml": "application/yaml",
            ".yml": "application/yaml",
            ".csv": "text/csv",
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".zip": "application/zip",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            ".bz2": "application/x-bzip2",
            ".7z": "application/x-7z-compressed",
            ".pcap": "application/vnd.tcpdump.pcap",
            ".pcapng": "application/vnd.tcpdump.pcap",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
            ".tiff": "image/tiff",
            ".svg": "image/svg+xml",
            ".webp": "image/webp",
            ".mp4": "video/mp4",
            ".mp3": "audio/mpeg",
            ".wav": "audio/wav",
            ".ogg": "audio/ogg",
            ".flac": "audio/flac",
            ".sql": "application/sql",
            ".py": "text/x-python",
            ".js": "text/javascript",
            ".css": "text/css",
            ".sh": "application/x-sh",
            ".bash": "application/x-sh",
            ".cfg": "text/plain",
            ".conf": "text/plain",
            ".ini": "text/plain",
            ".md": "text/markdown",
        }

        return content_types.get(extension, "application/octet-stream")

    def _record_evidence(self, evidence: Evidence) -> None:
        """
        Record collected evidence in the tracking system.

        Args:
            evidence: Evidence to record
        """
        # Add to the list of tracked evidence
        self.evidence_items.append(evidence)
        self.collected_evidence_paths.append(evidence.file_path)

        # Update the evidence registry
        self._update_evidence_registry()

    def _update_evidence_registry(self) -> None:
        """Update the evidence registry file with the latest evidence items."""
        registry_path = os.path.join(self.evidence_dir, "metadata", "evidence_registry.json")
        registry_data = {
            "assessment_id": self.assessment_id,
            "target_id": self.target_id,
            "updated_at": datetime.datetime.now().isoformat(),
            "created_by": self.assessor,
            "evidence_items": [],
            "retention_period": self.retention_period
        }

        # Convert evidence items to dictionaries
        for evidence in self.evidence_items:
            evidence_dict = {
                "evidence_id": evidence.evidence_id,
                "title": evidence.title,
                "description": evidence.description,
                "evidence_type": evidence.evidence_type,
                "file_path": evidence.file_path,
                "collection_time": evidence.collection_time.isoformat(),
                "collected_by": evidence.collected_by,
                "metadata": evidence.metadata
            }
            registry_data["evidence_items"].append(evidence_dict)

        # Write the registry file
        self._write_json_file(registry_path, registry_data)

    def _update_evidence(self, evidence: Evidence) -> None:
        """
        Update an existing evidence record.

        Args:
            evidence: Updated evidence object
        """
        # Find the evidence in the list
        for i, item in enumerate(self.evidence_items):
            if item.evidence_id == evidence.evidence_id:
                # Replace with the updated evidence
                self.evidence_items[i] = evidence
                break

        # Update the registry
        self._update_evidence_registry()

    def _add_custody_entry(
        self,
        evidence_id: str,
        action: Union[EvidenceAction, str],
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add an entry to the chain of custody log.

        Args:
            evidence_id: ID of the evidence
            action: Action performed on the evidence
            details: Additional details about the action
        """
        # Convert string action to EvidenceAction enum if needed
        if isinstance(action, str):
            try:
                action = EvidenceAction(action)
            except ValueError:
                # Use the string value directly if it's not a valid enum value
                pass

        # Create the entry
        entry = CustodyEntry(
            timestamp=datetime.datetime.now(),
            action=action.value if isinstance(action, EvidenceAction) else action,
            performed_by=self.assessor,
            details=details or {}
        )

        # Get the custody log file path
        custody_log_path = os.path.join(self.evidence_dir, "metadata", "chain_of_custody.json")

        # Load the existing log
        try:
            with open(custody_log_path, "r", encoding="utf-8") as f:
                custody_log = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Create a new log if it doesn't exist or is invalid
            custody_log = {
                "assessment_id": self.assessment_id,
                "entries": []
            }

        # Add the evidence ID to the entry details
        entry_dict = entry.to_dict()
        entry_dict["evidence_id"] = evidence_id

        # Add the entry to the log
        custody_log["entries"].append(entry_dict)

        # Write the log
        self._write_json_file(custody_log_path, custody_log)

    def _get_custody_entries(self, evidence_id: str) -> List[CustodyEntry]:
        """
        Get the chain of custody entries for evidence.

        Args:
            evidence_id: ID of the evidence

        Returns:
            List of custody entries
        """
        custody_log_path = os.path.join(self.evidence_dir, "metadata", "chain_of_custody.json")
        entries = []

        try:
            with open(custody_log_path, "r", encoding="utf-8") as f:
                custody_log = json.load(f)

            for entry_dict in custody_log.get("entries", []):
                if entry_dict.get("evidence_id") == evidence_id:
                    # Create a CustodyEntry from the dictionary
                    try:
                        timestamp = datetime.datetime.fromisoformat(entry_dict.get("timestamp", ""))
                    except ValueError:
                        timestamp = datetime.datetime.now()

                    entry = CustodyEntry(
                        timestamp=timestamp,
                        action=entry_dict.get("action", ""),
                        performed_by=entry_dict.get("performed_by", ""),
                        details=entry_dict.get("details", {})
                    )
                    entries.append(entry)
        except (FileNotFoundError, json.JSONDecodeError):
            # Return empty list if the log doesn't exist or is invalid
            pass

        return entries

    def _get_evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        """
        Get evidence by ID.

        Args:
            evidence_id: ID of the evidence to get

        Returns:
            Evidence object or None if not found
        """
        for evidence in self.evidence_items:
            if evidence.evidence_id == evidence_id:
                return evidence
        return None

    def _write_json_file(self, file_path: str, data: Any) -> None:
        """
        Write data to a JSON file with proper permissions.

        Args:
            file_path: Path to the file
            data: Data to write

        Raises:
            OSError: If file cannot be written
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Write data to a temporary file first
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
                json.dump(data, temp_file, indent=2)

            # Set permissions on the temporary file
            os.chmod(temp_file.name, DEFAULT_EVIDENCE_FILE_PERMISSIONS)

            # Move the temporary file to the target location
            shutil.move(temp_file.name, file_path)
        except Exception as e:
            self.logger.error(f"Failed to write JSON file {file_path}: {e}")
            # Clean up the temporary file if an error occurs
            if 'temp_file' in locals():
                try:
                    os.unlink(temp_file.name)
                except OSError:
                    pass
            raise OSError(f"Failed to write JSON file: {e}")

    def _capture_macos_screenshot(self, output_path: str) -> None:
        """
        Capture a screenshot on macOS.

        Args:
            output_path: Path to save the screenshot

        Raises:
            subprocess.SubprocessError: If screenshot capture fails
        """
        subprocess.run(["screencapture", "-x", output_path], check=True)

    def _capture_windows_screenshot(self, output_path: str) -> None:
        """
        Capture a screenshot on Windows.

        Args:
            output_path: Path to save the screenshot

        Raises:
            OSError: If screenshot capture fails
        """
        try:
            from PIL import ImageGrab
            if HAS_PILLOW:
                screenshot = ImageGrab.grab()
                screenshot.save(output_path)
            else:
                raise ImportError("PIL/Pillow is required for Windows screenshots")
        except ImportError:
            # Fall back to PowerShell if Pillow is not available
            powershell_cmd = (
                '$wia = Add-Type -AssemblyName System.Windows.Forms -PassThru;'
                '[System.Windows.Forms.Screen]::PrimaryScreen.Bounds | '
                'ForEach-Object {$bounds = $_; '
                '$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height; '
                '$graphics = [System.Drawing.Graphics]::FromImage($bitmap); '
                '$graphics.CopyFromScreen([System.Drawing.Point]::Empty, '
                '[System.Drawing.Point]::Empty, $bounds.Size); '
                f'$bitmap.Save("{output_path}"); '
                '$graphics.Dispose(); $bitmap.Dispose()}'
            )
            subprocess.run(["powershell", "-Command", powershell_cmd], check=True)

    def _capture_linux_screenshot(self, output_path: str) -> None:
        """
        Capture a screenshot on Linux.

        Args:
            output_path: Path to save the screenshot

        Raises:
            subprocess.SubprocessError: If screenshot capture fails
        """
        # Try different screenshot tools in order of preference
        tools = [
            ["gnome-screenshot", "-f", output_path],
            ["scrot", output_path],
            ["import", "-window", "root", output_path],
            ["xwd", "-root", "-out", output_path]
        ]

        for tool in tools:
            try:
                subprocess.run(tool, check=True)
                return
            except (subprocess.SubprocessError, FileNotFoundError):
                continue

        raise OSError("No supported screenshot tools found on Linux")


# Utility function for using the collector in a context manager
@contextmanager
def create_evidence_collector(
    assessment_id: str,
    target_id: str,
    assessor: str,
    evidence_base_dir: Optional[str] = None,
    retention_period: Optional[str] = None
) -> Generator[EvidenceCollector, None, None]:
    """
    Create an evidence collector as a context manager.

    Args:
        assessment_id: Unique identifier for the assessment
        target_id: Identifier for the target system
        assessor: Name or identifier of the person collecting evidence
        evidence_base_dir: Directory to store evidence
        retention_period: How long to retain evidence

    Yields:
        EvidenceCollector instance

    Example:
        ```python
        with create_evidence_collector("assessment-123", "target-456", "analyst") as collector:
            collector.collect_file("/path/to/config.json")
            collector.add_text_evidence("Log contents", "System Logs")
        # Evidence is finalized automatically when the context exits
        ```
    """
    collector = EvidenceCollector(
        assessment_id=assessment_id,
        target_id=target_id,
        assessor=assessor,
        evidence_base_dir=evidence_base_dir,
        retention_period=retention_period
    )

    try:
        yield collector
    finally:
        # Ensure evidence is finalized when the context exits
        collector.finalize()
