#!/usr/bin/env python3
"""
File integrity monitoring and verification system.

This module provides functions to create and verify file integrity baselines,
detect unauthorized changes to files, and manage integrity verification. It
implements secure hashing algorithms and robust change detection to help
maintain system security and compliance.

Key features:
- Multiple hash algorithm support (SHA-256, SHA-512, BLAKE2)
- Baseline generation for integrity verification
- Change detection with detailed reporting
- Recursive directory scanning
- File exclusion patterns
- Integrity status caching
- Verification scheduling
- Critical file prioritization
- Tamper evidence logging
- Integration with notification system
- Secure baseline storage
"""

import os
import sys
import json
import time
import glob
import hashlib
import logging
import fnmatch
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional, Union, Any, NamedTuple, BinaryIO
from dataclasses import dataclass, field, asdict

# Try to import core modules if available
try:
    from scripts.core.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback logging if core logger is not available
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

try:
    from scripts.core.error_handler import handle_error, ErrorCategory, ApplicationError
    ERROR_HANDLER_AVAILABLE = True
except ImportError:
    logger.warning("Error handler not available, using basic error handling")
    ERROR_HANDLER_AVAILABLE = False

try:
    from scripts.core.notification import send_notification
    NOTIFICATION_AVAILABLE = True
except ImportError:
    logger.warning("Notification system not available")
    NOTIFICATION_AVAILABLE = False

# Try to import cryptography for better hash functions if available
try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False

# Constants for file integrity operations
DEFAULT_HASH_ALGORITHM = "sha256"
SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "blake2s"]
if BLAKE3_AVAILABLE:
    SUPPORTED_HASH_ALGORITHMS.append("blake3")

# Default chunk size for file reading (64KB)
DEFAULT_CHUNK_SIZE = 65536

# Default exclusion patterns
DEFAULT_EXCLUDE_PATTERNS = [
    "*.tmp", "*.bak", "*.swp", "*.log", "*.pid",
    "*.pyc", "__pycache__", ".git/*", "*.gz", "*.zip"
]

# Severity levels for integrity issues
class Severity:
    """Severity levels for integrity issues."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntegrityError(ApplicationError):
    """Exception raised for integrity verification errors."""
    def __init__(self, message: str, severity: str = Severity.MEDIUM):
        super().__init__(message)
        self.severity = severity
        self.category = ErrorCategory.SECURITY


@dataclass
class FileInfo:
    """Information about a file including its hash and metadata."""
    path: str
    hash: str
    algorithm: str
    size: int
    mtime: float
    mode: int = 0
    owner: str = ""
    group: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileInfo':
        """Create FileInfo from dictionary representation."""
        return cls(**data)


@dataclass
class Violation:
    """Represents a file integrity violation."""
    file_path: str
    reason: str
    severity: str = Severity.MEDIUM
    expected_hash: Optional[str] = None
    current_hash: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class IntegrityResult:
    """Result of an integrity verification operation."""
    is_valid: bool
    violations: List[Violation] = field(default_factory=list)
    checked_files: int = 0
    baseline_files: int = 0
    timestamp: float = field(default_factory=time.time)
    execution_time: float = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_valid": self.is_valid,
            "violations": [v.to_dict() for v in self.violations],
            "checked_files": self.checked_files,
            "baseline_files": self.baseline_files,
            "timestamp": self.timestamp,
            "execution_time": self.execution_time
        }


@dataclass
class BaselineResult:
    """Result of a baseline creation operation."""
    file_count: int
    total_size: int
    baseline_path: str
    execution_time: float = 0
    excluded_files: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


#######################################
# File Hashing Functions
#######################################

def calculate_file_hash(file_path: Union[str, Path],
                       algorithm: str = DEFAULT_HASH_ALGORITHM,
                       chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Calculate the hash of a file using the specified algorithm.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (sha256, sha512, etc.)
        chunk_size: Size of chunks to read from file

    Returns:
        Hex digest of the hash

    Raises:
        FileNotFoundError: If file does not exist
        ValueError: If algorithm is not supported
        IntegrityError: If there's an error reading the file
    """
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. "
                         f"Supported algorithms: {', '.join(SUPPORTED_HASH_ALGORITHMS)}")

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    try:
        # Special case for BLAKE3 which isn't in hashlib
        if algorithm == "blake3" and BLAKE3_AVAILABLE:
            hasher = blake3.blake3()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()

        # Use hashlib for other algorithms
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    except (IOError, OSError) as e:
        error_msg = f"Error reading file {file_path} for hashing: {str(e)}"
        logger.error(error_msg)
        raise IntegrityError(error_msg)


def get_file_metadata(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Get file metadata including owner, group, permissions, size, and modified time.

    Args:
        file_path: Path to the file

    Returns:
        Dictionary containing file metadata
    """
    file_path = Path(file_path)
    try:
        stat_info = file_path.stat()
        metadata = {
            "size": stat_info.st_size,
            "mtime": stat_info.st_mtime,
            "mode": stat_info.st_mode & 0o777  # Get only permission bits
        }

        # Try to get owner and group names if platform supports it
        try:
            import pwd
            import grp
            metadata["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
            metadata["group"] = grp.getgrgid(stat_info.st_gid).gr_name
        except (ImportError, KeyError):
            # Fall back to numeric IDs if names can't be resolved
            metadata["owner"] = str(stat_info.st_uid)
            metadata["group"] = str(stat_info.st_gid)
        except AttributeError:
            # Windows doesn't have uid/gid
            metadata["owner"] = ""
            metadata["group"] = ""

        return metadata

    except (OSError, IOError) as e:
        logger.warning(f"Could not get metadata for {file_path}: {e}")
        return {
            "size": 0,
            "mtime": 0,
            "mode": 0,
            "owner": "",
            "group": ""
        }


#######################################
# Baseline Creation and Management
#######################################

def create_baseline(directory: Union[str, Path],
                   output_file: Union[str, Path],
                   algorithms: List[str] = None,
                   exclude_patterns: List[str] = None,
                   include_patterns: List[str] = None,
                   recursive: bool = True,
                   include_metadata: bool = True) -> BaselineResult:
    """
    Create a baseline hash file for a directory.

    Args:
        directory: Directory to create baseline for
        output_file: Path to save baseline file
        algorithms: Hash algorithms to use (defaults to SHA-256)
        exclude_patterns: Glob patterns to exclude
        include_patterns: Glob patterns to include only
        recursive: Whether to scan subdirectories
        include_metadata: Whether to include file metadata

    Returns:
        BaselineResult with information about the baseline creation

    Raises:
        IntegrityError: If there's an error creating the baseline
    """
    directory = Path(directory)
    output_file = Path(output_file)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    # Set defaults
    if algorithms is None:
        algorithms = [DEFAULT_HASH_ALGORITHM]

    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDE_PATTERNS

    # Validate algorithms
    for algorithm in algorithms:
        if algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Create baseline entries
    baseline = {
        "metadata": {
            "created": datetime.now(timezone.utc).isoformat(),
            "directory": str(directory),
            "algorithms": algorithms,
            "exclude_patterns": exclude_patterns,
            "include_patterns": include_patterns,
            "recursive": recursive,
            "version": "1.0"
        },
        "files": {}
    }

    result = BaselineResult(
        file_count=0,
        total_size=0,
        baseline_path=str(output_file),
        excluded_files=0,
        errors=[]
    )

    start_time = time.time()

    try:
        # Get list of files based on settings
        files_to_process = []

        if recursive:
            walkable = os.walk(directory)
        else:
            walkable = [(directory, [], [f.name for f in directory.iterdir() if f.is_file()])]

        # Process directory tree
        for root, _, files in walkable:
            for filename in files:
                file_path = Path(root) / filename
                rel_path = file_path.relative_to(directory)

                # Check exclude patterns
                if exclude_patterns and any(fnmatch.fnmatch(str(rel_path), pattern) for pattern in exclude_patterns):
                    result.excluded_files += 1
                    continue

                # Check include patterns if specified
                if include_patterns and not any(fnmatch.fnmatch(str(rel_path), pattern) for pattern in include_patterns):
                    result.excluded_files += 1
                    continue

                files_to_process.append((file_path, rel_path))

        # Process each file
        for file_path, rel_path in files_to_process:
            try:
                # Calculate hashes for each algorithm
                hashes = {}
                for algorithm in algorithms:
                    hashes[algorithm] = calculate_file_hash(file_path, algorithm)

                # Get file metadata
                metadata = get_file_metadata(file_path) if include_metadata else {}

                # Store file info
                file_info = {
                    "hashes": hashes,
                    "size": metadata.get("size", 0),
                    "mtime": metadata.get("mtime", 0)
                }

                # Add permission information if available
                if include_metadata:
                    file_info["mode"] = metadata.get("mode", 0)
                    file_info["owner"] = metadata.get("owner", "")
                    file_info["group"] = metadata.get("group", "")

                baseline["files"][str(rel_path)] = file_info

                # Update result stats
                result.file_count += 1
                result.total_size += metadata.get("size", 0)

            except (OSError, IOError, IntegrityError) as e:
                error_msg = f"Error processing file {file_path}: {str(e)}"
                logger.warning(error_msg)
                result.errors.append(error_msg)

        # Save baseline to file
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Set secure permissions for the directory if possible
        try:
            os.chmod(output_file.parent, 0o750)
        except OSError:
            logger.warning(f"Could not set secure permissions on {output_file.parent}")

        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        # Secure the baseline file itself
        try:
            os.chmod(output_file, 0o640)
        except OSError:
            logger.warning(f"Could not set secure permissions on {output_file}")

        logger.info(f"Created baseline with {result.file_count} files "
                   f"({result.excluded_files} excluded) at {output_file}")

    except Exception as e:
        error_msg = f"Error creating baseline: {str(e)}"
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        raise IntegrityError(error_msg)

    # Add execution time
    result.execution_time = time.time() - start_time

    return result


def update_baseline(directory: Union[str, Path],
                   baseline_file: Union[str, Path],
                   changes_approved_by: str,
                   comment: str = "",
                   algorithm: str = None,
                   keep_history: bool = True) -> BaselineResult:
    """
    Update an existing baseline with current files.

    Args:
        directory: Directory to create baseline for
        baseline_file: Path to existing baseline file
        changes_approved_by: Name/ID of person approving changes
        comment: Comment explaining reason for update
        algorithm: Override hash algorithm (defaults to one from existing baseline)
        keep_history: Whether to keep previous baseline as backup

    Returns:
        BaselineResult with information about the baseline update

    Raises:
        FileNotFoundError: If baseline file doesn't exist
        IntegrityError: If there's an error updating the baseline
    """
    baseline_path = Path(baseline_file)

    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    try:
        # Load existing baseline
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        # Extract metadata
        metadata = baseline.get("metadata", {})
        existing_directory = metadata.get("directory", str(directory))
        algorithms = metadata.get("algorithms", [DEFAULT_HASH_ALGORITHM])
        exclude_patterns = metadata.get("exclude_patterns", DEFAULT_EXCLUDE_PATTERNS)
        include_patterns = metadata.get("include_patterns", None)
        recursive = metadata.get("recursive", True)

        # Use provided algorithm if specified
        if algorithm:
            algorithms = [algorithm]

        # Create backup if keeping history
        if keep_history:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = baseline_path.with_suffix(f".{timestamp}.bak")
            with open(backup_path, 'w') as f:
                json.dump(baseline, f, indent=2)
            logger.info(f"Created baseline backup at {backup_path}")

        # Update baseline metadata
        baseline["metadata"]["updated"] = datetime.now(timezone.utc).isoformat()
        baseline["metadata"]["updated_by"] = changes_approved_by
        baseline["metadata"]["update_comment"] = comment

        # Generate new baseline
        result = create_baseline(
            directory=directory or existing_directory,
            output_file=baseline_path,
            algorithms=algorithms,
            exclude_patterns=exclude_patterns,
            include_patterns=include_patterns,
            recursive=recursive,
            include_metadata=True
        )

        logger.info(f"Updated baseline with {result.file_count} files at {baseline_path}")

        # Log update record
        update_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "approver": changes_approved_by,
            "comment": comment,
            "file_count": result.file_count
        }

        logger.info(f"Baseline update: {update_record}")

        # Send notification if available
        if NOTIFICATION_AVAILABLE:
            send_notification(
                title="File Integrity Baseline Updated",
                message=f"Baseline updated with {result.file_count} files. Approved by {changes_approved_by}.",
                priority="medium",
                category="security"
            )

        return result

    except (IOError, json.JSONDecodeError) as e:
        error_msg = f"Error updating baseline: {str(e)}"
        logger.error(error_msg)
        raise IntegrityError(error_msg)


#######################################
# Integrity Verification Functions
#######################################

def verify_integrity(directory: Union[str, Path],
                    baseline_file: Union[str, Path],
                    algorithm: Optional[str] = None,
                    report_file: Optional[Union[str, Path]] = None,
                    alert_on_failure: bool = False) -> IntegrityResult:
    """
    Verify the integrity of files in a directory against a baseline.

    Args:
        directory: Directory to verify
        baseline_file: Path to baseline file
        algorithm: Override the hash algorithm (uses first from baseline if None)
        report_file: Optional path to save the verification report
        alert_on_failure: Whether to send alerts on integrity failures

    Returns:
        IntegrityResult containing verification status and violations

    Raises:
        FileNotFoundError: If directory or baseline file doesn't exist
        IntegrityError: If there's an error during verification
    """
    directory = Path(directory)
    baseline_path = Path(baseline_file)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    result = IntegrityResult(
        is_valid=True,
        violations=[],
        checked_files=0,
        baseline_files=0
    )

    start_time = time.time()

    try:
        # Load baseline
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        baseline_files = baseline.get("files", {})
        result.baseline_files = len(baseline_files)

        # Get metadata from baseline
        metadata = baseline.get("metadata", {})
        baseline_algorithms = metadata.get("algorithms", [DEFAULT_HASH_ALGORITHM])

        # Use specified algorithm or first from baseline
        verification_algorithm = algorithm or baseline_algorithms[0]

        # Check each file in the baseline
        for rel_path_str, expected_info in baseline_files.items():
            try:
                file_path = directory / rel_path_str

                # Check if file exists
                if not file_path.exists():
                    violation = Violation(
                        file_path=rel_path_str,
                        reason="missing",
                        severity=Severity.HIGH,
                        expected_hash=expected_info.get("hashes", {}).get(verification_algorithm, "")
                    )
                    result.violations.append(violation)
                    result.is_valid = False
                    continue

                # Check if it's a file
                if not file_path.is_file():
                    violation = Violation(
                        file_path=rel_path_str,
                        reason="not_a_file",
                        severity=Severity.HIGH
                    )
                    result.violations.append(violation)
                    result.is_valid = False
                    continue

                # Get expected hash
                expected_hashes = expected_info.get("hashes", {})
                if verification_algorithm not in expected_hashes:
                    logger.warning(f"Algorithm {verification_algorithm} not found in baseline for {rel_path_str}")
                    # Try to fall back to another algorithm if available
                    if baseline_algorithms:
                        verification_algorithm = baseline_algorithms[0]

                expected_hash = expected_hashes.get(verification_algorithm, "")
                if not expected_hash:
                    logger.warning(f"No hash found for {rel_path_str} with algorithm {verification_algorithm}")
                    continue

                # Calculate current hash
                current_hash = calculate_file_hash(file_path, verification_algorithm)
                result.checked_files += 1

                # Compare hashes
                if current_hash != expected_hash:
                    violation = Violation(
                        file_path=rel_path_str,
                        reason="modified",
                        severity=Severity.HIGH,
                        expected_hash=expected_hash,
                        current_hash=current_hash
                    )
                    result.violations.append(violation)
                    result.is_valid = False

                # Check permissions if they were included in baseline
                if "mode" in expected_info:
                    try:
                        current_metadata = get_file_metadata(file_path)
                        expected_mode = expected_info.get("mode")
                        current_mode = current_metadata.get("mode")

                        if expected_mode != current_mode:
                            violation = Violation(
                                file_path=rel_path_str,
                                reason="permissions_changed",
                                severity=Severity.MEDIUM,
                                expected_hash=f"mode:{expected_mode:o}",
                                current_hash=f"mode:{current_mode:o}"
                            )
                            result.violations.append(violation)
                            result.is_valid = False
                    except (OSError, IOError) as e:
                        logger.warning(f"Could not check permissions for {file_path}: {e}")

                # Check ownership if included in baseline
                if "owner" in expected_info and "group" in expected_info:
                    try:
                        current_metadata = get_file_metadata(file_path)
                        expected_owner = expected_info.get("owner")
                        expected_group = expected_info.get("group")
                        current_owner = current_metadata.get("owner")
                        current_group = current_metadata.get("group")

                        if expected_owner != current_owner or expected_group != current_group:
                            violation = Violation(
                                file_path=rel_path_str,
                                reason="ownership_changed",
                                severity=Severity.MEDIUM,
                                expected_hash=f"{expected_owner}:{expected_group}",
                                current_hash=f"{current_owner}:{current_group}"
                            )
                            result.violations.append(violation)
                            result.is_valid = False
                    except (OSError, IOError) as e:
                        logger.warning(f"Could not check ownership for {file_path}: {e}")

            except (OSError, IOError) as e:
                logger.warning(f"Error checking file {rel_path_str}: {e}")
                violation = Violation(
                    file_path=rel_path_str,
                    reason=f"error: {str(e)}",
                    severity=Severity.MEDIUM
                )
                result.violations.append(violation)
                result.is_valid = False

        # Log result
        if result.is_valid:
            logger.info(f"Integrity verification passed for {result.checked_files} files")
        else:
            logger.warning(f"Integrity verification failed with {len(result.violations)} violations")

            # Send notification if requested
            if alert_on_failure and NOTIFICATION_AVAILABLE:
                critical_count = sum(1 for v in result.violations if v.severity == Severity.CRITICAL)
                high_count = sum(1 for v in result.violations if v.severity == Severity.HIGH)

                priority = "high" if critical_count > 0 or high_count > 0 else "medium"

                send_notification(
                    title="File Integrity Verification Failed",
                    message=f"Found {len(result.violations)} integrity violations. " +
                            f"Critical: {critical_count}, High: {high_count}",
                    priority=priority,
                    category="security"
                )

        # Save report if requested
        if report_file:
            report_path = Path(report_file)
            report_path.parent.mkdir(parents=True, exist_ok=True)

            report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "directory": str(directory),
                "baseline": str(baseline_path),
                "algorithm": verification_algorithm,
                "passed": result.is_valid,
                "checked_files": result.checked_files,
                "baseline_files": result.baseline_files,
                "violations": [v.to_dict() for v in result.violations],
                "execution_time": time.time() - start_time
            }

            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)

            logger.info(f"Saved integrity report to {report_path}")

            # Secure the report file
            try:
                os.chmod(report_path, 0o640)
            except OSError:
                logger.warning(f"Could not set secure permissions on {report_path}")

    except (IOError, json.JSONDecodeError) as e:
        error_msg = f"Error during integrity verification: {str(e)}"
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        raise IntegrityError(error_msg)

    # Add execution time
    result.execution_time = time.time() - start_time

    return result


def verify_file_integrity(file_path: Union[str, Path],
                         baseline_file: Union[str, Path],
                         algorithm: Optional[str] = None) -> bool:
    """
    Verify the integrity of a single file against a baseline.

    Args:
        file_path: Path to the file to verify
        baseline_file: Path to baseline file
        algorithm: Override the hash algorithm

    Returns:
        True if file integrity is verified, False otherwise

    Raises:
        FileNotFoundError: If the file or baseline doesn't exist
        IntegrityError: If there's an error during verification
    """
    file_path = Path(file_path)
    baseline_path = Path(baseline_file)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    try:
        # Load baseline
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        baseline_files = baseline.get("files", {})

        # Get metadata from baseline
        metadata = baseline.get("metadata", {})
        baseline_dir = Path(metadata.get("directory", ""))
        baseline_algorithms = metadata.get("algorithms", [DEFAULT_HASH_ALGORITHM])

        # Use specified algorithm or first from baseline
        verification_algorithm = algorithm or baseline_algorithms[0]

        # Determine relative path to the file
        try:
            rel_path = file_path.relative_to(baseline_dir)
            rel_path_str = str(rel_path)
        except ValueError:
            # If file is not relative to baseline directory, use full path
            rel_path_str = str(file_path)

        # Check if file is in baseline
        if rel_path_str not in baseline_files:
            logger.warning(f"File {rel_path_str} not found in baseline")
            return False

        # Get expected hash
        expected_info = baseline_files[rel_path_str]
        expected_hashes = expected_info.get("hashes", {})

        if verification_algorithm not in expected_hashes:
            logger.warning(f"Algorithm {verification_algorithm} not found in baseline for {rel_path_str}")
            # Fall back to another algorithm if available
            if baseline_algorithms:
                verification_algorithm = baseline_algorithms[0]

        expected_hash = expected_hashes.get(verification_algorithm, "")
        if not expected_hash:
            logger.warning(f"No hash found for {rel_path_str} with algorithm {verification_algorithm}")
            return False

        # Calculate current hash
        current_hash = calculate_file_hash(file_path, verification_algorithm)

        # Compare hashes
        return current_hash == expected_hash

    except (IOError, json.JSONDecodeError) as e:
        error_msg = f"Error verifying file integrity: {str(e)}"
        logger.error(error_msg)
        raise IntegrityError(error_msg)


#######################################
# Extended Integrity Functions
#######################################

def detect_new_files(directory: Union[str, Path],
                    baseline_file: Union[str, Path],
                    exclude_patterns: Optional[List[str]] = None) -> List[str]:
    """
    Detect files that exist in directory but not in the baseline.

    Args:
        directory: Directory to check
        baseline_file: Path to baseline file
        exclude_patterns: Patterns to exclude from scanning

    Returns:
        List of paths to new files not in the baseline
    """
    directory = Path(directory)
    baseline_path = Path(baseline_file)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    # Use default exclude patterns if none provided
    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDE_PATTERNS

    try:
        # Load baseline
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        # Get files from baseline
        baseline_files = baseline.get("files", {})
        baseline_file_paths = set(baseline_files.keys())

        # Get baseline metadata
        metadata = baseline.get("metadata", {})
        recursive = metadata.get("recursive", True)

        # Get current files
        current_files = []

        if recursive:
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = Path(root) / filename
                    rel_path = file_path.relative_to(directory)
                    current_files.append(str(rel_path))
        else:
            for file_path in directory.iterdir():
                if file_path.is_file():
                    rel_path = file_path.relative_to(directory)
                    current_files.append(str(rel_path))

        # Filter out excluded files
        if exclude_patterns:
            current_files = [
                path for path in current_files
                if not any(fnmatch.fnmatch(path, pattern) for pattern in exclude_patterns)
            ]

        # Find new files
        new_files = [path for path in current_files if path not in baseline_file_paths]

        return sorted(new_files)

    except (IOError, json.JSONDecodeError) as e:
        error_msg = f"Error detecting new files: {str(e)}"
        logger.error(error_msg)
        raise IntegrityError(error_msg)


def verify_critical_files(critical_paths: List[Union[str, Path]],
                         baseline_file: Optional[Union[str, Path]] = None,
                         expected_hashes: Optional[Dict[str, str]] = None,
                         algorithm: str = DEFAULT_HASH_ALGORITHM) -> IntegrityResult:
    """
    Verify the integrity of critical files using either a baseline or expected hashes.

    Args:
        critical_paths: List of critical file paths to verify
        baseline_file: Path to baseline file (optional)
        expected_hashes: Dictionary of path to expected hash (optional)
        algorithm: Hash algorithm to use

    Returns:
        IntegrityResult with verification status and violations
    """
    if baseline_file is None and expected_hashes is None:
        raise ValueError("Either baseline_file or expected_hashes must be provided")

    result = IntegrityResult(
        is_valid=True,
        violations=[],
        checked_files=0,
        baseline_files=len(critical_paths)
    )

    start_time = time.time()

    try:
        # Load baseline if provided
        if baseline_file:
            baseline_path = Path(baseline_file)

            if not baseline_path.exists():
                raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

            with open(baseline_path, 'r') as f:
                baseline = json.load(f)

            baseline_files = baseline.get("files", {})

            # Get metadata from baseline
            metadata = baseline.get("metadata", {})
            baseline_algorithms = metadata.get("algorithms", [DEFAULT_HASH_ALGORITHM])

            # Use specified algorithm or first from baseline
            verification_algorithm = algorithm or baseline_algorithms[0]
        else:
            # Use provided expected hashes
            baseline_files = {}  # We won't use this
            verification_algorithm = algorithm

        # Check each critical file
        for file_path_str in critical_paths:
            file_path = Path(file_path_str)

            if not file_path.exists():
                violation = Violation(
                    file_path=str(file_path),
                    reason="missing",
                    severity=Severity.CRITICAL
                )
                result.violations.append(violation)
                result.is_valid = False
                continue

            if not file_path.is_file():
                violation = Violation(
                    file_path=str(file_path),
                    reason="not_a_file",
                    severity=Severity.CRITICAL
                )
                result.violations.append(violation)
                result.is_valid = False
                continue

            try:
                # Calculate current hash
                current_hash = calculate_file_hash(file_path, verification_algorithm)
                result.checked_files += 1

                # Get expected hash
                if baseline_file:
                    # Use relative path if in baseline directory
                    baseline_dir = Path(metadata.get("directory", ""))
                    try:
                        rel_path = file_path.relative_to(baseline_dir)
                        rel_path_str = str(rel_path)
                    except ValueError:
                        # If not in baseline directory, use full path
                        rel_path_str = str(file_path)

                    if rel_path_str not in baseline_files:
                        logger.warning(f"Critical file {file_path} not found in baseline")
                        violation = Violation(
                            file_path=str(file_path),
                            reason="not_in_baseline",
                            severity=Severity.HIGH
                        )
                        result.violations.append(violation)
                        result.is_valid = False
                        continue

                    expected_info = baseline_files[rel_path_str]
                    expected_hashes_dict = expected_info.get("hashes", {})
                    expected_hash = expected_hashes_dict.get(verification_algorithm, "")
                else:
                    # Use provided expected hash
                    expected_hash = expected_hashes.get(str(file_path), "")

                if not expected_hash:
                    logger.warning(f"No expected hash for critical file {file_path}")
                    violation = Violation(
                        file_path=str(file_path),
                        reason="no_expected_hash",
                        severity=Severity.MEDIUM
                    )
                    result.violations.append(violation)
                    result.is_valid = False
                    continue

                # Compare hashes
                if current_hash != expected_hash:
                    violation = Violation(
                        file_path=str(file_path),
                        reason="modified",
                        severity=Severity.CRITICAL,
                        expected_hash=expected_hash,
                        current_hash=current_hash
                    )
                    result.violations.append(violation)
                    result.is_valid = False

            except (OSError, IOError) as e:
                logger.warning(f"Error checking critical file {file_path}: {e}")
                violation = Violation(
                    file_path=str(file_path),
                    reason=f"error: {str(e)}",
                    severity=Severity.HIGH
                )
                result.violations.append(violation)
                result.is_valid = False

        # Log result
        if result.is_valid:
            logger.info(f"Critical file integrity verification passed for {result.checked_files} files")
        else:
            logger.warning(f"Critical file integrity verification failed with {len(result.violations)} violations")

            # Send notification for critical file violations
            if NOTIFICATION_AVAILABLE:
                send_notification(
                    title="Critical File Integrity Verification Failed",
                    message=f"Found {len(result.violations)} integrity violations in critical files.",
                    priority="high",
                    category="security"
                )

    except Exception as e:
        error_msg = f"Error verifying critical files: {str(e)}"
        logger.error(error_msg)
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        raise IntegrityError(error_msg, severity=Severity.HIGH)

    # Add execution time
    result.execution_time = time.time() - start_time

    return result


def schedule_integrity_check(directory: Union[str, Path],
                           baseline_file: Union[str, Path],
                           interval: int = 3600,
                           report_dir: Optional[Union[str, Path]] = None,
                           alert_on_failure: bool = True) -> None:
    """
    Schedule periodic integrity checks.

    This function sets up a background thread to run integrity checks
    at the specified interval. It requires the 'schedule' package.

    Args:
        directory: Directory to verify
        baseline_file: Path to baseline file
        interval: Check interval in seconds (default: 1 hour)
        report_dir: Directory to save reports (optional)
        alert_on_failure: Whether to send alerts on integrity failures
    """
    try:
        import schedule
        import threading
        import time
    except ImportError:
        logger.error("Cannot schedule integrity checks: 'schedule' package not installed")
        return

    directory_path = Path(directory)
    baseline_path = Path(baseline_file)

    if not directory_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory_path}")

    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    if report_dir:
        report_dir_path = Path(report_dir)
        report_dir_path.mkdir(parents=True, exist_ok=True)

    def run_check():
        """Run the integrity check and save report."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = None

            if report_dir:
                report_path = Path(report_dir) / f"integrity_report_{timestamp}.json"

            result = verify_integrity(
                directory=directory_path,
                baseline_file=baseline_path,
                report_file=report_path,
                alert_on_failure=alert_on_failure
            )

            if result.is_valid:
                logger.info("Scheduled integrity check passed")
            else:
                logger.warning(f"Scheduled integrity check failed with {len(result.violations)} violations")

        except Exception as e:
            logger.error(f"Error during scheduled integrity check: {e}")

    def run_scheduler():
        """Run the scheduler in a background thread."""
        schedule.every(interval).seconds.do(run_check)

        while True:
            schedule.run_pending()
            time.sleep(1)

    # Run first check immediately
    run_check()

    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

    logger.info(f"Scheduled integrity checks every {interval} seconds")


#######################################
# Notification and Reporting
#######################################

def generate_integrity_report(results: List[IntegrityResult],
                            output_file: Optional[Union[str, Path]] = None,
                            format: str = "json") -> str:
    """
    Generate a comprehensive integrity report from multiple results.

    Args:
        results: List of IntegrityResult objects
        output_file: File to save the report (optional)
        format: Report format ('json' or 'html')

    Returns:
        Report content as a string
    """
    if not results:
        return "No results to report"

    # Aggregate results
    total_files_checked = sum(r.checked_files for r in results)
    total_baseline_files = sum(r.baseline_files for r in results)
    all_violations = []
    for result in results:
        all_violations.extend(result.violations)

    passed = all(r.is_valid for r in results)

    # Create report data
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "total_files_checked": total_files_checked,
        "total_baseline_files": total_baseline_files,
        "total_violations": len(all_violations),
        "violations": [v.to_dict() for v in all_violations],
        "results": [r.to_dict() for r in results]
    }

    # Generate report in requested format
    if format == "json":
        report_content = json.dumps(report_data, indent=2)
    elif format == "html":
        # Simple HTML report
        violations_html = ""
        for v in all_violations:
            severity_class = {
                Severity.CRITICAL: "critical",
                Severity.HIGH: "high",
                Severity.MEDIUM: "medium",
                Severity.LOW: "low"
            }.get(v.severity, "medium")

            violations_html += f"""
            <tr class="{severity_class}">
                <td>{v.file_path}</td>
                <td>{v.reason}</td>
                <td>{v.severity}</td>
                <td>{v.expected_hash or 'N/A'}</td>
                <td>{v.current_hash or 'N/A'}</td>
            </tr>
            """

        report_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>File Integrity Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ margin: 20px 0; padding: 10px; background-color: #f5f5f5; }}
                .passed {{ color: green; }}
                .failed {{ color: red; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr.critical {{ background-color: #ffdddd; }}
                tr.high {{ background-color: #ffeedd; }}
                tr.medium {{ background-color: #ffffdd; }}
                tr.low {{ background-color: #f8f8f8; }}
            </style>
        </head>
        <body>
            <h1>File Integrity Report</h1>
            <div class="summary">
                <p><strong>Timestamp:</strong> {datetime.now()}</p>
                <p><strong>Status:</strong> <span class="{'passed' if passed else 'failed'}">
                    {'PASSED' if passed else 'FAILED'}</span></p>
                <p><strong>Files Checked:</strong> {total_files_checked} of {total_baseline_files}</p>
                <p><strong>Violations:</strong> {len(all_violations)}</p>
            </div>

            <h2>Violations</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Reason</th>
                    <th>Severity</th>
                    <th>Expected Hash</th>
                    <th>Current Hash</th>
                </tr>
                {violations_html}
            </table>
        </body>
        </html>
        """
    else:
        raise ValueError(f"Unsupported report format: {format}")

    # Save to file if requested
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.write(report_content)

        # Set secure permissions
        try:
            os.chmod(output_path, 0o640)
        except OSError:
            logger.warning(f"Could not set secure permissions on {output_path}")

        logger.info(f"Saved integrity report to {output_path}")

    return report_content


#######################################
# Command-Line Interface
#######################################

def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description="File integrity verification tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create baseline command
    create_parser = subparsers.add_parser("create", help="Create integrity baseline")
    create_parser.add_argument("directory", help="Directory to create baseline for")
    create_parser.add_argument("output", help="Output baseline file")
    create_parser.add_argument("--algorithm", "-a", help="Hash algorithm to use", default=DEFAULT_HASH_ALGORITHM)
    create_parser.add_argument("--exclude", "-e", action="append", help="Glob patterns to exclude")
    create_parser.add_argument("--include", "-i", action="append", help="Glob patterns to include")
    create_parser.add_argument("--no-recursive", action="store_false", dest="recursive", help="Don't scan subdirectories")
    create_parser.add_argument("--no-metadata", action="store_false", dest="metadata", help="Don't include file metadata")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify integrity against baseline")
    verify_parser.add_argument("directory", help="Directory to verify")
    verify_parser.add_argument("baseline", help="Baseline file to use")
    verify_parser.add_argument("--algorithm", "-a", help="Override hash algorithm")
    verify_parser.add_argument("--report", "-r", help="Output report file")
    verify_parser.add_argument("--alert", action="store_true", help="Send alerts on failures")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update integrity baseline")
    update_parser.add_argument("directory", help="Directory to update baseline for")
    update_parser.add_argument("baseline", help="Baseline file to update")
    update_parser.add_argument("--approver", "-a", required=True, help="Name/ID of person approving changes")
    update_parser.add_argument("--comment", "-c", help="Comment explaining reason for update")
    update_parser.add_argument("--no-backup", action="store_false", dest="backup", help="Don't create backup of old baseline")

    # Check specific file command
    check_parser = subparsers.add_parser("check", help="Check integrity of a specific file")
    check_parser.add_argument("file", help="File to verify")
    check_parser.add_argument("baseline", help="Baseline file to use")
    check_parser.add_argument("--algorithm", "-a", help="Override hash algorithm")

    # Show new files command
    new_parser = subparsers.add_parser("new", help="Show files not in baseline")
    new_parser.add_argument("directory", help="Directory to check")
    new_parser.add_argument("baseline", help="Baseline file to use")
    new_parser.add_argument("--exclude", "-e", action="append", help="Glob patterns to exclude")

    args = parser.parse_args()

    try:
        if args.command == "create":
            result = create_baseline(
                directory=args.directory,
                output_file=args.output,
                algorithms=[args.algorithm],
                exclude_patterns=args.exclude,
                include_patterns=args.include,
                recursive=args.recursive,
                include_metadata=args.metadata
            )
            print(f"Created baseline with {result.file_count} files at {args.output}")
            if result.excluded_files:
                print(f"Excluded {result.excluded_files} files")
            if result.errors:
                print(f"Encountered {len(result.errors)} errors:")
                for error in result.errors:
                    print(f"  - {error}")

        elif args.command == "verify":
            result = verify_integrity(
                directory=args.directory,
                baseline_file=args.baseline,
                algorithm=args.algorithm,
                report_file=args.report,
                alert_on_failure=args.alert
            )

            if result.is_valid:
                print(f"✓ Integrity verification passed for {result.checked_files} files")
                return 0
            else:
                print(f"✗ Integrity verification failed with {len(result.violations)} violations:")
                for i, violation in enumerate(result.violations, 1):
                    print(f"  {i}. {violation.file_path}: {violation.reason} (Severity: {violation.severity})")
                return 1

        elif args.command == "update":
            result = update_baseline(
                directory=args.directory,
                baseline_file=args.baseline,
                changes_approved_by=args.approver,
                comment=args.comment or "",
                keep_history=args.backup
            )
            print(f"Updated baseline with {result.file_count} files")
            if args.backup:
                print("Created backup of previous baseline")
            if result.errors:
                print(f"Encountered {len(result.errors)} errors:")
                for error in result.errors:
                    print(f"  - {error}")

        elif args.command == "check":
            is_valid = verify_file_integrity(
                file_path=args.file,
                baseline_file=args.baseline,
                algorithm=args.algorithm
            )

            if is_valid:
                print(f"✓ File integrity verified: {args.file}")
                return 0
            else:
                print(f"✗ File integrity check failed: {args.file}")
                return 1

        elif args.command == "new":
            new_files = detect_new_files(
                directory=args.directory,
                baseline_file=args.baseline,
                exclude_patterns=args.exclude
            )

            if new_files:
                print(f"Found {len(new_files)} files not in baseline:")
                for file in new_files:
                    print(f"  - {file}")
            else:
                print("No new files detected")

        else:
            parser.print_help()

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
