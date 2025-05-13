#!/usr/bin/env python3
# filepath: scripts/core/security/permissions.py
"""
Secure file and directory permissions management for Cloud Infrastructure Platform.

This module provides functions to check, set, and audit file and directory permissions,
enforcing security baselines and preventing common permission-related vulnerabilities.
It implements platform-aware permission management that follows security best practices
from NIST, CIS benchmarks, and other security standards.

Key features:
- Permission validation against security baselines
- Recursive permission application
- Security-focused permission patterns
- Ownership verification
- SUID/SGID detection
- World-writable file detection
- Executable stack detection
- Compliance checking against standards
- Permission audit logging
- Platform-aware permission handling
- Security policy enforcement
"""

import os
import sys
import stat
import logging
import grp
import pwd
import json
import fnmatch
import platform
import shutil
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Union, Any, NamedTuple, BinaryIO
import time

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

try:
    from scripts.core.config_loader import load_config
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    logger.warning("Config loader not available, using default settings")
    CONFIG_LOADER_AVAILABLE = False

# Constants
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MACOS = platform.system() == 'Darwin'

# Default permission masks
DEFAULT_FILE_MODE = 0o644        # -rw-r--r--
DEFAULT_DIRECTORY_MODE = 0o755   # drwxr-xr-x
DEFAULT_SCRIPT_MODE = 0o750      # -rwxr-x---
DEFAULT_CONFIG_MODE = 0o640      # -rw-r-----
DEFAULT_SENSITIVE_MODE = 0o600   # -rw-------
DEFAULT_SECURE_DIR_MODE = 0o700  # drwx------

# Security baselines by environment
PERMISSION_BASELINES = {
    "development": {
        "file": 0o644,
        "directory": 0o755,
        "script": 0o750,
        "config": 0o640,
        "sensitive": 0o600,
        "secure_dir": 0o750,
    },
    "staging": {
        "file": 0o644,
        "directory": 0o755,
        "script": 0o750,
        "config": 0o640,
        "sensitive": 0o600,
        "secure_dir": 0o750,
    },
    "production": {
        "file": 0o644,
        "directory": 0o750,
        "script": 0o750,
        "config": 0o640,
        "sensitive": 0o600,
        "secure_dir": 0o700,
    }
}

# Default baseline
CURRENT_BASELINE = PERMISSION_BASELINES["production"]

# Load environment-specific settings
if CONFIG_LOADER_AVAILABLE:
    try:
        env = load_config("environment", "current", default="production")
        if env in PERMISSION_BASELINES:
            CURRENT_BASELINE = PERMISSION_BASELINES[env]
    except Exception as e:
        logger.warning(f"Could not load environment configuration: {e}")

# Special file paths
SENSITIVE_FILE_PATTERNS = [
    "*.key", "*.pem", "*.cert", "*.crt", "*.jks", "*.p12", "*.pfx",
    "*.pass", "*.password", "passwd", "shadow", "*credential*", "*secret*",
    "*.token", "*.env", "*.conf", "*.config", ".ssh/*", "authorized_keys",
    "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
]

# Directories that should not have world-readable or writable permissions
SECURE_DIRECTORY_PATTERNS = [
    ".ssh", "config", "conf.d", "certs", "certificates", "keys", "security",
    "credentials", "secrets", "secure", "private", "tokens"
]


class PermissionSeverity(str, Enum):
    """Severity levels for permission violations."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PermissionType(str, Enum):
    """Types of permission objects."""
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    SOCKET = "socket"
    FIFO = "fifo"
    BLOCK_DEVICE = "block_device"
    CHAR_DEVICE = "char_device"
    UNKNOWN = "unknown"


class PermissionError(ApplicationError):
    """Exception raised for permission-related errors."""
    def __init__(self, message: str, severity: PermissionSeverity = PermissionSeverity.MEDIUM):
        super().__init__(message)
        self.severity = severity
        self.category = ErrorCategory.SECURITY


@dataclass
class PermissionViolation:
    """Represents a permission security violation."""
    path: str
    issue: str
    severity: PermissionSeverity
    current_mode: int
    expected_mode: Optional[int] = None
    current_owner: Optional[str] = None
    expected_owner: Optional[str] = None
    current_group: Optional[str] = None
    expected_group: Optional[str] = None
    object_type: PermissionType = PermissionType.FILE
    timestamp: float = field(default_factory=datetime.now().timestamp)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = asdict(self)
        result["current_mode_octal"] = oct(self.current_mode)
        if self.expected_mode is not None:
            result["expected_mode_octal"] = oct(self.expected_mode)
        return result

    @property
    def is_critical(self) -> bool:
        """Return True if this is a critical severity violation."""
        return self.severity == PermissionSeverity.CRITICAL


@dataclass
class AuditResult:
    """Result of a permission audit operation."""
    violations: List[PermissionViolation] = field(default_factory=list)
    checked_files: int = 0
    checked_directories: int = 0
    execution_time: float = 0
    timestamp: float = field(default_factory=datetime.now().timestamp)

    @property
    def has_violations(self) -> bool:
        """Return True if any violations were found."""
        return len(self.violations) > 0

    @property
    def critical_count(self) -> int:
        """Return the count of critical violations."""
        return sum(1 for v in self.violations if v.severity == PermissionSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return the count of high severity violations."""
        return sum(1 for v in self.violations if v.severity == PermissionSeverity.HIGH)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "violations": [v.to_dict() for v in self.violations],
            "checked_files": self.checked_files,
            "checked_directories": self.checked_directories,
            "has_violations": self.has_violations,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp,
            "timestamp_readable": datetime.fromtimestamp(self.timestamp).isoformat()
        }


#######################################
# Permission Validation Functions
#######################################

def get_object_type(path: Union[str, Path]) -> PermissionType:
    """
    Determine the type of a filesystem object.

    Args:
        path: Path to the object

    Returns:
        PermissionType indicating the type of object
    """
    path = Path(path)

    try:
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        if path.is_symlink():
            return PermissionType.SYMLINK
        elif path.is_file():
            return PermissionType.FILE
        elif path.is_dir():
            return PermissionType.DIRECTORY
        elif path.is_socket():
            return PermissionType.SOCKET
        elif path.is_fifo():
            return PermissionType.FIFO
        elif path.is_block_device():
            return PermissionType.BLOCK_DEVICE
        elif path.is_char_device():
            return PermissionType.CHAR_DEVICE
        else:
            return PermissionType.UNKNOWN

    except Exception as e:
        logger.debug(f"Error determining object type for {path}: {str(e)}")
        return PermissionType.UNKNOWN


def check_file_permissions(path: Union[str, Path], mode: int = None,
                         owner: Optional[str] = None, group: Optional[str] = None,
                         file_type: Optional[str] = None) -> bool:
    """
    Check if file has secure permissions according to specified requirements.

    Args:
        path: Path to check permissions on
        mode: Expected permission mode (octal)
        owner: Expected owner username
        group: Expected group name
        file_type: Type hint for appropriate default mode (file, directory, script, config, sensitive)

    Returns:
        True if permissions match requirements, False otherwise
    """
    path = Path(path)

    try:
        if not path.exists():
            logger.warning(f"Path does not exist: {path}")
            return False

        # Get file stats
        stat_info = path.stat()
        current_mode = stat_info.st_mode & 0o777  # Get permission bits

        # Determine expected mode if not provided
        if mode is None:
            if file_type is None:
                # Auto-detect file type
                if path.is_dir():
                    file_type = "directory"
                elif path.is_file():
                    if path.suffix.lower() in (".sh", ".py", ".rb", ".pl"):
                        file_type = "script"
                    elif path.suffix.lower() in (".conf", ".ini", ".json", ".yaml", ".yml", ".xml", ".env"):
                        file_type = "config"
                    elif any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                        file_type = "sensitive"
                    else:
                        file_type = "file"

            # Set expected mode based on file type
            mode = CURRENT_BASELINE.get(file_type, DEFAULT_FILE_MODE)

        # Check mode
        if current_mode > mode:  # More permissive than allowed
            logger.debug(f"File {path} has mode {oct(current_mode)}, expected {oct(mode)}")
            return False

        # Check owner if specified
        if owner is not None:
            try:
                current_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if current_owner != owner:
                    logger.debug(f"File {path} has owner {current_owner}, expected {owner}")
                    return False
            except (KeyError, ImportError):
                # Skip owner check if we can't resolve the name or on Windows
                pass

        # Check group if specified
        if group is not None:
            try:
                current_group = grp.getgrgid(stat_info.st_gid).gr_name
                if current_group != group:
                    logger.debug(f"File {path} has group {current_group}, expected {group}")
                    return False
            except (KeyError, ImportError):
                # Skip group check if we can't resolve the name or on Windows
                pass

        return True

    except Exception as e:
        logger.error(f"Error checking file permissions: {str(e)}")
        return False


def is_world_writable(path: Union[str, Path]) -> bool:
    """
    Check if a file or directory is world-writable.

    Args:
        path: Path to check

    Returns:
        True if world-writable, False otherwise
    """
    path = Path(path)

    try:
        if not path.exists():
            return False

        stat_info = path.stat()
        mode = stat_info.st_mode

        # Check if world-writable (mode & 0o002)
        return bool(mode & 0o002)

    except Exception as e:
        logger.error(f"Error checking if {path} is world-writable: {str(e)}")
        return False


def is_setuid_setgid(path: Union[str, Path]) -> Tuple[bool, bool]:
    """
    Check if a file has SUID or SGID bits set.

    Args:
        path: Path to check

    Returns:
        Tuple of (is_setuid, is_setgid)
    """
    if IS_WINDOWS:
        return False, False

    path = Path(path)

    try:
        if not path.exists() or not path.is_file():
            return False, False

        stat_info = path.stat()
        mode = stat_info.st_mode

        # Check SUID (mode & 0o4000) and SGID (mode & 0o2000)
        is_setuid = bool(mode & 0o4000)
        is_setgid = bool(mode & 0o2000)

        return is_setuid, is_setgid

    except Exception as e:
        logger.error(f"Error checking SUID/SGID for {path}: {str(e)}")
        return False, False


def is_executable_stack(path: Union[str, Path]) -> bool:
    """
    Check if a binary has executable stack enabled (Linux only).

    Args:
        path: Path to binary to check

    Returns:
        True if executable stack is enabled, False otherwise
    """
    if not IS_LINUX:
        return False

    path = Path(path)

    try:
        if not path.exists() or not path.is_file():
            return False

        # Use readelf to check for executable stack
        try:
            import subprocess
            result = subprocess.run(
                ["readelf", "-l", str(path)],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode == 0:
                # Look for "GNU_STACK" with "RWE" flags (executable)
                return "GNU_STACK" in result.stdout and "RWE" in result.stdout

        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return False

    except Exception as e:
        logger.error(f"Error checking executable stack for {path}: {str(e)}")
        return False


def get_file_owner_group(path: Union[str, Path]) -> Tuple[Optional[str], Optional[str]]:
    """
    Get the owner and group of a file as strings.

    Args:
        path: Path to check

    Returns:
        Tuple of (owner_name, group_name)
    """
    path = Path(path)

    try:
        if not path.exists():
            return None, None

        stat_info = path.stat()

        # Get owner and group names
        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
        except (KeyError, ImportError):
            owner = str(stat_info.st_uid)

        try:
            group = grp.getgrgid(stat_info.st_gid).gr_name
        except (KeyError, ImportError):
            group = str(stat_info.st_gid)

        return owner, group

    except Exception as e:
        logger.error(f"Error getting owner/group for {path}: {str(e)}")
        return None, None


def check_recursive_permissions(
    path: Union[str, Path],
    dir_mode: int = DEFAULT_DIRECTORY_MODE,
    file_mode: int = DEFAULT_FILE_MODE,
    owner: Optional[str] = None,
    group: Optional[str] = None
) -> Dict[str, List[str]]:
    """
    Recursively check permissions on a directory tree.

    Args:
        path: Root path to check
        dir_mode: Maximum allowed directory permissions
        file_mode: Maximum allowed file permissions
        owner: Expected owner (if specified)
        group: Expected group (if specified)

    Returns:
        Dictionary with keys 'violations' and 'warnings' containing lists of paths
    """
    path = Path(path)
    results = {'violations': [], 'warnings': []}

    try:
        if not path.exists():
            logger.warning(f"Path does not exist: {path}")
            return results

        # Check the root path
        if path.is_dir():
            if not check_file_permissions(path, dir_mode, owner, group):
                results['violations'].append(str(path))
        else:
            if not check_file_permissions(path, file_mode, owner, group):
                results['violations'].append(str(path))
            return results  # Not a directory, return after checking

        # Recursively check subdirectories and files
        for root, dirs, files in os.walk(str(path)):
            # Check directories
            for dirname in dirs:
                dir_path = Path(root) / dirname
                if not check_file_permissions(dir_path, dir_mode, owner, group):
                    results['violations'].append(str(dir_path))

                # Check for insecure directory names that should be more secure
                if any(fnmatch.fnmatch(dirname.lower(), pattern) for pattern in SECURE_DIRECTORY_PATTERNS):
                    if is_world_writable(dir_path):
                        results['violations'].append(f"{dir_path} (secure directory is world-writable)")

            # Check files
            for filename in files:
                file_path = Path(root) / filename

                # Special handling for sensitive files
                if any(fnmatch.fnmatch(filename.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                    if not check_file_permissions(file_path, DEFAULT_SENSITIVE_MODE, owner, group):
                        results['violations'].append(str(file_path))

                    if is_world_writable(file_path):
                        results['violations'].append(f"{file_path} (sensitive file is world-writable)")
                else:
                    # Regular files
                    if not check_file_permissions(file_path, file_mode, owner, group):
                        results['violations'].append(str(file_path))

                # Check for SUID/SGID
                is_setuid, is_setgid = is_setuid_setgid(file_path)
                if is_setuid or is_setgid:
                    flag = "SUID" if is_setuid else "SGID"
                    results['warnings'].append(f"{file_path} ({flag})")

        return results

    except Exception as e:
        logger.error(f"Error checking recursive permissions: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        results['violations'].append(f"Error checking {path}: {str(e)}")
        return results


#######################################
# Permission Modification Functions
#######################################

def set_secure_permissions(
    path: Union[str, Path],
    mode: Optional[int] = None,
    owner: Optional[str] = None,
    group: Optional[str] = None,
    file_type: Optional[str] = None,
    recursive: bool = False
) -> bool:
    """
    Set secure permissions on a file or directory.

    Args:
        path: Path to set permissions on
        mode: Permission mode (octal)
        owner: Owner to set
        group: Group to set
        file_type: Type for default mode selection
        recursive: Whether to apply recursively for directories

    Returns:
        True if successful, False otherwise
    """
    path = Path(path)

    try:
        if not path.exists():
            logger.warning(f"Path does not exist: {path}")
            return False

        # Determine appropriate mode if not provided
        if mode is None:
            if file_type is None:
                # Auto-detect file type
                if path.is_dir():
                    file_type = "directory"
                elif path.is_file():
                    if path.suffix.lower() in (".sh", ".py", ".rb", ".pl"):
                        file_type = "script"
                    elif path.suffix.lower() in (".conf", ".ini", ".json", ".yaml", ".yml", ".xml", ".env"):
                        file_type = "config"
                    elif any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                        file_type = "sensitive"
                    else:
                        file_type = "file"

            # Set mode based on file type
            mode = CURRENT_BASELINE.get(file_type, DEFAULT_FILE_MODE)

        # Set permissions
        os.chmod(path, mode)
        logger.debug(f"Set permissions on {path} to {oct(mode)}")

        # Set owner/group if specified
        if owner is not None or group is not None:
            # Get UID/GID
            uid = -1
            gid = -1

            if owner is not None:
                try:
                    uid = pwd.getpwnam(owner).pw_uid
                except (KeyError, ImportError):
                    logger.warning(f"Could not find user {owner}")
                    return False

            if group is not None:
                try:
                    gid = grp.getgrnam(group).gr_gid
                except (KeyError, ImportError):
                    logger.warning(f"Could not find group {group}")
                    return False

            # Set ownership
            os.chown(path, uid, gid)
            logger.debug(f"Set ownership on {path} to {owner}:{group}")

        # Handle recursive application if requested
        if recursive and path.is_dir():
            if path.is_symlink():
                # Don't follow symlinks for recursive operations
                logger.warning(f"Not following symlink for recursive permission change: {path}")
                return True

            dir_mode = mode
            file_mode = DEFAULT_FILE_MODE

            # Adjust file mode for sensitive directories
            for pattern in SECURE_DIRECTORY_PATTERNS:
                if fnmatch.fnmatch(path.name.lower(), pattern):
                    file_mode = DEFAULT_CONFIG_MODE  # More restrictive
                    break

            for root, dirs, files in os.walk(str(path)):
                # Set directory permissions
                for dirname in dirs:
                    dir_path = os.path.join(root, dirname)
                    try:
                        os.chmod(dir_path, dir_mode)
                        if owner is not None or group is not None:
                            os.chown(dir_path, uid, gid)
                    except Exception as e:
                        logger.warning(f"Could not set permissions on directory {dir_path}: {str(e)}")

                # Set file permissions
                for filename in files:
                    file_path = os.path.join(root, filename)
                    current_file_mode = file_mode

                    # Adjust mode for scripts and sensitive files
                    if filename.endswith((".sh", ".py", ".rb", ".pl")):
                        current_file_mode = DEFAULT_SCRIPT_MODE
                    elif any(fnmatch.fnmatch(filename.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                        current_file_mode = DEFAULT_SENSITIVE_MODE

                    try:
                        os.chmod(file_path, current_file_mode)
                        if owner is not None or group is not None:
                            os.chown(file_path, uid, gid)
                    except Exception as e:
                        logger.warning(f"Could not set permissions on file {file_path}: {str(e)}")

        return True

    except Exception as e:
        logger.error(f"Error setting secure permissions: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        return False


def fix_permissions(
    violations: List[Union[PermissionViolation, str]],
    dry_run: bool = True,
    log_changes: bool = True
) -> Dict[str, int]:
    """
    Fix permission violations identified by audit.

    Args:
        violations: List of violations to fix (PermissionViolation objects or paths)
        dry_run: If True, only report what would be changed without making changes
        log_changes: Whether to log all changes

    Returns:
        Dictionary with counts of successful, failed, and skipped fixes
    """
    results = {
        "successful": 0,
        "failed": 0,
        "skipped": 0
    }

    for violation in violations:
        try:
            # Handle different types of input
            if isinstance(violation, PermissionViolation):
                path = violation.path
                expected_mode = violation.expected_mode
                expected_owner = violation.expected_owner
                expected_group = violation.expected_group
            else:
                # Assume it's a string path
                path = str(violation)
                expected_mode = None
                expected_owner = None
                expected_group = None

            path_obj = Path(path)
            if not path_obj.exists():
                logger.warning(f"Path no longer exists: {path}")
                results["skipped"] += 1
                continue

            # Determine appropriate mode if not provided
            if expected_mode is None:
                if path_obj.is_dir():
                    expected_mode = CURRENT_BASELINE.get("directory", DEFAULT_DIRECTORY_MODE)
                elif path_obj.is_file():
                    if path_obj.suffix.lower() in (".sh", ".py", ".rb", ".pl"):
                        expected_mode = CURRENT_BASELINE.get("script", DEFAULT_SCRIPT_MODE)
                    elif path_obj.suffix.lower() in (".conf", ".ini", ".json", ".yaml", ".yml", ".xml", ".env"):
                        expected_mode = CURRENT_BASELINE.get("config", DEFAULT_CONFIG_MODE)
                    elif any(fnmatch.fnmatch(path_obj.name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                        expected_mode = CURRENT_BASELINE.get("sensitive", DEFAULT_SENSITIVE_MODE)
                    else:
                        expected_mode = CURRENT_BASELINE.get("file", DEFAULT_FILE_MODE)

            # Get current mode
            current_mode = path_obj.stat().st_mode & 0o777

            # Skip if already compliant
            if expected_mode is not None and current_mode <= expected_mode:
                results["skipped"] += 1
                continue

            if dry_run:
                if log_changes:
                    logger.info(f"[DRY RUN] Would change permissions on {path} from {oct(current_mode)} to {oct(expected_mode)}")
                results["skipped"] += 1
            else:
                # Apply the fix
                success = set_secure_permissions(
                    path=path,
                    mode=expected_mode,
                    owner=expected_owner,
                    group=expected_group,
                    recursive=False
                )

                if success:
                    results["successful"] += 1
                    if log_changes:
                        logger.info(f"Fixed permissions on {path} from {oct(current_mode)} to {oct(expected_mode)}")
                else:
                    results["failed"] += 1
                    logger.warning(f"Failed to fix permissions on {path}")

        except Exception as e:
            logger.error(f"Error fixing permissions: {str(e)}")
            results["failed"] += 1

    return results


#######################################
# Audit and Analysis Functions
#######################################

def audit_file_permissions(
    path: Union[str, Path],
    expected_mode: Optional[int] = None,
    expected_owner: Optional[str] = None,
    expected_group: Optional[str] = None
) -> List[PermissionViolation]:
    """
    Audit a single file for permission violations.

    Args:
        path: Path to check
        expected_mode: Maximum allowed mode
        expected_owner: Expected owner
        expected_group: Expected group

    Returns:
        List of permission violations
    """
    path = Path(path)
    violations = []

    try:
        if not path.exists():
            violations.append(
                PermissionViolation(
                    path=str(path),
                    issue="File not found",
                    severity=PermissionSeverity.LOW,
                    current_mode=0,
                    expected_mode=expected_mode
                )
            )
            return violations

        # Get object type
        obj_type = get_object_type(path)

        # Get current permissions
        stat_info = path.stat()
        current_mode = stat_info.st_mode & 0o777

        # Get current owner/group
        current_owner, current_group = get_file_owner_group(path)

        # Determine expected mode if not specified
        if expected_mode is None:
            if obj_type == PermissionType.DIRECTORY:
                expected_mode = CURRENT_BASELINE.get("directory", DEFAULT_DIRECTORY_MODE)

                # Check if it's a secure directory type
                if any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in SECURE_DIRECTORY_PATTERNS):
                    expected_mode = CURRENT_BASELINE.get("secure_dir", DEFAULT_SECURE_DIR_MODE)
            elif obj_type == PermissionType.FILE:
                if path.suffix.lower() in (".sh", ".py", ".rb", ".pl"):
                    expected_mode = CURRENT_BASELINE.get("script", DEFAULT_SCRIPT_MODE)
                elif path.suffix.lower() in (".conf", ".ini", ".json", ".yaml", ".yml", ".xml", ".env"):
                    expected_mode = CURRENT_BASELINE.get("config", DEFAULT_CONFIG_MODE)
                elif any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                    expected_mode = CURRENT_BASELINE.get("sensitive", DEFAULT_SENSITIVE_MODE)
                else:
                    expected_mode = CURRENT_BASELINE.get("file", DEFAULT_FILE_MODE)

        # Check mode (if more permissive than expected)
        if expected_mode is not None and current_mode > expected_mode:
            # Determine severity based on permissions
            severity = PermissionSeverity.LOW

            # World-writable is high severity
            if current_mode & 0o002:
                severity = PermissionSeverity.HIGH
                if obj_type == PermissionType.DIRECTORY:
                    severity = PermissionSeverity.CRITICAL
            # World-readable for sensitive files is medium severity
            elif current_mode & 0o004:
                if any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                    severity = PermissionSeverity.MEDIUM

            violations.append(
                PermissionViolation(
                    path=str(path),
                    issue="Excessive permissions",
                    severity=severity,
                    current_mode=current_mode,
                    expected_mode=expected_mode,
                    current_owner=current_owner,
                    expected_owner=expected_owner,
                    current_group=current_group,
                    expected_group=expected_group,
                    object_type=obj_type
                )
            )

        # Check owner
        if expected_owner and current_owner and current_owner != expected_owner:
            violations.append(
                PermissionViolation(
                    path=str(path),
                    issue="Incorrect owner",
                    severity=PermissionSeverity.MEDIUM,
                    current_mode=current_mode,
                    expected_mode=expected_mode,
                    current_owner=current_owner,
                    expected_owner=expected_owner,
                    current_group=current_group,
                    expected_group=expected_group,
                    object_type=obj_type
                )
            )

        # Check group
        if expected_group and current_group and current_group != expected_group:
            violations.append(
                PermissionViolation(
                    path=str(path),
                    issue="Incorrect group",
                    severity=PermissionSeverity.MEDIUM,
                    current_mode=current_mode,
                    expected_mode=expected_mode,
                    current_owner=current_owner,
                    expected_owner=expected_owner,
                    current_group=current_group,
                    expected_group=expected_group,
                    object_type=obj_type
                )
            )

        # Additional security checks for specific file types
        if obj_type == PermissionType.FILE:
            # Check for SUID/SGID bits
            is_setuid, is_setgid = is_setuid_setgid(path)
            if is_setuid:
                violations.append(
                    PermissionViolation(
                        path=str(path),
                        issue="SUID bit set",
                        severity=PermissionSeverity.HIGH,
                        current_mode=current_mode,
                        object_type=obj_type
                    )
                )

            if is_setgid:
                violations.append(
                    PermissionViolation(
                        path=str(path),
                        issue="SGID bit set",
                        severity=PermissionSeverity.MEDIUM,
                        current_mode=current_mode,
                        object_type=obj_type
                    )
                )

            # Check for executable stack in Linux binaries
            if IS_LINUX and is_executable_stack(path):
                violations.append(
                    PermissionViolation(
                        path=str(path),
                        issue="Executable stack",
                        severity=PermissionSeverity.HIGH,
                        current_mode=current_mode,
                        object_type=obj_type
                    )
                )

    except Exception as e:
        logger.error(f"Error auditing file permissions for {path}: {str(e)}")
        violations.append(
            PermissionViolation(
                path=str(path),
                issue=f"Error: {str(e)}",
                severity=PermissionSeverity.MEDIUM,
                current_mode=0,
                expected_mode=expected_mode,
                object_type=PermissionType.UNKNOWN
            )
        )

    return violations


def audit_directory_permissions(
    directory: Union[str, Path],
    recursive: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None,
    expected_dir_mode: Optional[int] = None,
    expected_file_mode: Optional[int] = None,
    expected_owner: Optional[str] = None,
    expected_group: Optional[str] = None,
    security_baseline: str = "production"
) -> AuditResult:
    """
    Audit permissions for a directory tree.

    Args:
        directory: Directory to audit
        recursive: Whether to check subdirectories recursively
        exclude_patterns: File glob patterns to exclude
        include_patterns: File glob patterns to include
        expected_dir_mode: Maximum allowed directory mode
        expected_file_mode: Maximum allowed file mode
        expected_owner: Expected owner
        expected_group: Expected group
        security_baseline: Security baseline name ('development', 'staging', 'production')

    Returns:
        AuditResult with findings
    """
    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    # Set default exclude patterns if not provided
    if exclude_patterns is None:
        exclude_patterns = [
            "*.pyc", "__pycache__", ".git", ".svn", "node_modules",
            "*.tmp", "*.bak", "*.log", ".DS_Store", "Thumbs.db"
        ]

    # Apply baseline if specified
    if security_baseline in PERMISSION_BASELINES:
        baseline = PERMISSION_BASELINES[security_baseline]
        if expected_dir_mode is None:
            expected_dir_mode = baseline.get("directory")
        if expected_file_mode is None:
            expected_file_mode = baseline.get("file")

    start_time = time.time()
    result = AuditResult()

    try:
        # Add directory to the search if it's not excluded
        paths_to_check = []
        if not any(fnmatch.fnmatch(directory.name, pattern) for pattern in exclude_patterns):
            paths_to_check.append(directory)

        # Add all other paths
        if recursive:
            for root, dirs, files in os.walk(str(directory)):
                # Filter directories
                dirs_to_remove = []
                for i, dirname in enumerate(dirs):
                    if any(fnmatch.fnmatch(dirname, pattern) for pattern in exclude_patterns):
                        dirs_to_remove.append(i)

                # Remove excluded directories in reverse order to maintain indexing
                for i in reversed(dirs_to_remove):
                    del dirs[i]

                # Add all non-excluded paths to check
                root_path = Path(root)
                paths_to_check.extend(root_path / dirname for dirname in dirs)

                # Filter files
                for filename in files:
                    if exclude_patterns and any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_patterns):
                        continue
                    if include_patterns and not any(fnmatch.fnmatch(filename, pattern) for pattern in include_patterns):
                        continue
                    paths_to_check.append(root_path / filename)
        else:
            # Non-recursive - just check immediate child directories and files
            for child in directory.iterdir():
                if exclude_patterns and any(fnmatch.fnmatch(child.name, pattern) for pattern in exclude_patterns):
                    continue
                if include_patterns and not any(fnmatch.fnmatch(child.name, pattern) for pattern in include_patterns):
                    continue
                paths_to_check.append(child)

        # Audit each path
        for path in paths_to_check:
            # Determine expected mode based on path type
            if path.is_dir():
                result.checked_directories += 1
                expected_mode = expected_dir_mode
            else:
                result.checked_files += 1
                expected_mode = expected_file_mode

                # Special handling for sensitive files and scripts
                if path.suffix.lower() in (".sh", ".py", ".rb", ".pl"):
                    if security_baseline in PERMISSION_BASELINES:
                        expected_mode = PERMISSION_BASELINES[security_baseline].get("script")
                elif path.suffix.lower() in (".conf", ".ini", ".json", ".yaml", ".yml", ".xml", ".env"):
                    if security_baseline in PERMISSION_BASELINES:
                        expected_mode = PERMISSION_BASELINES[security_baseline].get("config")
                elif any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS):
                    if security_baseline in PERMISSION_BASELINES:
                        expected_mode = PERMISSION_BASELINES[security_baseline].get("sensitive")

            # Check permissions
            violations = audit_file_permissions(
                path,
                expected_mode=expected_mode,
                expected_owner=expected_owner,
                expected_group=expected_group
            )

            # Add any violations found
            result.violations.extend(violations)

        # Report findings
        if result.has_violations:
            logger.warning(f"Found {len(result.violations)} permission violations: "
                         f"{result.critical_count} critical, {result.high_count} high severity")

            # Notify if critical violations and notification system available
            if result.critical_count > 0 and NOTIFICATION_AVAILABLE:
                send_notification(
                    title="Critical Permission Violations",
                    message=f"Found {result.critical_count} critical permission violations in {directory}",
                    priority="high",
                    category="security"
                )
        else:
            logger.info(f"No permission violations found in {directory}")

    except Exception as e:
        logger.error(f"Error during permission audit: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)

    # Add execution time
    result.execution_time = time.time() - start_time

    return result


def create_permission_baseline(
    directory: Union[str, Path],
    output_file: Union[str, Path],
    recursive: bool = True,
    exclude_patterns: Optional[List[str]] = None,
    include_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create a baseline of current permissions for future comparison.

    Args:
        directory: Directory to create baseline from
        output_file: Output file path for the baseline
        recursive: Whether to scan recursively
        exclude_patterns: Patterns of files to exclude
        include_patterns: Patterns of files to include

    Returns:
        Dictionary with baseline metadata
    """
    directory = Path(directory)
    output_file = Path(output_file)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    # Set default exclude patterns if not provided
    if exclude_patterns is None:
        exclude_patterns = [
            "*.pyc", "__pycache__", ".git", ".svn", "node_modules",
            "*.tmp", "*.bak", "*.log", ".DS_Store", "Thumbs.db"
        ]

    try:
        baseline = {
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "source_directory": str(directory.resolve()),
                "hostname": platform.node(),
                "platform": platform.system(),
                "version": "1.0"
            },
            "permissions": {}
        }

        files_processed = 0

        # Process the directory tree
        if recursive:
            for root, dirs, files in os.walk(str(directory)):
                # Skip excluded directories
                dirs[:] = [d for d in dirs
                          if not any(fnmatch.fnmatch(d, pattern) for pattern in exclude_patterns)]

                # Process directories
                for dirname in dirs:
                    dir_path = Path(root) / dirname
                    rel_path = dir_path.relative_to(directory)

                    # Skip if excluded
                    if exclude_patterns and any(fnmatch.fnmatch(dirname, pattern) for pattern in exclude_patterns):
                        continue
                    if include_patterns and not any(fnmatch.fnmatch(dirname, pattern) for pattern in include_patterns):
                        continue

                    try:
                        stat_info = dir_path.stat()
                        mode = stat_info.st_mode & 0o777
                        owner, group = get_file_owner_group(dir_path)

                        baseline["permissions"][str(rel_path)] = {
                            "type": "directory",
                            "mode": mode,
                            "mode_octal": oct(mode),
                            "owner": owner,
                            "group": group
                        }
                        files_processed += 1
                    except Exception as e:
                        logger.warning(f"Error processing directory {dir_path}: {str(e)}")

                # Process files
                for filename in files:
                    # Skip excluded files
                    if exclude_patterns and any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_patterns):
                        continue
                    if include_patterns and not any(fnmatch.fnmatch(filename, pattern) for pattern in include_patterns):
                        continue

                    file_path = Path(root) / filename
                    rel_path = file_path.relative_to(directory)

                    try:
                        stat_info = file_path.stat()
                        mode = stat_info.st_mode & 0o777
                        owner, group = get_file_owner_group(file_path)
                        is_setuid, is_setgid = is_setuid_setgid(file_path)

                        baseline["permissions"][str(rel_path)] = {
                            "type": "file",
                            "mode": mode,
                            "mode_octal": oct(mode),
                            "owner": owner,
                            "group": group,
                            "setuid": is_setuid,
                            "setgid": is_setgid
                        }
                        files_processed += 1
                    except Exception as e:
                        logger.warning(f"Error processing file {file_path}: {str(e)}")
        else:
            # Non-recursive, just process immediate children
            for path in directory.iterdir():
                # Skip excluded paths
                if exclude_patterns and any(fnmatch.fnmatch(path.name, pattern) for pattern in exclude_patterns):
                    continue
                if include_patterns and not any(fnmatch.fnmatch(path.name, pattern) for pattern in include_patterns):
                    continue

                rel_path = path.relative_to(directory)

                try:
                    stat_info = path.stat()
                    mode = stat_info.st_mode & 0o777
                    owner, group = get_file_owner_group(path)

                    entry = {
                        "type": "directory" if path.is_dir() else "file",
                        "mode": mode,
                        "mode_octal": oct(mode),
                        "owner": owner,
                        "group": group
                    }

                    # Add SUID/SGID info for files
                    if path.is_file():
                        is_setuid, is_setgid = is_setuid_setgid(path)
                        entry["setuid"] = is_setuid
                        entry["setgid"] = is_setgid

                    baseline["permissions"][str(rel_path)] = entry
                    files_processed += 1
                except Exception as e:
                    logger.warning(f"Error processing path {path}: {str(e)}")

        # Add summary info to metadata
        baseline["metadata"]["total_entries"] = files_processed
        baseline["metadata"]["exclude_patterns"] = exclude_patterns
        baseline["metadata"]["include_patterns"] = include_patterns

        # Save baseline to file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(baseline, f, indent=2)

        # Set secure permissions on the baseline file
        try:
            os.chmod(output_file, 0o640)
        except Exception:
            pass

        logger.info(f"Created permission baseline with {files_processed} entries at {output_file}")
        return baseline["metadata"]

    except Exception as e:
        logger.error(f"Error creating permission baseline: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        raise


def verify_against_baseline(
    directory: Union[str, Path],
    baseline_file: Union[str, Path],
    report_file: Optional[Union[str, Path]] = None
) -> Dict[str, Any]:
    """
    Verify current permissions against a baseline.

    Args:
        directory: Directory to verify
        baseline_file: Path to the baseline file
        report_file: Path to save the report (optional)

    Returns:
        Dictionary with verification results
    """
    directory = Path(directory)
    baseline_file = Path(baseline_file)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not baseline_file.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")

    try:
        # Load baseline
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)

        baseline_permissions = baseline.get("permissions", {})

        # Setup result structure
        result = {
            "timestamp": datetime.now().isoformat(),
            "directory": str(directory),
            "baseline": str(baseline_file),
            "violations": [],
            "new_files": [],
            "missing_files": [],
            "stats": {
                "total_checked": 0,
                "violations_found": 0,
                "critical_violations": 0,
                "high_violations": 0
            }
        }

        # Check each file in the baseline
        for rel_path_str, expected in baseline_permissions.items():
            full_path = directory / rel_path_str
            result["stats"]["total_checked"] += 1

            if not full_path.exists():
                result["missing_files"].append(rel_path_str)
                continue

            # Compare permissions
            try:
                stat_info = full_path.stat()
                current_mode = stat_info.st_mode & 0o777
                current_owner, current_group = get_file_owner_group(full_path)
                expected_mode = expected.get("mode")
                expected_owner = expected.get("owner")
                expected_group = expected.get("group")

                # Check mode (check if more permissive than baseline)
                if current_mode > expected_mode:
                    violation = {
                        "path": rel_path_str,
                        "issue": "Excessive permissions",
                        "severity": "medium",
                        "current_mode": current_mode,
                        "current_mode_octal": oct(current_mode),
                        "expected_mode": expected_mode,
                        "expected_mode_octal": oct(expected_mode)
                    }

                    # Determine severity
                    if current_mode & 0o002:  # World-writable
                        violation["severity"] = "high"
                        if expected.get("type") == "directory":
                            violation["severity"] = "critical"
                            result["stats"]["critical_violations"] += 1
                        else:
                            result["stats"]["high_violations"] += 1

                    result["violations"].append(violation)
                    result["stats"]["violations_found"] += 1

                # Check owner
                if expected_owner and current_owner and current_owner != expected_owner:
                    violation = {
                        "path": rel_path_str,
                        "issue": "Incorrect owner",
                        "severity": "medium",
                        "current_owner": current_owner,
                        "expected_owner": expected_owner
                    }
                    result["violations"].append(violation)
                    result["stats"]["violations_found"] += 1

                # Check group
                if expected_group and current_group and current_group != expected_group:
                    violation = {
                        "path": rel_path_str,
                        "issue": "Incorrect group",
                        "severity": "medium",
                        "current_group": current_group,
                        "expected_group": expected_group
                    }
                    result["violations"].append(violation)
                    result["stats"]["violations_found"] += 1

                # Check for SUID/SGID changes
                if expected.get("type") == "file":
                    is_setuid, is_setgid = is_setuid_setgid(full_path)

                    if is_setuid != expected.get("setuid", False):
                        state = "added" if is_setuid else "removed"
                        violation = {
                            "path": rel_path_str,
                            "issue": f"SUID bit {state}",
                            "severity": "high" if is_setuid else "medium"
                        }
                        result["violations"].append(violation)
                        result["stats"]["violations_found"] += 1
                        if is_setuid:
                            result["stats"]["high_violations"] += 1

                    if is_setgid != expected.get("setgid", False):
                        state = "added" if is_setgid else "removed"
                        violation = {
                            "path": rel_path_str,
                            "issue": f"SGID bit {state}",
                            "severity": "medium"
                        }
                        result["violations"].append(violation)
                        result["stats"]["violations_found"] += 1

            except Exception as e:
                logger.warning(f"Error checking {full_path}: {str(e)}")
                result["violations"].append({
                    "path": rel_path_str,
                    "issue": f"Error checking permissions: {str(e)}",
                    "severity": "low"
                })
                result["stats"]["violations_found"] += 1

        # Look for new files (only at the top level for efficiency)
        baseline_exclude_patterns = baseline.get("metadata", {}).get("exclude_patterns", [])
        for path in directory.iterdir():
            rel_path = str(path.relative_to(directory))

            # Skip excluded paths
            if baseline_exclude_patterns and any(fnmatch.fnmatch(rel_path, pattern) for pattern in baseline_exclude_patterns):
                continue

            if rel_path not in baseline_permissions:
                result["new_files"].append(rel_path)

        # Set overall status
        result["passed"] = (result["stats"]["violations_found"] == 0 and len(result["missing_files"]) == 0)

        # Save report if requested
        if report_file:
            report_path = Path(report_file)
            report_path.parent.mkdir(parents=True, exist_ok=True)

            with open(report_path, 'w') as f:
                json.dump(result, f, indent=2)

            # Set secure permissions on the report
            try:
                os.chmod(report_path, 0o640)
            except Exception:
                pass

            logger.info(f"Saved permission verification report to {report_path}")

        # Log summary
        if result["passed"]:
            logger.info(f"Permission verification passed for {result['stats']['total_checked']} files")
        else:
            logger.warning(
                f"Permission verification failed: {result['stats']['violations_found']} violations, "
                f"{len(result['missing_files'])} missing files, {len(result['new_files'])} new files"
            )

            # Send notification if critical or high violations found
            if (result["stats"]["critical_violations"] > 0 or result["stats"]["high_violations"] > 0) and NOTIFICATION_AVAILABLE:
                severity = "Critical" if result["stats"]["critical_violations"] > 0 else "High"
                send_notification(
                    title=f"{severity} Permission Violations Detected",
                    message=f"Found {result['stats']['critical_violations']} critical and "
                           f"{result['stats']['high_violations']} high severity permission violations in {directory}",
                    priority="high",
                    category="security"
                )

        return result

    except Exception as e:
        logger.error(f"Error verifying against permission baseline: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        raise


#######################################
# SUID/SGID Management
#######################################

def find_suid_sgid(
    directory: Union[str, Path],
    recursive: bool = True,
    check_sgid: bool = True
) -> Dict[str, List[str]]:
    """
    Find files with SUID and/or SGID bit set.

    Args:
        directory: Directory to search
        recursive: Whether to search recursively
        check_sgid: Whether to check for SGID bit in addition to SUID

    Returns:
        Dictionary with 'suid' and 'sgid' lists of file paths
    """
    if IS_WINDOWS:
        logger.warning("SUID/SGID check not supported on Windows")
        return {'suid': [], 'sgid': []}

    directory = Path(directory)
    result = {'suid': [], 'sgid': []}

    try:
        if not directory.exists():
            logger.warning(f"Directory not found: {directory}")
            return result

        if recursive:
            for root, _, files in os.walk(str(directory)):
                for filename in files:
                    file_path = Path(root) / filename
                    try:
                        is_setuid, is_setgid = is_setuid_setgid(file_path)
                        if is_setuid:
                            result['suid'].append(str(file_path))
                        if check_sgid and is_setgid:
                            result['sgid'].append(str(file_path))
                    except Exception:
                        continue
        else:
            for path in directory.iterdir():
                if path.is_file():
                    try:
                        is_setuid, is_setgid = is_setuid_setgid(path)
                        if is_setuid:
                            result['suid'].append(str(path))
                        if check_sgid and is_setgid:
                            result['sgid'].append(str(path))
                    except Exception:
                        continue

        return result

    except Exception as e:
        logger.error(f"Error finding SUID/SGID files: {str(e)}")
        return result


def remove_suid_bit(path: Union[str, Path]) -> bool:
    """
    Remove the SUID bit from a file.

    Args:
        path: Path to the file

    Returns:
        True if successful, False otherwise
    """
    if IS_WINDOWS:
        logger.warning("SUID removal not supported on Windows")
        return False

    path = Path(path)

    try:
        if not path.exists() or not path.is_file():
            logger.warning(f"File not found or not a file: {path}")
            return False

        # Get current mode
        current_mode = path.stat().st_mode

        # Remove SUID bit (0o4000)
        new_mode = current_mode & ~0o4000

        # Apply new mode
        os.chmod(path, new_mode)
        logger.info(f"Removed SUID bit from {path}")
        return True

    except Exception as e:
        logger.error(f"Error removing SUID bit from {path}: {str(e)}")
        return False


def remove_sgid_bit(path: Union[str, Path]) -> bool:
    """
    Remove the SGID bit from a file.

    Args:
        path: Path to the file

    Returns:
        True if successful, False otherwise
    """
    if IS_WINDOWS:
        logger.warning("SGID removal not supported on Windows")
        return False

    path = Path(path)

    try:
        if not path.exists() or not path.is_file():
            logger.warning(f"File not found or not a file: {path}")
            return False

        # Get current mode
        current_mode = path.stat().st_mode

        # Remove SGID bit (0o2000)
        new_mode = current_mode & ~0o2000

        # Apply new mode
        os.chmod(path, new_mode)
        logger.info(f"Removed SGID bit from {path}")
        return True

    except Exception as e:
        logger.error(f"Error removing SGID bit from {path}: {str(e)}")
        return False


#######################################
# World-Writable File Management
#######################################

def find_world_writable(
    directory: Union[str, Path],
    recursive: bool = True,
    exclude_patterns: Optional[List[str]] = None
) -> List[str]:
    """
    Find world-writable files and directories.

    Args:
        directory: Directory to search
        recursive: Whether to search recursively
        exclude_patterns: Patterns to exclude

    Returns:
        List of world-writable paths
    """
    directory = Path(directory)
    result = []

    # Set default exclude patterns if not provided
    if exclude_patterns is None:
        exclude_patterns = [".git", ".svn", "node_modules"]

    try:
        if not directory.exists():
            logger.warning(f"Directory not found: {directory}")
            return result

        if recursive:
            for root, dirs, files in os.walk(str(directory)):
                # Skip excluded directories
                dirs_to_remove = []
                for i, dirname in enumerate(dirs):
                    if any(fnmatch.fnmatch(dirname, pattern) for pattern in exclude_patterns):
                        dirs_to_remove.append(i)

                # Remove excluded directories
                for i in reversed(dirs_to_remove):
                    del dirs[i]

                # Check directories
                for dirname in dirs:
                    dir_path = Path(root) / dirname
                    if is_world_writable(dir_path):
                        result.append(str(dir_path))

                # Check files
                for filename in files:
                    if any(fnmatch.fnmatch(filename, pattern) for pattern in exclude_patterns):
                        continue

                    file_path = Path(root) / filename
                    if is_world_writable(file_path):
                        result.append(str(file_path))
        else:
            # Non-recursive, just check immediate children
            for path in directory.iterdir():
                if any(fnmatch.fnmatch(path.name, pattern) for pattern in exclude_patterns):
                    continue

                if is_world_writable(path):
                    result.append(str(path))

        return result

    except Exception as e:
        logger.error(f"Error finding world-writable paths: {str(e)}")
        return result


def remove_world_writable_permission(path: Union[str, Path]) -> bool:
    """
    Remove world-writable permission from a file or directory.

    Args:
        path: Path to modify

    Returns:
        True if successful, False otherwise
    """
    path = Path(path)

    try:
        if not path.exists():
            logger.warning(f"Path does not exist: {path}")
            return False

        # Get current mode
        current_mode = path.stat().st_mode

        # Check if already not world-writable
        if not (current_mode & 0o002):
            logger.debug(f"Path {path} is already not world-writable")
            return True

        # Remove world-writable bit (o-w)
        new_mode = current_mode & ~0o002

        # Apply new mode
        os.chmod(path, new_mode)
        logger.info(f"Removed world-writable permission from {path}")
        return True

    except Exception as e:
        logger.error(f"Error removing world-writable permission from {path}: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        return False


def remove_world_readable_permission(path: Union[str, Path]) -> bool:
    """
    Remove world-readable permission from a file or directory.

    Args:
        path: Path to modify

    Returns:
        True if successful, False otherwise
    """
    path = Path(path)

    try:
        if not path.exists():
            logger.warning(f"Path does not exist: {path}")
            return False

        # Get current mode
        current_mode = path.stat().st_mode

        # Check if already not world-readable
        if not (current_mode & 0o004):
            logger.debug(f"Path {path} is already not world-readable")
            return True

        # Remove world-readable bit (o-r)
        new_mode = current_mode & ~0o004

        # Apply new mode
        os.chmod(path, new_mode)
        logger.info(f"Removed world-readable permission from {path}")
        return True

    except Exception as e:
        logger.error(f"Error removing world-readable permission from {path}: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        return False


def secure_sensitive_files(directory: Union[str, Path],
                           recursive: bool = True,
                           dry_run: bool = False) -> Dict[str, int]:
    """
    Automatically secure sensitive files in a directory.

    Finds files matching sensitive patterns and applies appropriate permissions.

    Args:
        directory: Directory to process
        recursive: Whether to process subdirectories recursively
        dry_run: If True, only report what would be changed without making changes

    Returns:
        Dictionary with counts of processed, secured, and failed files
    """
    directory = Path(directory)
    results = {
        "processed": 0,
        "secured": 0,
        "failed": 0,
        "skipped": 0
    }

    try:
        if not directory.exists():
            logger.warning(f"Directory not found: {directory}")
            return results

        # Find all sensitive files
        for root, dirs, files in os.walk(str(directory)):
            # Skip hidden directories if needed
            dirs[:] = [d for d in dirs if not d.startswith('.') or d in ('.ssh', '.keys')]

            # If not recursive, clear dirs to prevent walking deeper
            if not recursive:
                dirs.clear()

            # Check each file
            for filename in files:
                file_path = Path(root) / filename

                # Check if it's a sensitive file
                is_sensitive = any(fnmatch.fnmatch(filename.lower(), pattern)
                                  for pattern in SENSITIVE_FILE_PATTERNS)

                # Also check the parent directory for sensitive contexts
                parent_sensitive = any(fnmatch.fnmatch(file_path.parent.name.lower(), pattern)
                                     for pattern in SECURE_DIRECTORY_PATTERNS)

                if is_sensitive or parent_sensitive:
                    results["processed"] += 1

                    try:
                        # Get current mode
                        current_mode = file_path.stat().st_mode & 0o777

                        # Determine appropriate secure mode
                        if filename.endswith(('.sh', '.py', '.pl', '.rb')):
                            secure_mode = DEFAULT_SCRIPT_MODE & ~0o007  # Remove world permissions
                        else:
                            secure_mode = DEFAULT_SENSITIVE_MODE

                        # Check if permissions are already secure
                        if current_mode <= secure_mode:
                            results["skipped"] += 1
                            continue

                        if dry_run:
                            logger.info(f"[DRY RUN] Would secure {file_path} by changing mode from {oct(current_mode)} to {oct(secure_mode)}")
                            results["skipped"] += 1
                        else:
                            os.chmod(file_path, secure_mode)
                            logger.info(f"Secured sensitive file {file_path} by changing mode from {oct(current_mode)} to {oct(secure_mode)}")
                            results["secured"] += 1

                    except Exception as e:
                        logger.error(f"Failed to secure {file_path}: {str(e)}")
                        results["failed"] += 1

        return results

    except Exception as e:
        logger.error(f"Error in secure_sensitive_files: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        return results


def compare_permissions(file1: Union[str, Path], file2: Union[str, Path]) -> Dict[str, Any]:
    """
    Compare permissions between two files.

    Args:
        file1: First file path
        file2: Second file path

    Returns:
        Dictionary with comparison results
    """
    file1 = Path(file1)
    file2 = Path(file2)

    result = {
        "file1": str(file1),
        "file2": str(file2),
        "differences": [],
        "identical": True
    }

    try:
        # Check if both files exist
        if not file1.exists():
            result["differences"].append(f"File1 {file1} does not exist")
            result["identical"] = False
            return result

        if not file2.exists():
            result["differences"].append(f"File2 {file2} does not exist")
            result["identical"] = False
            return result

        # Get stats for both files
        stat1 = file1.stat()
        stat2 = file2.stat()

        # Compare modes
        mode1 = stat1.st_mode & 0o777
        mode2 = stat2.st_mode & 0o777

        if mode1 != mode2:
            result["differences"].append({
                "type": "mode",
                "file1_mode": oct(mode1),
                "file2_mode": oct(mode2)
            })
            result["identical"] = False

        # Compare owners
        owner1, group1 = get_file_owner_group(file1)
        owner2, group2 = get_file_owner_group(file2)

        if owner1 != owner2:
            result["differences"].append({
                "type": "owner",
                "file1_owner": owner1,
                "file2_owner": owner2
            })
            result["identical"] = False

        if group1 != group2:
            result["differences"].append({
                "type": "group",
                "file1_group": group1,
                "file2_group": group2
            })
            result["identical"] = False

        # Compare SUID/SGID bits
        is_setuid1, is_setgid1 = is_setuid_setgid(file1)
        is_setuid2, is_setgid2 = is_setuid_setgid(file2)

        if is_setuid1 != is_setuid2:
            result["differences"].append({
                "type": "setuid",
                "file1_setuid": is_setuid1,
                "file2_setuid": is_setuid2
            })
            result["identical"] = False

        if is_setgid1 != is_setgid2:
            result["differences"].append({
                "type": "setgid",
                "file1_setgid": is_setgid1,
                "file2_setgid": is_setgid2
            })
            result["identical"] = False

        return result

    except Exception as e:
        logger.error(f"Error comparing permissions: {str(e)}")
        result["differences"].append(f"Error: {str(e)}")
        result["identical"] = False
        return result


def find_insecure_permissions(directory: Union[str, Path],
                             security_level: str = "production") -> Dict[str, List[str]]:
    """
    Find files with insecure permissions according to security level.

    Args:
        directory: Directory to check
        security_level: Security level to use ('development', 'staging', 'production')

    Returns:
        Dictionary with categories of insecure files
    """
    directory = Path(directory)
    result = {
        "world_writable": [],
        "excessive_directory_perms": [],
        "sensitive_files_exposed": [],
        "setuid_files": [],
        "setgid_files": [],
        "invalid_owner": []
    }

    # Select baseline based on security level
    if security_level in PERMISSION_BASELINES:
        baseline = PERMISSION_BASELINES[security_level]
    else:
        baseline = PERMISSION_BASELINES["production"]  # Most restrictive default

    try:
        # Find world-writable files
        result["world_writable"] = find_world_writable(directory)

        # Check other security issues
        for root, dirs, files in os.walk(str(directory)):
            # Check directories
            for dirname in dirs:
                dir_path = Path(root) / dirname
                try:
                    dir_mode = dir_path.stat().st_mode & 0o777
                    is_secure_dir = any(fnmatch.fnmatch(dirname.lower(), pattern)
                                      for pattern in SECURE_DIRECTORY_PATTERNS)

                    # Check if directory has excessive permissions
                    max_dir_mode = baseline.get("secure_dir" if is_secure_dir else "directory")
                    if dir_mode > max_dir_mode:
                        result["excessive_directory_perms"].append(str(dir_path))
                except Exception as e:
                    logger.debug(f"Error checking directory {dir_path}: {str(e)}")

            # Check files
            for filename in files:
                file_path = Path(root) / filename
                try:
                    # Check if it's a sensitive file with improper permissions
                    is_sensitive = any(fnmatch.fnmatch(filename.lower(), pattern)
                                     for pattern in SENSITIVE_FILE_PATTERNS)

                    if is_sensitive:
                        file_mode = file_path.stat().st_mode & 0o777
                        max_sensitive_mode = baseline.get("sensitive", DEFAULT_SENSITIVE_MODE)
                        if file_mode > max_sensitive_mode:
                            result["sensitive_files_exposed"].append(str(file_path))

                    # Check for SUID/SGID
                    is_setuid, is_setgid = is_setuid_setgid(file_path)
                    if is_setuid:
                        result["setuid_files"].append(str(file_path))
                    if is_setgid:
                        result["setgid_files"].append(str(file_path))

                except Exception as e:
                    logger.debug(f"Error checking file {file_path}: {str(e)}")

        return result

    except Exception as e:
        logger.error(f"Error finding insecure permissions: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        return result


def generate_permission_report(
    path: Union[str, Path],
    output_format: str = "json",
    output_file: Optional[Union[str, Path]] = None,
    recursive: bool = True,
    include_stats: bool = True,
    security_level: str = "production"
) -> Dict[str, Any]:
    """
    Generate a detailed report of file permissions in a directory.

    Args:
        path: Path to analyze
        output_format: Format for the report ('json', 'text', 'csv')
        output_file: File to save the report to (optional)
        recursive: Whether to analyze recursively
        include_stats: Whether to include statistics
        security_level: Security level to use for baseline comparison

    Returns:
        Dictionary with the report data
    """
    path = Path(path)
    report = {
        "timestamp": datetime.now().isoformat(),
        "path": str(path),
        "security_level": security_level,
        "files": {},
        "violations": []
    }

    if include_stats:
        report["stats"] = {
            "total_files": 0,
            "total_directories": 0,
            "world_writable": 0,
            "world_readable": 0,
            "setuid": 0,
            "setgid": 0,
            "excessive_permissions": 0,
            "sensitive_files": 0
        }

    # Select baseline based on security level
    if security_level in PERMISSION_BASELINES:
        baseline = PERMISSION_BASELINES[security_level]
    else:
        baseline = PERMISSION_BASELINES["production"]

    try:
        # Process files
        for root, dirs, files in os.walk(str(path)):
            # Skip if not recursive and not at top level
            if not recursive and root != str(path):
                continue

            # Process directories
            for dirname in dirs:
                dir_path = Path(root) / dirname

                try:
                    # Get stats
                    stat_info = dir_path.stat()
                    mode = stat_info.st_mode & 0o777
                    owner, group = get_file_owner_group(dir_path)

                    # Record directory
                    rel_path = str(dir_path.relative_to(path))
                    report["files"][rel_path] = {
                        "type": "directory",
                        "mode": mode,
                        "mode_octal": oct(mode),
                        "owner": owner,
                        "group": group
                    }

                    if include_stats:
                        report["stats"]["total_directories"] += 1

                    # Check for violations
                    is_secure_dir = any(fnmatch.fnmatch(dirname.lower(), pattern)
                                      for pattern in SECURE_DIRECTORY_PATTERNS)
                    max_dir_mode = baseline.get("secure_dir" if is_secure_dir else "directory")

                    if mode > max_dir_mode:
                        violation = {
                            "path": rel_path,
                            "issue": "Excessive directory permissions",
                            "severity": "medium",
                            "current_mode": oct(mode),
                            "expected_max": oct(max_dir_mode)
                        }

                        if mode & 0o002:  # World-writable
                            violation["severity"] = "critical"
                            if include_stats:
                                report["stats"]["world_writable"] += 1
                        elif mode & 0o004:  # World-readable
                            if is_secure_dir:  # More serious for secure dirs
                                violation["severity"] = "high"
                            if include_stats:
                                report["stats"]["world_readable"] += 1

                        report["violations"].append(violation)
                        if include_stats:
                            report["stats"]["excessive_permissions"] += 1

                except Exception as e:
                    logger.debug(f"Error processing directory {dir_path}: {str(e)}")

            # Process files
            for filename in files:
                file_path = Path(root) / filename

                try:
                    # Get stats
                    stat_info = file_path.stat()
                    mode = stat_info.st_mode & 0o777
                    owner, group = get_file_owner_group(file_path)
                    is_setuid, is_setgid = is_setuid_setgid(file_path)

                    # Record file
                    rel_path = str(file_path.relative_to(path))
                    file_record = {
                        "type": "file",
                        "mode": mode,
                        "mode_octal": oct(mode),
                        "owner": owner,
                        "group": group,
                        "setuid": is_setuid,
                        "setgid": is_setgid
                    }

                    report["files"][rel_path] = file_record

                    if include_stats:
                        report["stats"]["total_files"] += 1
                        if is_setuid:
                            report["stats"]["setuid"] += 1
                        if is_setgid:
                            report["stats"]["setgid"] += 1

                    # Check for violations
                    is_sensitive = any(fnmatch.fnmatch(filename.lower(), pattern)
                                     for pattern in SENSITIVE_FILE_PATTERNS)
                    is_script = file_path.suffix.lower() in (".sh", ".py", ".rb", ".pl")
                    is_config = file_path.suffix.lower() in (".conf", ".ini", ".json", ".yaml", ".yml", ".xml", ".env")

                    if is_sensitive:
                        file_type = "sensitive"
                        if include_stats:
                            report["stats"]["sensitive_files"] += 1
                    elif is_script:
                        file_type = "script"
                    elif is_config:
                        file_type = "config"
                    else:
                        file_type = "file"

                    max_file_mode = baseline.get(file_type, baseline.get("file", DEFAULT_FILE_MODE))

                    if mode > max_file_mode:
                        violation = {
                            "path": rel_path,
                            "issue": f"Excessive file permissions for {file_type}",
                            "severity": "low",
                            "current_mode": oct(mode),
                            "expected_max": oct(max_file_mode)
                        }

                        if mode & 0o002:  # World-writable
                            violation["severity"] = "high"
                            if is_sensitive:
                                violation["severity"] = "critical"
                            if include_stats:
                                report["stats"]["world_writable"] += 1
                        elif mode & 0o004:  # World-readable
                            if is_sensitive:
                                violation["severity"] = "medium"
                            if include_stats:
                                report["stats"]["world_readable"] += 1

                        report["violations"].append(violation)
                        if include_stats:
                            report["stats"]["excessive_permissions"] += 1

                    # Check SUID/SGID for violations
                    if is_setuid and not is_script:
                        report["violations"].append({
                            "path": rel_path,
                            "issue": "SUID bit set on non-executable file",
                            "severity": "high"
                        })

                except Exception as e:
                    logger.debug(f"Error processing file {file_path}: {str(e)}")

        # Save report to file if requested
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_format == "json":
                with open(output_path, "w") as f:
                    json.dump(report, f, indent=2)
            elif output_format == "csv":
                import csv
                with open(output_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Path", "Type", "Mode", "Owner", "Group", "SUID", "SGID"])
                    for file_path, data in report["files"].items():
                        writer.writerow([
                            file_path,
                            data.get("type", ""),
                            data.get("mode_octal", ""),
                            data.get("owner", ""),
                            data.get("group", ""),
                            data.get("setuid", ""),
                            data.get("setgid", "")
                        ])
            else:  # text format
                with open(output_path, "w") as f:
                    f.write(f"# Permission Report for {path}\n")
                    f.write(f"# Generated: {report['timestamp']}\n")
                    f.write(f"# Security Level: {security_level}\n\n")

                    # Write violations
                    if report["violations"]:
                        f.write("## Violations\n\n")
                        for v in sorted(report["violations"], key=lambda x: x.get("severity", "low")):
                            f.write(f"- [{v.get('severity', 'unknown').upper()}] {v.get('path')}: {v.get('issue')}\n")
                        f.write("\n")

                    # Write stats
                    if include_stats and "stats" in report:
                        f.write("## Statistics\n\n")
                        for key, value in report["stats"].items():
                            f.write(f"- {key}: {value}\n")

            logger.info(f"Saved permission report to {output_path}")

            # Set secure permissions on the report
            try:
                os.chmod(output_path, 0o640)
            except Exception:
                pass

        return report

    except Exception as e:
        logger.error(f"Error generating permission report: {str(e)}")
        if ERROR_HANDLER_AVAILABLE:
            handle_error(e, category=ErrorCategory.SECURITY)
        return report


if __name__ == "__main__":
    """
    Command line interface for permissions.py module.

    Examples:
        python -m scripts.core.security.permissions audit /path/to/dir
        python -m scripts.core.security.permissions fix /path/to/dir
        python -m scripts.core.security.permissions baseline /path/to/dir /path/to/baseline.json
    """
    import argparse

    parser = argparse.ArgumentParser(description="File and directory permission management")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Audit permissions")
    audit_parser.add_argument("directory", help="Directory to audit")
    audit_parser.add_argument("--recursive", "-r", action="store_true", help="Audit recursively")
    audit_parser.add_argument("--owner", help="Expected owner")
    audit_parser.add_argument("--group", help="Expected group")
    audit_parser.add_argument("--baseline", help="Security baseline to use", choices=["development", "staging", "production"], default="production")
    audit_parser.add_argument("--output", "-o", help="Output file for report")
    audit_parser.add_argument("--format", "-f", help="Output format", choices=["json", "text", "csv"], default="text")

    # Fix command
    fix_parser = subparsers.add_parser("fix", help="Fix permission issues")
    fix_parser.add_argument("directory", help="Directory to fix")
    fix_parser.add_argument("--recursive", "-r", action="store_true", help="Fix recursively")
    fix_parser.add_argument("--dry-run", "-d", action="store_true", help="Only show what would be changed")
    fix_parser.add_argument("--baseline", help="Security baseline to use", choices=["development", "staging", "production"], default="production")

    # Find command
    find_parser = subparsers.add_parser("find", help="Find specific permission issues")
    find_parser.add_argument("directory", help="Directory to search")
    find_parser.add_argument("--world-writable", "-w", action="store_true", help="Find world-writable files")
    find_parser.add_argument("--setuid", "-s", action="store_true", help="Find SUID files")
    find_parser.add_argument("--setgid", "-g", action="store_true", help="Find SGID files")
    find_parser.add_argument("--recursive", "-r", action="store_true", help="Search recursively")

    # Baseline command
    baseline_parser = subparsers.add_parser("baseline", help="Create or verify against a baseline")
    baseline_parser.add_argument("directory", help="Directory to process")
    baseline_parser.add_argument("baseline_file", help="Baseline file path")
    baseline_parser.add_argument("--create", "-c", action="store_true", help="Create new baseline")
    baseline_parser.add_argument("--verify", "-v", action="store_true", help="Verify against baseline")
    baseline_parser.add_argument("--recursive", "-r", action="store_true", help="Process recursively")
    baseline_parser.add_argument("--report", help="Output file for verification report")

    args = parser.parse_args()

    # Process commands
    try:
        if args.command == "audit":
            print(f"Auditing permissions in {args.directory}...")
            result = audit_directory_permissions(
                directory=args.directory,
                recursive=args.recursive,
                expected_owner=args.owner,
                expected_group=args.group,
                security_baseline=args.baseline
            )

            if result.has_violations:
                print(f"\nFound {len(result.violations)} issues:")
                for v in result.violations:
                    print(f"- [{v.severity}] {v.path}: {v.issue}")
                print(f"\nCritical: {result.critical_count}, High: {result.high_count}")
            else:
                print("No permission issues found.")

            if args.output:
                print(f"Generating detailed report in {args.output}...")
                generate_permission_report(
                    path=args.directory,
                    output_format=args.format,
                    output_file=args.output,
                    recursive=args.recursive,
                    security_level=args.baseline
                )

        elif args.command == "fix":
            print(f"{'Analyzing' if args.dry_run else 'Fixing'} permission issues in {args.directory}...")

            # First audit to find issues
            result = audit_directory_permissions(
                directory=args.directory,
                recursive=args.recursive,
                security_baseline=args.baseline
            )

            if not result.has_violations:
                print("No permission issues found.")
            else:
                print(f"Found {len(result.violations)} permission issues.")

                # Fix the issues
                fix_result = fix_permissions(
                    result.violations,
                    dry_run=args.dry_run,
                    log_changes=True
                )

                if args.dry_run:
                    print(f"Would fix {len(result.violations)} issues (dry run)")
                else:
                    print(f"Fixed {fix_result['successful']} issues, {fix_result['failed']} failed, {fix_result['skipped']} skipped")

        elif args.command == "find":
            if args.world_writable:
                print(f"Finding world-writable files in {args.directory}...")
                result = find_world_writable(args.directory, args.recursive)
                if result:
                    print(f"Found {len(result)} world-writable files/directories:")
                    for path in result:
                        print(f"- {path}")
                else:
                    print("No world-writable files found.")

            if args.setuid or args.setgid:
                print(f"Finding {'SUID and ' if args.setuid else ''}{'SGID ' if args.setgid else ''}files in {args.directory}...")
                result = find_suid_sgid(args.directory, args.recursive, args.setgid)

                if args.setuid and result['suid']:
                    print(f"Found {len(result['suid'])} SUID files:")
                    for path in result['suid']:
                        print(f"- {path}")
                elif args.setuid:
                    print("No SUID files found.")

                if args.setgid and result['sgid']:
                    print(f"Found {len(result['sgid'])} SGID files:")
                    for path in result['sgid']:
                        print(f"- {path}")
                elif args.setgid:
                    print("No SGID files found.")

        elif args.command == "baseline":
            if args.create:
                print(f"Creating permission baseline for {args.directory} in {args.baseline_file}...")
                result = create_permission_baseline(
                    directory=args.directory,
                    output_file=args.baseline_file,
                    recursive=args.recursive
                )
                print(f"Baseline created with {result['total_entries']} entries.")

            elif args.verify:
                print(f"Verifying {args.directory} against baseline {args.baseline_file}...")
                result = verify_against_baseline(
                    directory=args.directory,
                    baseline_file=args.baseline_file,
                    report_file=args.report
                )

                if result["passed"]:
                    print(f"Verification passed. Checked {result['stats']['total_checked']} files.")
                else:
                    print(f"Verification failed with {result['stats']['violations_found']} violations.")
                    print(f"- {result['stats'].get('critical_violations', 0)} critical issues")
                    print(f"- {result['stats'].get('high_violations', 0)} high severity issues")
                    print(f"- {len(result['missing_files'])} missing files")
                    print(f"- {len(result['new_files'])} new files")

                    if args.report:
                        print(f"See detailed report at {args.report}")
            else:
                print("Error: Either --create or --verify must be specified for baseline command.")

        else:
            parser.print_help()

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)
