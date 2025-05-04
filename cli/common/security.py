"""
Security utilities for the Cloud Infrastructure Platform CLI.

This module provides CLI-specific security functions including path safety,
command execution safety, file integrity verification, and security checks.
"""

import os
import subprocess
import sys
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, Callable

# Import core security functions if available
try:
    from core.security.cs_utils import (
        is_within_directory,
        sanitize_path,
        is_safe_file_operation
    )
except ImportError:
    # Fallback implementations if core security module isn't available
    def is_within_directory(path: str, allowed_dirs: List[str]) -> bool:
        """
        Check if a path is contained within allowed directories.

        Args:
            path: Path to check
            allowed_dirs: List of allowed base directories

        Returns:
            bool: True if path is within allowed directories
        """
        path = os.path.abspath(os.path.normpath(path))
        return any(path.startswith(os.path.abspath(d)) for d in allowed_dirs)

    def sanitize_path(path: str, base_dir: Optional[str] = None) -> str:
        """
        Sanitize and validate a file path.

        Args:
            path: Path to sanitize
            base_dir: Optional base directory to prepend

        Returns:
            str: Sanitized path

        Raises:
            ValueError: If path contains dangerous components
        """
        # Check for path traversal attempts
        if '..' in path or path.startswith('/'):
            raise ValueError(f"Path contains unsafe components: {path}")

        # Apply base directory if provided
        if base_dir:
            path = os.path.join(base_dir, path)

        return os.path.normpath(path)

    def is_safe_file_operation(operation: str, path: str,
                              safe_dirs: Optional[List[str]] = None) -> bool:
        """
        Check if a file operation is safe.

        Args:
            operation: Operation type ('read', 'write', 'delete')
            path: Path to operate on
            safe_dirs: List of directories considered safe

        Returns:
            bool: True if operation is safe
        """
        if safe_dirs is None:
            safe_dirs = [os.getcwd()]

        # Normalize path
        path = os.path.abspath(os.path.normpath(path))

        # Check if path is within safe directories
        if not is_within_directory(path, safe_dirs):
            return False

        return True

# Try to import file integrity functions
try:
    from core.security.cs_file_integrity import (
        verify_file_signature,
        calculate_file_hash,
        verify_baseline_update,
        detect_file_changes
    )
except ImportError:
    # Fallback implementations
    import hashlib

    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate the hash of a file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use

        Returns:
            str: Hex digest of the hash
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    def verify_file_signature(file_path: str, signature_path: str) -> bool:
        """
        Verify a file's signature.

        Args:
            file_path: Path to the file
            signature_path: Path to the signature file

        Returns:
            bool: True if signature is valid
        """
        # Simple implementation that checks if signature file exists
        # In a real implementation, this would validate cryptographic signatures
        return os.path.isfile(signature_path)

    def verify_baseline_update(file_path: str, current_hash: str, expected_hash: str) -> bool:
        """
        Verify if a baseline update is authorized.

        Args:
            file_path: Path to the file being updated
            current_hash: New hash of the file
            expected_hash: Original hash in the baseline

        Returns:
            bool: True if the update should be allowed
        """
        # Simple implementation for CLI use
        # Real implementation would check against authorized changes
        return current_hash != expected_hash and os.path.isfile(file_path)

    def detect_file_changes(basedir: str, reference_hashes: Dict[str, str],
                           critical_patterns: Optional[List[str]] = None,
                           detect_permissions: bool = False) -> List[Dict[str, Any]]:
        """
        Detect changes in files compared to a baseline.

        Args:
            basedir: Base directory to scan
            reference_hashes: Dictionary mapping file paths to expected hashes
            critical_patterns: Optional list of glob patterns for critical files
            detect_permissions: Whether to check for permission changes

        Returns:
            List[Dict[str, Any]]: List of detected changes
        """
        changes = []

        # Simple implementation that just verifies existing files in the reference
        for file_path, expected_hash in reference_hashes.items():
            full_path = os.path.join(basedir, file_path)

            if not os.path.exists(full_path):
                changes.append({
                    'path': file_path,
                    'status': 'missing',
                    'severity': 'high'
                })
                continue

            current_hash = calculate_file_hash(full_path)
            if current_hash != expected_hash:
                changes.append({
                    'path': file_path,
                    'status': 'modified',
                    'severity': 'high',
                    'expected_hash': expected_hash,
                    'current_hash': current_hash
                })

        return changes

# CLI-specific security functions
def verify_cli_environment() -> Tuple[bool, List[str]]:
    """
    Verify the security of the CLI environment.

    Checks:
    1. PATH contains only safe directories
    2. Current directory is writable
    3. No suspicious environment variables

    Returns:
        Tuple[bool, List[str]]: (is_safe, list_of_issues)
    """
    issues = []

    # Check PATH for unsafe directories
    path_dirs = os.environ.get('PATH', '').split(os.pathsep)
    for directory in path_dirs:
        if directory and (not os.path.isdir(directory) or os.access(directory, os.W_OK)):
            if directory not in ['/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin']:
                issues.append(f"Potentially unsafe PATH entry: {directory}")

    # Check if current directory is writable by others
    try:
        cwd = os.getcwd()
        cwd_stat = os.stat(cwd)
        if cwd_stat.st_mode & 0o002:  # World writable
            issues.append(f"Current directory is world-writable: {cwd}")
    except Exception as e:
        issues.append(f"Error checking current directory permissions: {e}")

    # Check for suspicious environment variables
    suspicious_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'DYLD_INSERT_LIBRARIES']
    for var in suspicious_vars:
        if var in os.environ:
            issues.append(f"Suspicious environment variable set: {var}={os.environ[var]}")

    return len(issues) == 0, issues

def safe_execute_command(
    command: List[str],
    check_input: bool = True,
    timeout: Optional[int] = 60,
    safe_env: bool = True,
    working_dir: Optional[str] = None,
    capture_output: bool = True
) -> Tuple[int, str, str]:
    """
    Safely execute a command with security checks.

    Args:
        command: Command and arguments as list
        check_input: Whether to validate command input
        timeout: Command timeout in seconds
        safe_env: Whether to use a sanitized environment
        working_dir: Optional working directory for the command
        capture_output: Whether to capture stdout/stderr

    Returns:
        Tuple[int, str, str]: (return_code, stdout, stderr)
    """
    # Validate command if requested
    if check_input:
        # Check for shell injection attempts
        for arg in command:
            if any(char in arg for char in ';&|$()`'):
                raise ValueError(f"Potentially unsafe command argument: {arg}")

    # Create safe environment if requested
    env = None
    if safe_env:
        # Start with minimal environment
        env = {
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin',
            'LANG': os.environ.get('LANG', 'C.UTF-8'),
            'HOME': os.environ.get('HOME', '/tmp'),
        }

    # Prepare stdout/stderr handling
    stdout_pipe = subprocess.PIPE if capture_output else None
    stderr_pipe = subprocess.PIPE if capture_output else None

    try:
        # Execute command with security measures
        process = subprocess.Popen(
            command,
            stdout=stdout_pipe,
            stderr=stderr_pipe,
            env=env,
            cwd=working_dir,
            universal_newlines=True
        )

        if capture_output:
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr
        else:
            # If not capturing output, just wait for completion
            process.wait(timeout=timeout)
            return process.returncode, '', ''

    except subprocess.TimeoutExpired:
        # Kill process if it times out
        try:
            process.kill()
            if capture_output:
                stdout, stderr = process.communicate()
                return 124, stdout, f"{stderr}\nCommand timed out after {timeout} seconds"
            return 124, '', 'Command timed out'
        except Exception:
            return 124, '', 'Command timed out and could not be killed'
    except Exception as e:
        return 1, '', f"Error executing command: {e}"

def verify_script_integrity(
    script_path: str,
    baseline_hash: Optional[str] = None,
    verify_permissions: bool = True
) -> Tuple[bool, str, Optional[str]]:
    """
    Verify the integrity of a CLI script.

    Args:
        script_path: Path to the script
        baseline_hash: Expected hash value (if known)
        verify_permissions: Whether to verify file permissions

    Returns:
        Tuple[bool, str, Optional[str]]: (is_valid, current_hash, reason)
    """
    # Check if file exists
    if not os.path.isfile(script_path):
        return False, '', 'File not found'

    # Check file permissions if requested
    if verify_permissions:
        try:
            stat_info = os.stat(script_path)
            # Check if file is world-writable (dangerous)
            if stat_info.st_mode & 0o002:
                return False, '', 'File is world-writable'
        except Exception as e:
            return False, '', f'Error checking file permissions: {e}'

    # Calculate current hash
    try:
        current_hash = calculate_file_hash(script_path)
    except Exception as e:
        return False, '', f'Error calculating file hash: {e}'

    # If baseline hash provided, compare them
    if baseline_hash:
        return current_hash == baseline_hash, current_hash, None if current_hash == baseline_hash else 'Hash mismatch'

    # If no baseline provided, just return the hash
    return True, current_hash, None

def get_safe_config_dir() -> str:
    """
    Get a safe directory for CLI configuration files.

    Returns:
        str: Path to safe config directory
    """
    # Check for XDG config directory
    config_home = os.environ.get('XDG_CONFIG_HOME')
    if not config_home:
        config_home = os.path.join(os.path.expanduser('~'), '.config')

    # Create application config directory
    config_dir = os.path.join(config_home, 'cloud-platform', 'cli')

    # Ensure directory exists with secure permissions
    if not os.path.exists(config_dir):
        os.makedirs(config_dir, mode=0o700, exist_ok=True)
    elif os.path.isdir(config_dir):
        os.chmod(config_dir, 0o700)  # Secure permissions

    return config_dir

def secure_resource_cleanup(files_to_remove: List[str],
                          safe_dirs: Optional[List[str]] = None,
                          secure_delete: bool = True,
                          recursive: bool = False) -> List[str]:
    """
    Securely clean up temporary resources.

    Args:
        files_to_remove: List of files or directories to remove
        safe_dirs: List of directories considered safe for deletion
        secure_delete: Whether to overwrite files before deletion
        recursive: Whether to recursively remove directories

    Returns:
        List[str]: List of files that couldn't be removed
    """
    failed = []

    # Ensure we have safe_dirs
    if safe_dirs is None:
        safe_dirs = [os.getcwd()]

    for path in files_to_remove:
        if not os.path.exists(path):
            continue

        # Verify path is safe to delete
        if not is_safe_file_operation('delete', path, safe_dirs):
            failed.append(path)
            continue

        try:
            # For files, securely delete by overwriting first
            if os.path.isfile(path):
                if secure_delete:
                    try:
                        # Get file size
                        file_size = os.path.getsize(path)
                        if file_size > 0:
                            # Overwrite with zeros (max 1MB per write to handle large files efficiently)
                            with open(path, 'wb') as f:
                                # Write in smaller chunks for large files
                                chunk_size = min(file_size, 1024 * 1024)
                                remaining = file_size
                                while remaining > 0:
                                    write_size = min(remaining, chunk_size)
                                    f.write(b'\0' * write_size)
                                    remaining -= write_size
                    except Exception as e:
                        logging.warning(f"Secure overwrite failed for {path}: {e}, proceeding with deletion anyway")

                # Delete file
                os.unlink(path)
            elif os.path.isdir(path):
                # For directories
                if recursive:
                    # Get all files in directory first
                    all_files = []
                    for root, dirs, files in os.walk(path, topdown=False):
                        for file in files:
                            all_files.append(os.path.join(root, file))

                    # First securely delete all files if requested
                    if secure_delete:
                        for file_path in all_files:
                            try:
                                if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
                                    with open(file_path, 'wb') as f:
                                        f.write(b'\0' * min(os.path.getsize(file_path), 1024 * 1024))
                            except Exception:
                                # Log but continue - best effort
                                pass

                    # Remove entire directory tree
                    shutil.rmtree(path)
                else:
                    # Only remove if directory is empty
                    os.rmdir(path)
        except Exception as e:
            logging.error(f"Failed to remove {path}: {str(e)}")
            failed.append(path)

    return failed

def validate_file_permissions(path: str,
                            min_permissions: Optional[int] = None,
                            max_permissions: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate file permissions against specified limits.

    Args:
        path: Path to the file
        min_permissions: Minimum required permissions (octal)
        max_permissions: Maximum allowed permissions (octal)

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, reason_if_invalid)
    """
    if not os.path.exists(path):
        return False, "File does not exist"

    try:
        # Get file permissions
        stat_info = os.stat(path)
        mode = stat_info.st_mode & 0o777  # Extract the permission bits

        # Check minimum permissions if specified
        if min_permissions is not None and mode < min_permissions:
            return False, f"File permissions ({oct(mode)}) are less than minimum required ({oct(min_permissions)})"

        # Check maximum permissions if specified
        if max_permissions is not None and mode > max_permissions:
            return False, f"File permissions ({oct(mode)}) exceed maximum allowed ({oct(max_permissions)})"

        # Check specific dangerous settings
        if mode & 0o002:  # World writable
            return False, "File is world-writable"

        # Executable setuid/setgid checks for regular files
        if os.path.isfile(path) and mode & (0o4000 | 0o2000):
            return False, "File has setuid or setgid bit set"

        return True, None

    except Exception as e:
        return False, f"Error checking file permissions: {e}"

def create_secure_tempdir(prefix: str = 'cli-tmp-',
                        dir: Optional[str] = None,
                        mode: int = 0o700) -> Optional[str]:
    """
    Create a secure temporary directory with proper permissions.

    Args:
        prefix: Prefix for the directory name
        dir: Parent directory location
        mode: Directory permission mode (default: 0o700 - owner only)

    Returns:
        Optional[str]: Path to the created directory or None on failure
    """
    import tempfile

    try:
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=prefix, dir=dir)

        # Set secure permissions
        os.chmod(temp_dir, mode)

        return temp_dir
    except Exception as e:
        logging.error(f"Failed to create secure temporary directory: {e}")
        return None

def protect_sensitive_data(text: str,
                         patterns: Optional[List[str]] = None,
                         replacement: str = "********") -> str:
    """
    Redact sensitive data in text strings.

    Args:
        text: Input text that may contain sensitive data
        patterns: List of regex patterns to identify sensitive data
        replacement: Text to use for replacement

    Returns:
        str: Text with sensitive data redacted
    """
    import re

    if not text:
        return text

    # Use default patterns if none provided
    if not patterns:
        patterns = [
            # API keys, tokens, etc.
            r'api[_-]?key[=:]\s*["\'](.*?)["\']',
            r'token[=:]\s*["\'](.*?)["\']',
            r'secret[=:]\s*["\'](.*?)["\']',
            r'password[=:]\s*["\'](.*?)["\']',

            # Common sensitive patterns
            r'\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}\b',  # API keys
            r'eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}',  # JWTs
        ]

    # Apply each pattern
    result = text
    for pattern in patterns:
        result = re.sub(pattern, r'\1' + replacement, result, flags=re.IGNORECASE)

    return result

# Constants for reuse across the CLI
CLI_SECURITY_CONSTANTS = {
    'MAX_FILE_SIZE': 100 * 1024 * 1024,  # 100 MB max file size for operations
    'SECURE_UMASK': 0o077,               # Default umask for secure operations
    'DEFAULT_TIMEOUT': 30,               # Default timeout for operations
    'MAX_PATH_LENGTH': 4096,             # Maximum safe path length
    'SAFE_PATHS': [                      # Default safe paths
        '/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/sbin'
    ],
    'UNSAFE_ENV_VARS': [
        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'DYLD_INSERT_LIBRARIES'
    ]
}
