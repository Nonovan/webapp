#!/usr/bin/env python3
# filepath: scripts/security/audit/checkers/common/check_utils.py
"""
Common utility functions for security checkers.

This module provides reusable functions for security checks implementation
including baseline loading, value comparison, secure command execution,
permission calculation, and other security-related utilities.
"""

import os
import psutil
import re
import yaml
import json
import hashlib
import logging
import subprocess
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from enum import Enum

# Configure logging
logger = logging.getLogger("security.audit.checker")

# Define standard paths
DEFAULT_BASELINE_DIR = Path(__file__).parent.parent.parent / "baseline"
DEFAULT_CONFIG_DIR = Path("/etc/cloud-platform/security")
USER_CONFIG_DIR = Path.home() / ".cloud-platform/security"

# Define constants
DEFAULT_TIMEOUT = 30  # Default timeout for command execution in seconds
MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB max output size


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    CIS = "CIS"
    NIST = "NIST"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    GDPR = "GDPR"


def load_baseline(name: str, environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a security baseline configuration from the baseline directory.

    Args:
        name: The baseline name (filename without extension)
        environment: Optional environment name (development, staging, production)
                     If provided, will attempt to load environment-specific baseline

    Returns:
        Loaded baseline configuration as dictionary

    Raises:
        FileNotFoundError: If baseline file cannot be found
        ValueError: If baseline format is invalid
    """
    # Construct possible baseline paths
    paths = []
    if environment:
        # Try environment-specific baseline first
        paths.append(DEFAULT_BASELINE_DIR / f"{name}.{environment}.yaml")
        paths.append(DEFAULT_BASELINE_DIR / f"{name}.{environment}.yml")
        paths.append(DEFAULT_BASELINE_DIR / environment / f"{name}.yaml")
        paths.append(DEFAULT_BASELINE_DIR / environment / f"{name}.yml")

    # Add default baseline paths
    paths.append(DEFAULT_BASELINE_DIR / f"{name}.yaml")
    paths.append(DEFAULT_BASELINE_DIR / f"{name}.yml")
    paths.append(DEFAULT_CONFIG_DIR / f"{name}.yaml")
    paths.append(USER_CONFIG_DIR / f"{name}.yaml")

    # Try each path in order
    for path in paths:
        if path.exists() and path.is_file():
            logger.debug(f"Loading baseline from {path}")
            try:
                with open(path, 'r') as f:
                    baseline = yaml.safe_load(f)
                    if not isinstance(baseline, dict):
                        raise ValueError(f"Invalid baseline format in {path} - expected dictionary")
                    return baseline
            except Exception as e:
                logger.error(f"Error loading baseline from {path}: {e}")
                raise

    # No baseline found
    raise FileNotFoundError(f"Could not find baseline '{name}' for environment '{environment}'")


def get_file_permissions(path: Union[str, Path]) -> int:
    """
    Get numeric file permissions.

    Args:
        path: Path to the file or directory

    Returns:
        Permission bits as octal integer (0o777 format)
    """
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except (FileNotFoundError, PermissionError) as e:
        logger.warning(f"Cannot get permissions for {path}: {e}")
        raise


def check_file_ownership(path: Union[str, Path],
                        expected_owner: Optional[str] = None,
                        expected_group: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Check if a file or directory has the expected owner and group.

    Args:
        path: Path to the file or directory
        expected_owner: Expected owner username (None to skip check)
        expected_group: Expected group name (None to skip check)

    Returns:
        Tuple of (success_flag, evidence_dict)
    """
    path = Path(path)
    evidence = {
        "path": str(path),
        "exists": path.exists(),
    }

    if not path.exists():
        return False, evidence

    try:
        import pwd
        import grp

        stat_info = path.stat()

        # Get owner and group names
        try:
            actual_owner = pwd.getpwuid(stat_info.st_uid).pw_name
            actual_group = grp.getgrgid(stat_info.st_gid).gr_name
        except (KeyError, ImportError):
            # Fall back to numeric IDs if names cannot be resolved
            actual_owner = str(stat_info.st_uid)
            actual_group = str(stat_info.st_gid)

        evidence["owner"] = actual_owner
        evidence["group"] = actual_group

        # Check owner and group if expected values provided
        owner_ok = expected_owner is None or actual_owner == expected_owner
        group_ok = expected_group is None or actual_group == expected_group

        if expected_owner is not None:
            evidence["expected_owner"] = expected_owner
        if expected_group is not None:
            evidence["expected_group"] = expected_group

        return owner_ok and group_ok, evidence

    except Exception as e:
        logger.warning(f"Error checking ownership of {path}: {e}")
        evidence["error"] = str(e)
        return False, evidence


def is_world_writable(path: Union[str, Path]) -> bool:
    """
    Check if a file or directory is world-writable.

    Args:
        path: Path to the file or directory

    Returns:
        True if world-writable, False otherwise
    """
    try:
        mode = get_file_permissions(path)
        return bool(mode & stat.S_IWOTH)
    except Exception:
        return False


def is_world_readable(path: Union[str, Path]) -> bool:
    """
    Check if a file or directory is world-readable.

    Args:
        path: Path to the file or directory

    Returns:
        True if world-readable, False otherwise
    """
    try:
        mode = get_file_permissions(path)
        return bool(mode & stat.S_IROTH)
    except Exception:
        return False


def is_suid_set(path: Union[str, Path]) -> bool:
    """
    Check if a file has the SUID bit set.

    Args:
        path: Path to the file

    Returns:
        True if SUID bit is set, False otherwise
    """
    try:
        return bool(os.stat(path).st_mode & stat.S_ISUID)
    except Exception:
        return False


def is_sgid_set(path: Union[str, Path]) -> bool:
    """
    Check if a file has the SGID bit set.

    Args:
        path: Path to the file

    Returns:
        True if SGID bit is set, False otherwise
    """
    try:
        return bool(os.stat(path).st_mode & stat.S_ISGID)
    except Exception:
        return False


def secure_execute(command: Union[str, List[str]],
                  timeout: int = DEFAULT_TIMEOUT,
                  shell: bool = False,
                  check: bool = False,
                  env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """
    Execute a command securely with proper error handling and resource limits.

    Args:
        command: The command to execute (string or list of arguments)
        timeout: Maximum execution time in seconds
        shell: Whether to execute through the shell
        check: Whether to check the return code and raise an exception on non-zero exit
        env: Optional environment variables dictionary

    Returns:
        CompletedProcess instance with returncode, stdout, and stderr

    Raises:
        subprocess.TimeoutExpired: If the command times out
        subprocess.SubprocessError: If check=True and the command fails
    """
    # Set a restrictive environment if none provided
    if env is None:
        env = os.environ.copy()
        # Remove potentially dangerous environment variables
        for var in ['LD_PRELOAD', 'LD_LIBRARY_PATH']:
            env.pop(var, None)

    # Set resource limits
    import resource
    # Prevent creation of new processes
    resource.setrlimit(resource.RLIMIT_NPROC, (100, 100))
    # Limit file size creation
    resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))  # 10MB

    logger.debug(f"Executing command: {command}")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=shell,
            check=check,
            env=env,
            text=True
        )

        # Truncate output if too large
        if len(result.stdout) > MAX_OUTPUT_SIZE:
            result.stdout = result.stdout[:MAX_OUTPUT_SIZE] + "\n... [output truncated] ..."
        if len(result.stderr) > MAX_OUTPUT_SIZE:
            result.stderr = result.stderr[:MAX_OUTPUT_SIZE] + "\n... [output truncated] ..."

        return result
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        raise


def find_files_with_pattern(directory: Union[str, Path],
                           pattern: str,
                           max_depth: int = 5,
                           exclude_paths: Optional[List[str]] = None) -> List[str]:
    """
    Find files matching a pattern with security safeguards.

    Args:
        directory: The directory to search in
        pattern: Glob pattern for matching files
        max_depth: Maximum directory depth to search
        exclude_paths: List of path patterns to exclude

    Returns:
        List of matching file paths
    """
    if exclude_paths is None:
        exclude_paths = []

    # Compile exclude path regexes
    exclude_regexes = [re.compile(ex_pattern) for ex_pattern in exclude_paths]

    directory = Path(directory)
    matching_files = []

    try:
        # Traverse directory up to max_depth
        for root, dirs, files in os.walk(str(directory)):
            # Check depth to limit search scope
            current_depth = len(Path(root).relative_to(directory).parts)
            if current_depth > max_depth:
                dirs.clear()  # Don't go deeper than max_depth
                continue

            # Check each file against pattern
            for filename in files:
                file_path = os.path.join(root, filename)

                # Skip excluded paths
                if any(regex.search(file_path) for regex in exclude_regexes):
                    continue

                # Check if file matches pattern
                if re.search(pattern, filename):
                    matching_files.append(file_path)

    except Exception as e:
        logger.error(f"Error searching files: {e}")

    return matching_files


def compute_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
    """
    Compute the hash of a file using the specified algorithm.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256', 'sha512')

    Returns:
        Hex-encoded hash string

    Raises:
        ValueError: If algorithm is not supported
        FileNotFoundError: If the file doesn't exist
    """
    # Check if algorithm is supported
    if algorithm not in hashlib.algorithms_guaranteed:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Create hash object based on algorithm
    hash_func = getattr(hashlib, algorithm)()

    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error computing hash for {file_path}: {e}")
        raise


def compare_versions(version1: str, version2: str, operator: str) -> bool:
    """
    Compare two version strings using the specified operator.

    Args:
        version1: First version string (e.g., '1.2.3')
        version2: Second version string (e.g., '1.3.0')
        operator: Comparison operator ('==', '!=', '<', '<=', '>', '>=')

    Returns:
        Boolean result of the comparison
    """
    from packaging import version

    # Parse versions
    v1 = version.parse(version1)
    v2 = version.parse(version2)

    # Perform comparison based on operator
    if operator == '==':
        return v1 == v2
    elif operator == '!=':
        return v1 != v2
    elif operator == '<':
        return v1 < v2
    elif operator == '<=':
        return v1 <= v2
    elif operator == '>':
        return v1 > v2
    elif operator == '>=':
        return v1 >= v2
    else:
        raise ValueError(f"Invalid comparison operator: {operator}")


def sanitize_string(input_str: str) -> str:
    """
    Sanitize a string by removing potentially dangerous characters.

    Args:
        input_str: The input string to sanitize

    Returns:
        Sanitized string
    """
    # Remove control characters and common shell metacharacters
    return re.sub(r'[\x00-\x1F\x7F-\x9F\'"`;|&$><]', '', input_str)


def is_valid_ip_address(ip: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).

    Args:
        ip: String to check

    Returns:
        True if valid IP address, False otherwise
    """
    # IPv4
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True

    # IPv6
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|' \
                  r'^([0-9a-fA-F]{1,4}:){1,7}:|' \
                  r'^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|' \
                  r'^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|' \
                  r'^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|' \
                  r'^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|' \
                  r'^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|' \
                  r'^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|' \
                  r'^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|' \
                  r'^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}$|' \
                  r'^::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$|' \
                  r'^([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$'
    return bool(re.match(ipv6_pattern, ip))


def is_valid_port(port: Union[str, int]) -> bool:
    """
    Check if a value is a valid port number.

    Args:
        port: Port number (string or integer)

    Returns:
        True if valid port, False otherwise
    """
    try:
        port_int = int(port)
        return 0 < port_int < 65536
    except (ValueError, TypeError):
        return False


def get_os_info() -> Dict[str, str]:
    """
    Get information about the operating system.

    Returns:
        Dictionary with OS information
    """
    os_info = {
        'name': 'unknown',
        'version': 'unknown',
        'distribution': 'unknown'
    }

    # Try to get OS info from different sources
    try:
        import platform
        os_info['system'] = platform.system()
        os_info['release'] = platform.release()
        os_info['version'] = platform.version()

        # For Linux, try to get distribution info
        if platform.system() == 'Linux':
            # Try to read /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            os_info['distribution'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('VERSION_ID='):
                            os_info['dist_version'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('PRETTY_NAME='):
                            os_info['pretty_name'] = line.split('=')[1].strip().strip('"')

            # Try distribution-specific files
            elif os.path.exists('/etc/redhat-release'):
                with open('/etc/redhat-release', 'r') as f:
                    os_info['pretty_name'] = f.read().strip()
                    os_info['distribution'] = 'rhel'
            elif os.path.exists('/etc/debian_version'):
                with open('/etc/debian_version', 'r') as f:
                    os_info['dist_version'] = f.read().strip()
                    os_info['distribution'] = 'debian'
    except Exception as e:
        logger.warning(f"Error getting OS information: {e}")

    return os_info


def find_process_by_name(name: str) -> List[int]:
    """
    Find process IDs by name.

    Args:
        name: Process name to search for

    Returns:
        List of matching process IDs
    """
    pids = []

    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if name.lower() in proc.info['name'].lower():
                pids.append(proc.info['pid'])
    except ImportError:
        # Fall back to ps command if psutil is not available
        try:
            result = secure_execute(['ps', '-e', '-o', 'pid,comm'], shell=False)
            if result.returncode == 0:
                for line in result.stdout.splitlines()[1:]:  # Skip header
                    if name in line:
                        pid = int(line.strip().split()[0])
                        pids.append(pid)
        except Exception as e:
            logger.warning(f"Error finding process by name: {e}")

    return pids


def check_port_listening(port: int, interface: str = '0.0.0.0') -> bool:
    """
    Check if a port is listening on a specific interface.

    Args:
        port: Port number
        interface: Network interface IP (default: '0.0.0.0' for all interfaces)

    Returns:
        True if port is listening, False otherwise
    """
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((interface, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.warning(f"Error checking port {port}: {e}")
        return False


def parse_config_file(file_path: Union[str, Path],
                    pattern: str) -> Dict[str, str]:
    """
    Parse a configuration file using regex pattern matching.

    Args:
        file_path: Path to the configuration file
        pattern: Regex pattern with named capture groups

    Returns:
        Dictionary with matched values
    """
    result = {}
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # Find all matches
        matches = re.finditer(pattern, content)
        for match in matches:
            # Add all named groups to result dictionary
            for name, value in match.groupdict().items():
                if value is not None:
                    result[name] = value
    except Exception as e:
        logger.warning(f"Error parsing config file {file_path}: {e}")

    return result


def get_compliance_requirements(
    framework: Union[str, ComplianceFramework],
    control_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compliance requirements for a specific framework and optional control ID.

    Args:
        framework: The compliance framework
        control_id: Optional control ID within the framework

    Returns:
        Dictionary with compliance requirements
    """
    # Normalize framework input
    if isinstance(framework, str):
        try:
            framework = ComplianceFramework(framework)
        except ValueError:
            logger.warning(f"Unknown compliance framework: {framework}")
            return {}

    # Construct path to compliance requirements file
    compliance_file = DEFAULT_BASELINE_DIR / "compliance" / f"{framework.value.lower()}.yaml"

    try:
        if not compliance_file.exists():
            logger.warning(f"Compliance file not found: {compliance_file}")
            return {}

        with open(compliance_file, 'r') as f:
            compliance_data = yaml.safe_load(f)

        # Return specific control if requested
        if control_id and control_id in compliance_data:
            return {control_id: compliance_data[control_id]}

        return compliance_data
    except Exception as e:
        logger.warning(f"Error loading compliance requirements: {e}")
        return {}


def get_environment() -> str:
    """
    Determine the current environment (development, staging, production).

    Returns:
        Environment name string
    """
    # Check environment variable
    env = os.environ.get('ENVIRONMENT') or os.environ.get('ENV')
    if env:
        return env.lower()

    # Try to determine from hostname
    try:
        import socket
        hostname = socket.gethostname().lower()
        if 'prod' in hostname:
            return 'production'
        elif 'stag' in hostname or 'test' in hostname:
            return 'staging'
        elif 'dev' in hostname:
            return 'development'
    except Exception:
        pass

    # Default to development
    return 'development'


def convert_to_human_readable(value: Any) -> str:
    """
    Convert a value to a human-readable string representation.

    Args:
        value: The value to convert

    Returns:
        Human-readable string representation
    """
    if isinstance(value, bool):
        return "Yes" if value else "No"
    elif isinstance(value, (int, float)) and value >= 1024 and value % 1024 == 0:
        # Convert to KB/MB/GB if appropriate
        if value >= 1024 * 1024 * 1024:
            return f"{value / (1024 * 1024 * 1024):.1f} GB"
        elif value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.1f} MB"
        elif value >= 1024:
            return f"{value / 1024:.1f} KB"
    elif isinstance(value, (list, tuple)):
        return ", ".join(str(x) for x in value)
    elif isinstance(value, dict):
        return json.dumps(value, indent=2)

    return str(value)


if __name__ == "__main__":
    # This section will only run when the file is executed directly
    print("Security Check Utilities Module")
    print(f"OS Information: {get_os_info()}")
    print(f"Current Environment: {get_environment()}")
