"""
Test Constants for Live Response Forensic Toolkit

This module defines constants used across the Live Response Forensic Toolkit test suite.
It provides shared variables for tracking test outcomes, results, and statistics to
maintain consistent test reporting across both shell script and Python test components.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

# Base test tracking variables
TEST_COUNT = 0
TEST_PASS_COUNT = 0
TEST_FAIL_COUNT = 0
TEST_SKIP_COUNT = 0

# Test results storage - format: [ "test_name|status|duration|message", ... ]
# Example: "test_memory_acquisition: verify hash|PASS|0.5|"
TEST_RESULTS = []

# Thresholds for test validation
FILE_HASH_VERIFICATION_TIMEOUT = 60  # Seconds to wait for file hash verification
COMMAND_EXECUTION_TIMEOUT = 30       # Default timeout for command execution in tests
PROCESS_START_TIMEOUT = 10           # Seconds to wait for a process to start
NETWORK_CONNECTION_TIMEOUT = 5       # Seconds to wait for network connections
TEST_FILE_MAX_SIZE = 10 * 1024 * 1024  # 10MB max size for test files

# Test directories and paths
TEST_ROOT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA_DIR = TEST_ROOT_DIR / "test_data"
TEST_OUTPUT_DIR = TEST_ROOT_DIR / "test_output"
TEST_TEMP_DIR = TEST_ROOT_DIR / "test_temp"

# Result status constants
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"
STATUS_ERROR = "ERROR"

# Test execution modes
TEST_MODE_UNIT = "unit"
TEST_MODE_INTEGRATION = "integration"
TEST_MODE_ALL = "all"

# Test verbosity levels
TEST_VERBOSITY_QUIET = "quiet"
TEST_VERBOSITY_NORMAL = "normal"
TEST_VERBOSITY_VERBOSE = "verbose"
TEST_VERBOSITY_DEBUG = "debug"

# Default file permissions for test evidence files
DEFAULT_TEST_FILE_PERMS = 0o600  # Owner read/write only
DEFAULT_TEST_DIR_PERMS = 0o750   # Owner rwx, group read/execute

# Hash algorithms for testing file integrity
TEST_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

# Test case identification information
TEST_CASE_ID = "TEST-CASE-2024-001"
TEST_EXAMINER = "Forensic Tester"

# Content for test files
TEST_FILE_CONTENT = """This is test file content for the Live Response Forensic Toolkit.
It contains multiple lines to test various parsing functions.
Line 3 contains some keywords: password, secret, token
Line 4 has an IP address: 192.168.1.100
Line 5 has a domain: malicious-domain.example.com
--- END OF TEST CONTENT ---
"""

# Functions to reset test tracking variables
def reset_test_counters() -> None:
    """Reset test counters to initial values."""
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT, TEST_SKIP_COUNT
    TEST_COUNT = 0
    TEST_PASS_COUNT = 0
    TEST_FAIL_COUNT = 0
    TEST_SKIP_COUNT = 0

def clear_test_results() -> None:
    """Clear the test results list."""
    global TEST_RESULTS
    TEST_RESULTS = []

def get_test_summary() -> Dict[str, Any]:
    """
    Get a summary of test execution results.

    Returns:
        dict: Dictionary containing test result summary
    """
    return {
        "total": TEST_COUNT,
        "passed": TEST_PASS_COUNT,
        "failed": TEST_FAIL_COUNT,
        "skipped": TEST_SKIP_COUNT,
        "success_rate": (TEST_PASS_COUNT / TEST_COUNT * 100) if TEST_COUNT > 0 else 0
    }

def add_test_result(name: str, status: str, duration: float, message: str = "") -> None:
    """
    Add a test result to the results list.

    Args:
        name: Test name/identifier
        status: Test status (PASS, FAIL, SKIP, ERROR)
        duration: Test duration in seconds
        message: Optional message (failure details, skip reason, etc.)
    """
    global TEST_RESULTS
    TEST_RESULTS.append(f"{name}|{status}|{duration}|{message}")

def create_test_evidence_file(directory: Path, filename: str, content: str = None) -> Path:
    """
    Create a test evidence file with specified content.

    Args:
        directory: Directory where the file should be created
        filename: Name of the file to create
        content: Content to write to file (defaults to TEST_FILE_CONTENT)

    Returns:
        Path to the created file
    """
    if content is None:
        content = TEST_FILE_CONTENT

    file_path = directory / filename
    file_path.write_text(content)
    os.chmod(file_path, DEFAULT_TEST_FILE_PERMS)

    return file_path

def create_test_evidence_directory(base_dir: Path, dir_name: str) -> Path:
    """
    Create a test evidence directory with proper permissions.

    Args:
        base_dir: Parent directory where the directory should be created
        dir_name: Name of the directory to create

    Returns:
        Path to the created directory
    """
    dir_path = base_dir / dir_name
    dir_path.mkdir(parents=True, exist_ok=True)
    os.chmod(dir_path, DEFAULT_TEST_DIR_PERMS)

    return dir_path

def get_test_metadata() -> Dict[str, Any]:
    """
    Get standard test metadata for evidence files.

    Returns:
        Dictionary with standard metadata for test evidence
    """
    return {
        "case_id": TEST_CASE_ID,
        "examiner": TEST_EXAMINER,
        "timestamp": datetime.now().isoformat(),
        "test_run_id": f"TEST-RUN-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "environment": "test"
    }

def write_test_metadata(directory: Path, metadata: Dict[str, Any] = None) -> Path:
    """
    Write standard test metadata to a file.

    Args:
        directory: Directory where to write metadata file
        metadata: Optional metadata (defaults to get_test_metadata())

    Returns:
        Path to the created metadata file
    """
    if metadata is None:
        metadata = get_test_metadata()

    metadata_path = directory / "test_metadata.json"
    with metadata_path.open('w') as f:
        json.dump(metadata, f, indent=2)

    os.chmod(metadata_path, DEFAULT_TEST_FILE_PERMS)
    return metadata_path

def calculate_test_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash for a test file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hash digest as a string
    """
    import hashlib

    hash_func = getattr(hashlib, algorithm.lower())()

    with file_path.open('rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)

    return hash_func.hexdigest()

# Create necessary directories if they don't exist
try:
    TEST_DATA_DIR.mkdir(mode=DEFAULT_TEST_DIR_PERMS, parents=True, exist_ok=True)
    TEST_OUTPUT_DIR.mkdir(mode=DEFAULT_TEST_DIR_PERMS, parents=True, exist_ok=True)
    TEST_TEMP_DIR.mkdir(mode=DEFAULT_TEST_DIR_PERMS, parents=True, exist_ok=True)
except (OSError, PermissionError) as e:
    print(f"Warning: Could not create test directories: {e}", file=sys.stderr)

# Module exports - define what should be accessible when importing
__all__ = [
    # Test tracking variables
    'TEST_COUNT', 'TEST_PASS_COUNT', 'TEST_FAIL_COUNT', 'TEST_SKIP_COUNT', 'TEST_RESULTS',

    # Test thresholds
    'FILE_HASH_VERIFICATION_TIMEOUT', 'COMMAND_EXECUTION_TIMEOUT',
    'PROCESS_START_TIMEOUT', 'NETWORK_CONNECTION_TIMEOUT', 'TEST_FILE_MAX_SIZE',

    # Test paths
    'TEST_ROOT_DIR', 'TEST_DATA_DIR', 'TEST_OUTPUT_DIR', 'TEST_TEMP_DIR',

    # Status constants
    'STATUS_PASS', 'STATUS_FAIL', 'STATUS_SKIP', 'STATUS_ERROR',

    # Test modes
    'TEST_MODE_UNIT', 'TEST_MODE_INTEGRATION', 'TEST_MODE_ALL',

    # Verbosity levels
    'TEST_VERBOSITY_QUIET', 'TEST_VERBOSITY_NORMAL', 'TEST_VERBOSITY_VERBOSE', 'TEST_VERBOSITY_DEBUG',

    # Test file settings
    'DEFAULT_TEST_FILE_PERMS', 'DEFAULT_TEST_DIR_PERMS', 'TEST_HASH_ALGORITHMS',

    # Test case information
    'TEST_CASE_ID', 'TEST_EXAMINER', 'TEST_FILE_CONTENT',

    # Functions
    'reset_test_counters', 'clear_test_results', 'get_test_summary', 'add_test_result',
    'create_test_evidence_file', 'create_test_evidence_directory',
    'get_test_metadata', 'write_test_metadata', 'calculate_test_file_hash'
]
