"""
Test Constants for Live Response Forensic Toolkit

This module defines constants used across the Live Response Forensic Toolkit test suite.
It provides shared variables for tracking test outcomes, results, and statistics to
maintain consistent test reporting across both shell script and Python test components.
"""

import os
import sys
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
    global TEST_RESULTS, TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT, TEST_SKIP_COUNT

    # Add to appropriate counter
    TEST_COUNT += 1
    if status == STATUS_PASS:
        TEST_PASS_COUNT += 1
    elif status == STATUS_FAIL:
        TEST_FAIL_COUNT += 1
    elif status == STATUS_SKIP:
        TEST_SKIP_COUNT += 1

    # Add to results list
    TEST_RESULTS.append(f"{name}|{status}|{duration}|{message}")

# Create necessary directories if they don't exist
try:
    TEST_DATA_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    TEST_OUTPUT_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    TEST_TEMP_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
except (OSError, PermissionError) as e:
    print(f"Warning: Could not create test directories: {e}", file=sys.stderr)
