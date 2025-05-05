#!/usr/bin/env python3
# filepath: admin/security/forensics/live_response/tests/test_functions.py
"""
Test helper functions for Live Response Forensic Tools

This module provides test utilities specifically for forensic tools testing,
with assertions designed for validating forensic evidence collection and
chain of custody requirements.
"""

import os
import sys
import subprocess
import json
import hashlib
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path

# Setup logging
logger = logging.getLogger('test_functions')
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import test constants - these are required for operation
from .test_constants import (
    TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT, TEST_SKIP_COUNT,
    TEST_RESULTS, TEST_VERBOSITY_DEBUG, TEST_VERBOSITY_VERBOSE,
    TEST_VERBOSITY_NORMAL, TEST_VERBOSITY_QUIET,
    STATUS_PASS, STATUS_FAIL, STATUS_SKIP, STATUS_ERROR,
    add_test_result, get_test_summary, reset_test_counters, clear_test_results,
    DEFAULT_TEST_FILE_PERMS, DEFAULT_TEST_DIR_PERMS, TEST_HASH_ALGORITHMS,
    TEST_CASE_ID, TEST_EXAMINER, TEST_FILE_CONTENT
)

# Test control variables
CURRENT_TEST_NAME = ""
TEST_START_TIME = ""
TEST_VERBOSITY = os.environ.get("TEST_VERBOSITY", TEST_VERBOSITY_NORMAL)

# --- Logging Functions ---

def _log(level: str, message: str) -> None:
    """Internal logging function."""
    if level == "DEBUG" and TEST_VERBOSITY not in [TEST_VERBOSITY_DEBUG]:
        return
    if level == "INFO" and TEST_VERBOSITY in [TEST_VERBOSITY_QUIET]:
        return
    if level == "WARN" and TEST_VERBOSITY in [TEST_VERBOSITY_QUIET]:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"{timestamp} [{level}] {message}"

    if level == "DEBUG":
        logger.debug(message)
    elif level == "INFO":
        logger.info(message)
    elif level == "SUCCESS":
        logger.info(f"✓ {message}")
    elif level == "WARN":
        logger.warning(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "AUDIT":
        logger.info(f"[AUDIT] {message}")

def log_debug(message: str) -> None:
    """Log a debug message."""
    _log("DEBUG", message)

def log_info(message: str) -> None:
    """Log an info message."""
    _log("INFO", message)

def log_success(message: str) -> None:
    """Log a success message."""
    _log("SUCCESS", message)

def log_warn(message: str) -> None:
    """Log a warning message."""
    _log("WARN", message)

def log_error(message: str) -> None:
    """Log an error message."""
    _log("ERROR", message)

def log_audit(message: str) -> None:
    """Log an audit message."""
    _log("AUDIT", message)

# --- Basic Assertion Functions ---

def assert_equals(actual: Any, expected: Any, description: str = "") -> bool:
    """
    Assert that two values are equal.

    Args:
        actual: The actual value
        expected: The expected value
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    TEST_COUNT += 1
    if actual == expected:
        log_success(f"PASS: {test_name}")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name}")
        log_error(f"  Expected: '{expected}'")
        log_error(f"  Actual:   '{actual}'")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"Expected: '{expected}', Actual: '{actual}'")
        return False

def assert_not_equals(actual: Any, not_expected: Any, description: str = "") -> bool:
    """
    Assert that two values are not equal.

    Args:
        actual: The actual value
        not_expected: The value that should not match
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    TEST_COUNT += 1
    if actual != not_expected:
        log_success(f"PASS: {test_name}")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name}")
        log_error(f"  Expected to be different from: '{not_expected}'")
        log_error(f"  Actual: '{actual}'")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0,
                       f"Expected to be different from: '{not_expected}', Actual: '{actual}'")
        return False

def assert_contains(haystack: str, needle: str, description: str = "") -> bool:
    """
    Assert that a string contains a substring.

    Args:
        haystack: The string to search in
        needle: The substring to search for
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    TEST_COUNT += 1
    if needle in haystack:
        log_success(f"PASS: {test_name}")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name}")
        log_error(f"  String does not contain: '{needle}'")
        log_error(f"  In: '{haystack[:200]}{'...' if len(haystack) > 200 else ''}'")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"String does not contain: '{needle}'")
        return False

def assert_success(cmd: str, description: str = "", timeout: int = 30) -> bool:
    """
    Assert that a command executes successfully (exit code 0).

    Args:
        cmd: Command to execute (as a string)
        description: Optional test description
        timeout: Timeout in seconds (default: 30)

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    log_debug(f"Running command (timeout: {timeout}s): {cmd}")

    # Measure execution time
    start_time = time.time()

    try:
        # Execute command with timeout
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        try:
            output, _ = process.communicate(timeout=timeout)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
            exit_code = -1
            output += "\n[TIMEOUT EXPIRED]"
    except Exception as e:
        exit_code = -1
        output = str(e)

    duration = time.time() - start_time

    TEST_COUNT += 1
    if exit_code == 0:
        log_success(f"PASS: {test_name} ({duration:.2f}s)")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, duration, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (Exit code: {exit_code}, {duration:.2f}s)")
        log_error(f"  Command: {cmd}")
        log_error(f"  Output: {output.strip()}")
        TEST_FAIL_COUNT += 1
        truncated_output = output[:200] + "..." if len(output) > 200 else output
        add_test_result(test_name, STATUS_FAIL, duration,
                       f"Exit code: {exit_code}, Output: {truncated_output}")
        return False

def assert_fail(cmd: str, description: str = "", timeout: int = 30) -> bool:
    """
    Assert that a command fails (non-zero exit code).

    Args:
        cmd: Command to execute (as a string)
        description: Optional test description
        timeout: Timeout in seconds (default: 30)

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    log_debug(f"Running command expecting failure (timeout: {timeout}s): {cmd}")

    # Measure execution time
    start_time = time.time()

    try:
        # Execute command with timeout
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        try:
            output, _ = process.communicate(timeout=timeout)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
            exit_code = -1
            output += "\n[TIMEOUT EXPIRED]"
    except Exception as e:
        exit_code = -1
        output = str(e)

    duration = time.time() - start_time

    TEST_COUNT += 1
    if exit_code != 0:
        log_success(f"PASS: {test_name} (Got expected non-zero exit code: {exit_code}, {duration:.2f}s)")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, duration, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (Expected non-zero exit code, got 0, {duration:.2f}s)")
        log_error(f"  Command: {cmd}")
        log_error(f"  Output: {output.strip()}")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, duration, "Expected non-zero exit code, got 0")
        return False

# --- File-based Assertion Functions ---

def assert_file_exists(file_path: str, description: str = "") -> bool:
    """
    Assert that a file exists.

    Args:
        file_path: File path
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    TEST_COUNT += 1
    if os.path.isfile(file_path):
        log_success(f"PASS: {test_name} (File exists: {file_path})")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (File does not exist: {file_path})")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"File does not exist: {file_path}")
        return False

def assert_file_not_exists(file_path: str, description: str = "") -> bool:
    """
    Assert that a file does not exist.

    Args:
        file_path: File path
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    TEST_COUNT += 1
    if not os.path.isfile(file_path):
        log_success(f"PASS: {test_name} (File does not exist: {file_path})")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (File exists: {file_path})")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"File exists: {file_path}")
        return False

def assert_dir_exists(dir_path: str, description: str = "") -> bool:
    """
    Assert that a directory exists.

    Args:
        dir_path: Directory path
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    TEST_COUNT += 1
    if os.path.isdir(dir_path):
        log_success(f"PASS: {test_name} (Directory exists: {dir_path})")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (Directory does not exist: {dir_path})")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"Directory does not exist: {dir_path}")
        return False

def assert_file_contains(file_path: str, pattern: str, description: str = "",
                         use_regex: bool = False) -> bool:
    """
    Assert that a file contains a specific string or pattern.

    Args:
        file_path: File path
        pattern: String or pattern to search for
        description: Optional test description
        use_regex: Whether to use regex matching (default: False)

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    # Check if file exists first
    if not os.path.isfile(file_path):
        TEST_COUNT += 1
        log_error(f"FAIL: {test_name} (File does not exist: {file_path})")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"File does not exist: {file_path}")
        return False

    # Read file content and search for pattern
    found = False
    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

        if use_regex:
            import re
            found = bool(re.search(pattern, content))
        else:
            found = pattern in content

    TEST_COUNT += 1
    if found:
        log_success(f"PASS: {test_name} (File contains pattern: {pattern})")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (File does not contain pattern: {pattern})")
        log_error("  File content (first 5 lines):")
        try:
            with open(file_path, 'r', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= 5:
                        break
                    log_error(f"    {line.rstrip()}")
        except Exception as e:
            log_error(f"    Error reading file: {e}")

        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"File does not contain pattern: {pattern}")
        return False

def assert_var_defined(var_name: str, description: str = "") -> bool:
    """
    Assert that a variable is defined in the caller's scope.

    Args:
        var_name: Variable name (without $)
        description: Optional test description

    Returns:
        bool: True if assertion passed, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"

    # Check if variable exists in caller's namespace
    import inspect
    frame = inspect.currentframe().f_back
    var_exists = var_name in frame.f_locals or var_name in frame.f_globals

    TEST_COUNT += 1
    if var_exists:
        log_success(f"PASS: {test_name} (Variable {var_name} is defined)")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name} (Variable {var_name} is not defined)")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"Variable {var_name} is not defined")
        return False

def skip_test(description: str, reason: str = "") -> bool:
    """
    Skip a test with a message.

    Args:
        description: Test name or description
        reason: Optional skip reason

    Returns:
        bool: Always True (indicating test was handled)
    """
    global TEST_COUNT, TEST_SKIP_COUNT
    test_name = CURRENT_TEST_NAME if CURRENT_TEST_NAME else description
    reason = reason if reason else "No reason provided"

    log_warn(f"SKIP: {test_name} ({reason})")
    TEST_COUNT += 1
    TEST_SKIP_COUNT += 1
    add_test_result(test_name, STATUS_SKIP, 0, reason)
    return True

# --- Forensic Verification Functions ---

def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = "sha256",
                     description: str = "") -> bool:
    """
    Verify file hash matches expected value.

    Args:
        file_path: File path
        expected_hash: Expected hash
        algorithm: Hash algorithm (default: sha256)
        description: Optional test description

    Returns:
        bool: True if hash matches, False otherwise
    """
    global TEST_COUNT, TEST_PASS_COUNT, TEST_FAIL_COUNT
    test_name = f"{CURRENT_TEST_NAME}{': ' + description if description else ''}"
    test_name = test_name if test_name else f"Verify {algorithm} hash of {file_path}"
    actual_hash = ""

    # Check if file exists
    if not os.path.isfile(file_path):
        TEST_COUNT += 1
        log_error(f"FAIL: {test_name} (File does not exist: {file_path})")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"File does not exist: {file_path}")
        return False

    # Calculate hash based on algorithm
    try:
        if algorithm.lower() == "md5":
            hash_obj = hashlib.md5()
        elif algorithm.lower() == "sha1":
            hash_obj = hashlib.sha1()
        elif algorithm.lower() == "sha256":
            hash_obj = hashlib.sha256()
        elif algorithm.lower() == "sha512":
            hash_obj = hashlib.sha512()
        else:
            TEST_COUNT += 1
            log_error(f"FAIL: {test_name} (Unsupported hash algorithm: {algorithm})")
            TEST_FAIL_COUNT += 1
            add_test_result(test_name, STATUS_FAIL, 0, f"Unsupported hash algorithm: {algorithm}")
            return False

        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        actual_hash = hash_obj.hexdigest()
    except Exception as e:
        TEST_COUNT += 1
        log_error(f"FAIL: {test_name} (Error calculating hash: {str(e)})")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0, f"Error calculating hash: {str(e)}")
        return False

    # Compare hashes (case insensitive)
    TEST_COUNT += 1
    if actual_hash.lower() == expected_hash.lower():
        log_success(f"PASS: {test_name} ({algorithm} hash matches: {expected_hash})")
        TEST_PASS_COUNT += 1
        add_test_result(test_name, STATUS_PASS, 0, "")
        return True
    else:
        log_error(f"FAIL: {test_name}")
        log_error(f"  Expected hash: {expected_hash}")
        log_error(f"  Actual hash:   {actual_hash}")
        TEST_FAIL_COUNT += 1
        add_test_result(test_name, STATUS_FAIL, 0,
                       f"Hash mismatch - Expected: {expected_hash}, Actual: {actual_hash}")
        return False

# --- Test Management Functions ---

def run_test_function(test_func: str) -> None:
    """
    Run a specific test function.

    Args:
        test_func: Name of the test function to run
    """
    global CURRENT_TEST_NAME

    # Set current test name
    CURRENT_TEST_NAME = test_func

    # Start timing
    start_time = time.time()

    # Get reference to the function
    import inspect
    frame = inspect.currentframe()
    try:
        # Find function in caller's namespace
        caller_globals = frame.f_back.f_globals

        if test_func in caller_globals and callable(caller_globals[test_func]):
            # Execute the test function in a safe manner
            try:
                caller_globals[test_func]()
            except Exception as e:
                log_error(f"Error in test function {test_func}: {str(e)}")
                import traceback
                log_error(traceback.format_exc())
                global TEST_FAIL_COUNT
                TEST_FAIL_COUNT += 1
                add_test_result(test_func, STATUS_ERROR, 0, f"Exception: {str(e)}")
        else:
            log_error(f"FAIL: Test function '{test_func}' not found.")
            global TEST_COUNT
            TEST_COUNT += 1
            TEST_FAIL_COUNT += 1
            add_test_result(test_func, STATUS_FAIL, 0, "Test function not found")
    finally:
        if frame:
            del frame  # Avoid reference cycles

    # End timing
    duration = time.time() - start_time
    log_debug(f"Test completed in {duration:.2f}s")

    # Reset current test name
    CURRENT_TEST_NAME = ""
    print()  # Add a newline for readability

def run_all_tests(pattern: str = "test_*") -> None:
    """
    Run all functions in the caller's module starting with "test_".

    Args:
        pattern: Optional pattern to filter test function names
    """
    import re
    log_info("=============================")
    log_info("Starting Live Response Tests")
    log_info("=============================")

    # Reset test counters
    reset_test_counters()

    # Clear test results
    clear_test_results()

    # Start timing
    start_time = time.time()

    # Find all test functions in caller's namespace
    import inspect
    frame = inspect.currentframe()
    try:
        # Get caller's globals
        caller_globals = frame.f_back.f_globals
        test_functions = []

        # Filter functions based on pattern
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")

        # Find all matching functions
        for name, obj in caller_globals.items():
            if callable(obj) and re.match(regex_pattern, name):
                test_functions.append(name)

        # Sort functions by name
        test_functions.sort()

        if not test_functions:
            log_error(f"No test functions match pattern: {pattern}")
            return

        # Run each test function
        for func in test_functions:
            run_test_function(func)
    finally:
        if frame:
            del frame  # Avoid reference cycles

    # End timing
    end_time = time.time()
    duration = end_time - start_time

    # Print summary
    log_info("=============================")
    log_info("Test Summary")
    log_info("=============================")
    log_info(f"Total tests run: {TEST_COUNT}")
    log_success(f"Passed: {TEST_PASS_COUNT}")

    if TEST_FAIL_COUNT > 0:
        log_error(f"Failed: {TEST_FAIL_COUNT}")
    else:
        log_info(f"Failed: {TEST_FAIL_COUNT}")

    if TEST_SKIP_COUNT > 0:
        log_warn(f"Skipped: {TEST_SKIP_COUNT}")
    else:
        log_info(f"Skipped: {TEST_SKIP_COUNT}")

    log_info(f"Total time: {duration:.2f}s")

    # Set exit code based on test results
    if TEST_FAIL_COUNT > 0:
        log_error("Some tests failed!")
        sys.exit(1)

def generate_test_report(format_type: str = "text", output_file: str = None) -> str:
    """
    Generate a test report in the specified format.

    Args:
        format_type: Report format ('text', 'json', 'junit', or 'markdown')
        output_file: Optional path to save the report to

    Returns:
        str: Generated report content
    """
    format_type = format_type.lower()

    if format_type not in ["text", "json", "junit", "markdown"]:
        log_warn(f"Unsupported report format: {format_type}. Defaulting to 'text'.")
        format_type = "text"

    # Generate report content based on format
    if format_type == "text":
        output = generate_text_report()
    elif format_type == "json":
        output = generate_json_report()
    elif format_type == "junit":
        output = generate_junit_report()
    elif format_type == "markdown":
        output = generate_markdown_report()

    # Save report to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output)
            log_info(f"Test report saved to: {output_file}")
        except Exception as e:
            log_error(f"Error saving test report: {str(e)}")

    return output

def generate_text_report() -> str:
    """Generate a plain text test report."""
    lines = []
    lines.append("Live Response Forensic Toolkit Test Report")
    lines.append("=========================================")
    lines.append("")
    lines.append(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("Test Summary")
    lines.append("------------")
    lines.append(f"Total Tests:  {TEST_COUNT}")
    lines.append(f"Passed:       {TEST_PASS_COUNT}")
    lines.append(f"Failed:       {TEST_FAIL_COUNT}")
    lines.append(f"Skipped:      {TEST_SKIP_COUNT}")
    lines.append("")
    lines.append("Test Details")
    lines.append("------------")

    for result in TEST_RESULTS:
        name, status, duration, message = result.split("|", 3)
        status_str = {
            STATUS_PASS: "PASS",
            STATUS_FAIL: "FAIL",
            STATUS_SKIP: "SKIP",
            STATUS_ERROR: "ERROR"
        }.get(status, status)

        duration_str = f"({duration}s)" if duration and duration != "0" else ""
        lines.append(f"{status_str}: {name} {duration_str}")

        if message:
            lines.append(f"    {message}")

    return "\n".join(lines)

def generate_json_report() -> str:
    """Generate a JSON test report."""
    import json

    data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": TEST_COUNT,
            "passed": TEST_PASS_COUNT,
            "failed": TEST_FAIL_COUNT,
            "skipped": TEST_SKIP_COUNT
        },
        "tests": []
    }

    for result in TEST_RESULTS:
        name, status, duration, message = result.split("|", 3)
        try:
            duration_float = float(duration) if duration else 0
        except ValueError:
            duration_float = 0

        test_data = {
            "name": name,
            "status": status,
            "duration": duration_float
        }

        if message:
            test_data["message"] = message

        data["tests"].append(test_data)

    return json.dumps(data, indent=2)

def generate_junit_report() -> str:
    """Generate a JUnit XML test report."""
    from xml.sax.saxutils import escape

    lines = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<testsuites>')
    lines.append(f'  <testsuite name="LiveResponseTests" tests="{TEST_COUNT}" failures="{TEST_FAIL_COUNT}" skipped="{TEST_SKIP_COUNT}" timestamp="{datetime.now().isoformat()}">')

    for result in TEST_RESULTS:
        name, status, duration, message = result.split("|", 3)
        try:
            duration_float = float(duration) if duration else 0
        except ValueError:
            duration_float = 0

        if status == STATUS_PASS:
            lines.append(f'    <testcase name="{escape(name)}" time="{duration_float}"/>')
        elif status == STATUS_SKIP:
            lines.append(f'    <testcase name="{escape(name)}" time="{duration_float}">')
            lines.append(f'      <skipped message="{escape(message)}"/>')
            lines.append('    </testcase>')
        else:  # FAIL or ERROR
            failure_type = "failure" if status == STATUS_FAIL else "error"
            lines.append(f'    <testcase name="{escape(name)}" time="{duration_float}">')
            lines.append(f'      <{failure_type} message="{escape(message)}"/>')
            lines.append('    </testcase>')

    lines.append('  </testsuite>')
    lines.append('</testsuites>')

    return "\n".join(lines)

def generate_markdown_report() -> str:
    """Generate a Markdown test report."""
    lines = []
    lines.append("# Live Response Forensic Toolkit Test Report")
    lines.append("")
    lines.append(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| ------ | ----- |")
    lines.append(f"| Total Tests | {TEST_COUNT} |")
    lines.append(f"| Passed | {TEST_PASS_COUNT} |")
    lines.append(f"| Failed | {TEST_FAIL_COUNT} |")
    lines.append(f"| Skipped | {TEST_SKIP_COUNT} |")
    lines.append("")
    lines.append("## Detailed Results")
    lines.append("")

    current_status = None
    for result in TEST_RESULTS:
        name, status, duration, message = result.split("|", 3)

        if status != current_status:
            current_status = status
            status_heading = {
                STATUS_PASS: "### ✅ Passed Tests",
                STATUS_FAIL: "### ❌ Failed Tests",
                STATUS_SKIP: "### ⚠️ Skipped Tests",
                STATUS_ERROR: "### 🔥 Error Tests"
            }.get(status, f"### {status} Tests")
            lines.append("")
            lines.append(status_heading)
            lines.append("")

        duration_str = f"({duration}s)" if duration and duration != "0" else ""
        lines.append(f"- **{name}** {duration_str}")

        if message:
            lines.append(f"  - {message}")

    return "\n".join(lines)

def show_usage():
    """Show usage information for the test runner."""
    print("""
Live Response Forensic Tools Test Runner

Usage: python test_functions.py [options]

Options:
  -v, --verbose       Show detailed output
  -h, --help          Show this help message
  -p, --pattern PAT   Run only tests matching pattern (e.g., "test_*_hash")
  -f, --format FMT    Report format: text, json, junit, or markdown
  -o, --output FILE   Save report to specified file

Examples:
  python test_functions.py --verbose
  python test_functions.py --pattern "test_crypto_*" --format json --output report.json
""")

def parse_args() -> Dict[str, Any]:
    """
    Parse command line arguments.

    Returns:
        Dict[str, Any]: Dictionary of parsed arguments
    """
    import argparse

    parser = argparse.ArgumentParser(description="Live Response Forensic Toolkit Test Runner")
    parser.add_argument("--test", "-t", help="Specific test or pattern to run")
    parser.add_argument("--report", "-r", choices=["text", "json", "junit", "markdown"],
                       default="text", help="Report format")
    parser.add_argument("--output", "-o", help="Output file for test report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args()

    # Update verbosity level
    global TEST_VERBOSITY
    if args.verbose:
        TEST_VERBOSITY = TEST_VERBOSITY_VERBOSE
    elif args.quiet:
        TEST_VERBOSITY = TEST_VERBOSITY_QUIET

    return vars(args)

# Define exports
__all__ = [
    # Basic assertion functions
    'assert_equals',
    'assert_not_equals',
    'assert_contains',
    'assert_success',
    'assert_fail',

    # File-based assertion functions
    'assert_file_exists',
    'assert_file_not_exists',
    'assert_dir_exists',
    'assert_file_contains',

    # Variable assertions
    'assert_var_defined',
    'skip_test',

    # Forensic verification
    'verify_file_hash',

    # Test management
    'run_test_function',
    'run_all_tests',
    'generate_test_report',
    'parse_args',
    'show_usage',

    # Logging functions
    'log_debug',
    'log_info',
    'log_success',
    'log_warn',
    'log_error',
    'log_audit',

    # Constants exposure
    'TEST_VERBOSITY_DEBUG',
    'TEST_VERBOSITY_VERBOSE',
    'TEST_VERBOSITY_NORMAL',
    'TEST_VERBOSITY_QUIET',
    'STATUS_PASS',
    'STATUS_FAIL',
    'STATUS_SKIP',
    'STATUS_ERROR'
]

# Run tests if script is executed directly
if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_args()

    # Run tests
    if args.get("test"):
        run_all_tests(args["test"])
    else:
        run_all_tests()

    # Generate report
    if args.get("output"):
        generate_test_report(args.get("report", "text"), args["output"])
