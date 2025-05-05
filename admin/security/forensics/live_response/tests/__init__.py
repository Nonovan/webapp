"""
Live Response Forensic Toolkit - Test Module

This module provides testing utilities for validating the functionality of the
Live Response Forensic Toolkit. It includes unit tests, integration tests, and
helper functions for testing forensic evidence collection and verification.

The test suite validates:
- Memory acquisition functionality
- Volatile data collection tools
- Network state analysis utilities
- Evidence packaging and integrity verification
- Chain of custody documentation
"""

import os
import sys
import logging
from pathlib import Path

# Version information
__version__ = "0.1.1"
__author__ = "Security Forensics Team"

# Export test constants
try:
    from .test_constants import (
        # Base test tracking variables
        TEST_COUNT,
        TEST_PASS_COUNT,
        TEST_FAIL_COUNT,
        TEST_SKIP_COUNT,
        TEST_RESULTS,

        # Test directories and paths
        TEST_ROOT_DIR,
        TEST_DATA_DIR,
        TEST_OUTPUT_DIR,
        TEST_TEMP_DIR,

        # Result status constants
        STATUS_PASS,
        STATUS_FAIL,
        STATUS_SKIP,
        STATUS_ERROR,

        # Test execution modes
        TEST_MODE_UNIT,
        TEST_MODE_INTEGRATION,
        TEST_MODE_ALL,

        # Verbosity levels
        TEST_VERBOSITY_QUIET,
        TEST_VERBOSITY_NORMAL,
        TEST_VERBOSITY_VERBOSE,
        TEST_VERBOSITY_DEBUG,

        # Test file settings
        DEFAULT_TEST_FILE_PERMS,
        DEFAULT_TEST_DIR_PERMS,
        TEST_HASH_ALGORITHMS,

        # Test case information
        TEST_CASE_ID,
        TEST_EXAMINER,
        TEST_FILE_CONTENT,

        # Test management functions
        reset_test_counters,
        clear_test_results,
        get_test_summary,
        add_test_result,

        # Test evidence functions
        create_test_evidence_file,
        create_test_evidence_directory,
        get_test_metadata,
        write_test_metadata,
        calculate_test_file_hash
    )
    TEST_CONSTANTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Could not import test constants: {e}")
    TEST_CONSTANTS_AVAILABLE = False

# Export test utility functions
try:
    from .test_functions import (
        # Basic assertion functions
        assert_equals,
        assert_not_equals,
        assert_contains,
        assert_success,
        assert_fail,
        assert_file_exists,
        assert_file_not_exists,
        assert_dir_exists,
        assert_file_contains,
        assert_var_defined,
        skip_test,
        verify_file_hash,

        # Test runner functions
        run_test_function,
        run_all_tests,
        generate_test_report,
        parse_args,
        show_usage,

        # Logging functions
        log_debug,
        log_info,
        log_success,
        log_warn,
        log_error,
        log_audit
    )
    TEST_FUNCTIONS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Could not import test functions: {e}")
    TEST_FUNCTIONS_AVAILABLE = False

# Export validation suite components
try:
    from .validation_suite import (
        # Helper functions
        run_script,
        setup_test_environment,
        cleanup_test_environment,

        # Test classes
        TestArtifactParser,
        TestEvidencePackagingScript,
        TestMemoryAcquisitionScript,
        TestNetworkStateScript,
        TestVolatileDataScript,
        TestEvidenceIntegrityFunctions,

        # Constants
        TEST_DATA_DIR,
        TEST_OUTPUT_DIR,
        ARTIFACT_PARSER_SCRIPT,
        EVIDENCE_PACKAGING_SCRIPT,
        MEMORY_ACQUISITION_SCRIPT,
        NETWORK_STATE_SCRIPT,
        VOLATILE_DATA_SCRIPT,
        COMMON_FUNCTIONS_SCRIPT,

        # Availability flags
        ARTIFACT_PARSER_AVAILABLE,
        FORENSIC_UTILS_AVAILABLE
    )
    VALIDATION_SUITE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Could not import validation suite: {e}")
    VALIDATION_SUITE_AVAILABLE = False

# Determine base test directory
TEST_DIR = Path(__file__).parent

def get_available_tests():
    """
    Returns information about available tests in the test suite.

    Returns:
        dict: Dictionary containing available test components and their status
    """
    return {
        "test_constants": TEST_CONSTANTS_AVAILABLE,
        "test_functions": TEST_FUNCTIONS_AVAILABLE,
        "validation_suite": VALIDATION_SUITE_AVAILABLE,
        "test_artifact_parser": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestArtifactParser", None) is not None,
        "test_evidence_packaging": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestEvidencePackagingScript", None) is not None,
        "test_memory_acquisition": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestMemoryAcquisitionScript", None) is not None,
        "test_network_state": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestNetworkStateScript", None) is not None,
        "test_volatile_data": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestVolatileDataScript", None) is not None,
        "test_evidence_integrity": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestEvidenceIntegrityFunctions", None) is not None
    }

def run_all_available_tests(output_format="text", output_file=None):
    """
    Run all available tests in the test suite.

    Args:
        output_format (str): Format for the test report ('text', 'json', 'junit', or 'markdown')
        output_file (str, optional): Path to save the test report

    Returns:
        bool: True if all tests passed, False otherwise
    """
    if not VALIDATION_SUITE_AVAILABLE:
        logging.error("Validation suite not available, cannot run tests")
        return False

    # Setup test environment
    cleanup_test_environment()
    setup_test_environment()

    # Import unittest for test execution
    import unittest

    # Create test suite
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    # Add available test classes
    if "TestArtifactParser" in globals() and ARTIFACT_PARSER_AVAILABLE:
        suite.addTest(loader.loadTestsFromTestCase(TestArtifactParser))
    if "TestEvidencePackagingScript" in globals() and EVIDENCE_PACKAGING_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestEvidencePackagingScript))
    if "TestMemoryAcquisitionScript" in globals() and MEMORY_ACQUISITION_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestMemoryAcquisitionScript))
    if "TestNetworkStateScript" in globals() and NETWORK_STATE_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestNetworkStateScript))
    if "TestVolatileDataScript" in globals() and VOLATILE_DATA_SCRIPT.exists():
        suite.addTest(loader.loadTestsFromTestCase(TestVolatileDataScript))
    if "TestEvidenceIntegrityFunctions" in globals() and FORENSIC_UTILS_AVAILABLE:
        suite.addTest(loader.loadTestsFromTestCase(TestEvidenceIntegrityFunctions))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Clean up after tests
    cleanup_test_environment()

    # Generate report if output file is specified
    if output_file and TEST_FUNCTIONS_AVAILABLE:
        generate_test_report(output_format, output_file)

    return result.wasSuccessful()

# Define module exports
__all__ = [
    # Version info
    '__version__',
    '__author__',

    # Module-level functions
    'get_available_tests',
    'run_all_available_tests'
]

# Add constant exports if available
if TEST_CONSTANTS_AVAILABLE:
    __all__.extend([
        # Test tracking variables
        'TEST_COUNT', 'TEST_PASS_COUNT', 'TEST_FAIL_COUNT', 'TEST_SKIP_COUNT', 'TEST_RESULTS',

        # Status constants
        'STATUS_PASS', 'STATUS_FAIL', 'STATUS_SKIP', 'STATUS_ERROR',

        # Test modes and verbosity
        'TEST_MODE_UNIT', 'TEST_MODE_INTEGRATION', 'TEST_MODE_ALL',
        'TEST_VERBOSITY_QUIET', 'TEST_VERBOSITY_NORMAL', 'TEST_VERBOSITY_VERBOSE', 'TEST_VERBOSITY_DEBUG',

        # Test file settings
        'DEFAULT_TEST_FILE_PERMS', 'DEFAULT_TEST_DIR_PERMS', 'TEST_HASH_ALGORITHMS',

        # Test case information
        'TEST_CASE_ID', 'TEST_EXAMINER', 'TEST_FILE_CONTENT',

        # Test directories
        'TEST_ROOT_DIR', 'TEST_DATA_DIR', 'TEST_OUTPUT_DIR', 'TEST_TEMP_DIR',

        # Test management functions
        'reset_test_counters', 'clear_test_results', 'get_test_summary', 'add_test_result',

        # Test evidence creation functions
        'create_test_evidence_file', 'create_test_evidence_directory',
        'get_test_metadata', 'write_test_metadata', 'calculate_test_file_hash'
    ])

# Add test function exports if available
if TEST_FUNCTIONS_AVAILABLE:
    __all__.extend([
        # Basic assertion functions
        'assert_equals', 'assert_not_equals', 'assert_contains', 'assert_success', 'assert_fail',
        'assert_file_exists', 'assert_file_not_exists', 'assert_dir_exists', 'assert_file_contains',
        'assert_var_defined', 'skip_test', 'verify_file_hash',

        # Test runner functions
        'run_test_function', 'run_all_tests', 'generate_test_report', 'parse_args', 'show_usage',

        # Logging functions
        'log_debug', 'log_info', 'log_success', 'log_warn', 'log_error', 'log_audit'
    ])

# Add validation suite exports if available
if VALIDATION_SUITE_AVAILABLE:
    __all__.extend([
        # Helper functions
        'run_script', 'setup_test_environment', 'cleanup_test_environment',

        # Test classes
        'TestArtifactParser', 'TestEvidencePackagingScript', 'TestMemoryAcquisitionScript',
        'TestNetworkStateScript', 'TestVolatileDataScript', 'TestEvidenceIntegrityFunctions',

        # Script paths
        'ARTIFACT_PARSER_SCRIPT', 'EVIDENCE_PACKAGING_SCRIPT', 'MEMORY_ACQUISITION_SCRIPT',
        'NETWORK_STATE_SCRIPT', 'VOLATILE_DATA_SCRIPT', 'COMMON_FUNCTIONS_SCRIPT',

        # Availability flags
        'ARTIFACT_PARSER_AVAILABLE', 'FORENSIC_UTILS_AVAILABLE'
    ])
