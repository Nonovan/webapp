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

        # Test management functions
        reset_test_counters,
        clear_test_results,
        get_test_summary,
        add_test_result
    )
    TEST_CONSTANTS_AVAILABLE = True
except ImportError as e:
    import logging
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
    )
    TEST_FUNCTIONS_AVAILABLE = True
except ImportError as e:
    import logging
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

        # Constants
        TEST_DATA_DIR,
        TEST_OUTPUT_DIR,
        ARTIFACT_PARSER_SCRIPT,
        EVIDENCE_PACKAGING_SCRIPT,
        MEMORY_ACQUISITION_SCRIPT,
        NETWORK_STATE_SCRIPT,
        VOLATILE_DATA_SCRIPT
    )
    VALIDATION_SUITE_AVAILABLE = True
except ImportError as e:
    import logging
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
        "test_volatile_data": VALIDATION_SUITE_AVAILABLE and getattr(sys.modules.get(__name__, {}), "TestVolatileDataScript", None) is not None
    }

def run_all_available_tests(output_format="text", output_file=None):
    """
    Run all available tests in the test suite.

    Args:
        output_format (str): Format for the test report ('text', 'json', or 'junit')
        output_file (str, optional): Path to save the test report

    Returns:
        bool: True if all tests passed, False otherwise
    """
    if not VALIDATION_SUITE_AVAILABLE:
        import logging
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
    if "TestArtifactParser" in globals():
        suite.addTest(loader.loadTestsFromTestCase(TestArtifactParser))
    if "TestEvidencePackagingScript" in globals():
        suite.addTest(loader.loadTestsFromTestCase(TestEvidencePackagingScript))
    if "TestMemoryAcquisitionScript" in globals():
        suite.addTest(loader.loadTestsFromTestCase(TestMemoryAcquisitionScript))
    if "TestNetworkStateScript" in globals():
        suite.addTest(loader.loadTestsFromTestCase(TestNetworkStateScript))
    if "TestVolatileDataScript" in globals():
        suite.addTest(loader.loadTestsFromTestCase(TestVolatileDataScript))

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
        'TEST_COUNT', 'TEST_PASS_COUNT', 'TEST_FAIL_COUNT', 'TEST_SKIP_COUNT', 'TEST_RESULTS',
        'STATUS_PASS', 'STATUS_FAIL', 'STATUS_SKIP', 'STATUS_ERROR',
        'TEST_MODE_UNIT', 'TEST_MODE_INTEGRATION', 'TEST_MODE_ALL',
        'TEST_VERBOSITY_QUIET', 'TEST_VERBOSITY_NORMAL', 'TEST_VERBOSITY_VERBOSE', 'TEST_VERBOSITY_DEBUG',
        'reset_test_counters', 'clear_test_results', 'get_test_summary', 'add_test_result'
    ])

# Add test function exports if available
if TEST_FUNCTIONS_AVAILABLE:
    __all__.extend([
        'assert_equals', 'assert_not_equals', 'assert_contains', 'assert_success', 'assert_fail',
        'assert_file_exists', 'assert_file_not_exists', 'assert_dir_exists', 'assert_file_contains',
        'assert_var_defined', 'skip_test', 'verify_file_hash',
        'run_test_function', 'run_all_tests', 'generate_test_report', 'parse_args'
    ])

# Add validation suite exports if available
if VALIDATION_SUITE_AVAILABLE:
    __all__.extend([
        'run_script', 'setup_test_environment', 'cleanup_test_environment',
        'TestArtifactParser', 'TestEvidencePackagingScript', 'TestMemoryAcquisitionScript',
        'TestNetworkStateScript', 'TestVolatileDataScript',
        'TEST_ROOT_DIR', 'TEST_DATA_DIR', 'TEST_OUTPUT_DIR', 'TEST_TEMP_DIR', 'ARTIFACT_PARSER_SCRIPT', 'EVIDENCE_PACKAGING_SCRIPT',
        'MEMORY_ACQUISITION_SCRIPT', 'NETWORK_STATE_SCRIPT', 'VOLATILE_DATA_SCRIPT'
    ])
