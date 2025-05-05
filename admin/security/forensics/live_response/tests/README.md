# Live Response Forensic Toolkit Test Suite

This directory contains the test suite for the Live Response Forensic Toolkit, providing comprehensive testing capabilities to validate evidence collection, preservation, and integrity verification. The test suite implements both unit and integration tests with a focus on forensic soundness and proper evidence handling.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Test Configuration](#test-configuration)
- [Running Tests](#running-tests)
- [Creating New Tests](#creating-new-tests)
- [Test Assertions](#test-assertions)
- [Evidence Testing Utilities](#evidence-testing-utilities)
- [Chain of Custody Validation](#chain-of-custody-validation)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

The test suite validates the functionality, reliability, and forensic integrity of the Live Response Forensic Toolkit. It implements tests for memory acquisition, volatile data collection, network state analysis, evidence packaging, and evidence integrity verification to ensure the toolkit meets forensic standards and legal requirements for evidence admissibility.

## Key Components

- **`test_constants.py`**: Shared constants, variables, and utility functions for testing
  - Defines test paths and directories
  - Provides evidence creation utilities
  - Maintains test result tracking
  - Establishes security-oriented file permissions

- **`test_functions.py`**: Core test utility functions and assertions
  - Implements forensic-specific assertions
  - Provides file integrity verification
  - Includes command execution validation
  - Offers reporting capabilities

- **`validation_suite.py`**: Integration tests for toolkit components
  - Tests artifact parser functionality
  - Validates evidence packaging
  - Verifies memory acquisition
  - Tests network state collection
  - Validates volatile data collection

- **`__init__.py`**: Package initialization and exports
  - Exposes test utilities
  - Provides test discovery and execution
  - Creates a unified interface for the test suite

## Directory Structure

```plaintext
admin/security/forensics/live_response/tests/
├── README.md                  # This documentation
├── __init__.py                # Package initialization and exports
├── common_functions.sh        # Shared shell functions for tests
├── test_constants.py          # Constants for testing environment
├── test_functions.py          # Test utility functions
├── test_functions.sh          # Shell-based test utilities
├── validation_suite.py        # Integration tests
├── test_data/                 # Test data files
│   ├── evidence_source/       # Source files for evidence tests
│   ├── integrity/             # Test files for integrity checking
│   ├── network_state/         # Sample network data
│   └── process_info/          # Test process data
└── test_output/               # Directory for test results
```

## Test Configuration

The test suite uses several configuration variables that can be customized through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_VERBOSITY` | Controls logging verbosity | `normal` |
| `TEST_MODE` | Test execution mode | `all` |
| `TEST_OUTPUT_DIR` | Directory for test output | `tests/test_output` |
| `TEST_DATA_DIR` | Directory with test data | `tests/test_data` |

## Running Tests

To run the entire test suite:

```bash
# Run all tests
python -m admin.security.forensics.live_response.tests

# Run with specific verbosity level
TEST_VERBOSITY=verbose python -m admin.security.forensics.live_response.tests

# Run specific test categories
python -m admin.security.forensics.live_response.tests --test "test_artifact_parser*"

# Generate test report
python -m admin.security.forensics.live_response.tests --report json --output report.json
```

## Creating New Tests

When creating new tests, follow these guidelines:

1. Use the utilities from `test_functions.py` for assertions
2. Create proper test evidence with `create_test_evidence_file()`
3. Follow the order of volatility for testing evidence collection
4. Always clean up any files created during tests
5. Document test methods with clear docstrings
6. Use `@unittest.skipIf` or `@unittest.skipUnless` for conditional tests

Example test structure:

```python
import unittest
from admin.security.forensics.live_response.tests import (
    assert_equals, assert_file_exists, create_test_evidence_file,
    TEST_OUTPUT_DIR
)

class TestMyComponent(unittest.TestCase):
    """Tests for my component functionality."""

    def setUp(self):
        """Set up test environment."""
        self.evidence_file = create_test_evidence_file(
            TEST_OUTPUT_DIR,
            "test_evidence.txt",
            "Sample evidence content"
        )

    def test_my_function(self):
        """Test specific functionality."""
        # Test implementation
        assert_file_exists(self.evidence_file)
```

## Test Assertions

The test suite provides specialized assertions for forensic testing:

| Assertion | Purpose |
|-----------|---------|
| `assert_equals` | Assert that values match |
| `assert_not_equals` | Assert that values differ |
| `assert_contains` | Assert string contains substring |
| `assert_success` | Assert command executes successfully |
| `assert_fail` | Assert command fails expectedly |
| `assert_file_exists` | Assert evidence file exists |
| `assert_file_not_exists` | Assert file doesn't exist |
| `assert_dir_exists` | Assert directory exists |
| `assert_file_contains` | Assert file contains content |
| `verify_file_hash` | Validate file integrity |

## Evidence Testing Utilities

The test suite provides utilities for creating and verifying test evidence:

```python
# Create test evidence file
evidence_file = create_test_evidence_file(TEST_OUTPUT_DIR, "evidence.txt")

# Create test evidence directory with proper permissions
evidence_dir = create_test_evidence_directory(TEST_OUTPUT_DIR, "evidence_dir")

# Generate test metadata
metadata = get_test_metadata()

# Write metadata to a file
metadata_file = write_test_metadata(TEST_OUTPUT_DIR, metadata)

# Calculate file hash for integrity verification
file_hash = calculate_test_file_hash(evidence_file, "sha256")
```

## Chain of Custody Validation

The test suite includes capabilities for validating chain of custody features:

1. Creation of evidence containers
2. Proper metadata association
3. Hash verification for evidence integrity
4. Evidence registration workflow
5. Chain of custody documentation

Example test for evidence integrity:

```python
def test_evidence_integrity_verification(self):
    """Test evidence integrity verification."""
    # Create baseline
    success, baseline_path = update_evidence_integrity_baseline(
        evidence_dir=self.evidence_dir,
        output_path=self.baseline_path,
        case_id="TEST-CASE-001",
        examiner="Test Examiner"
    )
    self.assertTrue(success)

    # Verify against baseline
    verified, results = verify_evidence_integrity(
        evidence_dir=self.evidence_dir,
        baseline_path=baseline_path
    )
    self.assertTrue(verified)
```

## Best Practices & Security

- **Evidence Handling**: Treat test evidence like real evidence
- **Permission Management**: Always use secure permissions for evidence files
- **Cleanup**: Clean up all test artifacts after tests complete
- **Isolation**: Keep test evidence isolated from real data
- **Validation**: Verify integrity of all evidence created during tests
- **Documentation**: Document all test methods thoroughly
- **Logging**: Maintain detailed logs of test execution
- **Separation**: Keep test data separate from test output
- **Dependencies**: Document and verify tool dependencies
- **Error Handling**: Gracefully handle missing tools or dependencies

## Related Documentation

- Live Response Forensic Toolkit
- Evidence Handling Guidelines
- Usage Guide
- Chain of Custody Documentation
- Digital Forensics Procedures
- Live Response Configuration
