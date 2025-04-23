# Testing Framework Modules

## Overview

This directory contains core module files for the Cloud Infrastructure Platform's testing framework. These modules provide the foundation for test execution, assertions, mocking, reporting, and system testing capabilities that can be used across the platform.

## Key Modules

- **`assertions.sh`**: Comprehensive assertion library for validating test expectations
- **`core.sh`**: Core testing framework providing test group management, test execution, and fundamental utilities
- **`mocking.sh`**: Mocking framework for creating test environments and simulating dependencies
- **`reporting.sh`**: Report generation in various formats (text, JSON, JUnit/XML)
- **`system.sh`**: Utilities for testing system-level components like ports, processes, and connectivity

## Directory Structure

scripts/utils/modules/
├── assertions.sh      # Assertion utilities for verifying test conditions
├── core.sh            # Core testing functionality and test execution
├── mocking.sh         # Mock functionality for unit testing
├── README.md          # This documentation
├── reporting.sh       # Report generation in various formats
└── system.sh          # System testing utilities

## Configuration

The module framework supports configuration through environment variables:

- **LOG_LEVEL**: Controls verbosity of logging (DEBUG, INFO, WARN, ERROR)
- **TEST_TIMEOUT**: Default timeout for test operations in seconds
- **TEST_TEMP_DIR**: Directory to use for temporary test files

## Best Practices & Security

- Always source `core.sh` before other modules
- Use proper cleanup handlers with `trap` to ensure resource cleanup
- Avoid using test modules in production environments
- Validate all inputs to prevent script injection
- Use secure temporary directories for test data

## Common Features

- Cross-platform compatibility (Linux, macOS)
- Detailed logging with different levels (INFO, DEBUG, ERROR)
- Modular design allowing selective inclusion
- Self-test capabilities when run directly
- Comprehensive documentation and examples
- Secure handling of test resources

## Usage

```bash
# Source the core module (required by most other modules)
source "$(dirname "$0")/../../utils/modules/core.sh"

# Source additional modules as needed
source "$(dirname "$0")/../../utils/modules/assertions.sh"
source "$(dirname "$0")/../../utils/modules/reporting.sh"

# Create a test group
begin_test_group "Example Tests"

# Run test with assertions
run_test "Example test" "
  assert_equals 'actual' 'expected' 'Values should match'
"

# End test group
end_test_group

# Generate a report
generate_report "junit" "test-results.xml"

```

## Module Dependencies

- **`assertions.sh`**: Depends on `core.sh`
- **`core.sh`**: No dependencies, must be loaded first
- **`mocking.sh`**: Depends on `core.sh`
- **`reporting.sh`**: Depends on `core.sh`
- **`system.sh`**: Depends on `core.sh`

## Related Documentation

- Test Utilities
- Common Utilities
- Testing Guide

## Version History

- **1.0.1 (2023-12-20)**: Added improved system testing capabilities
- **1.0.0 (2023-12-01)**: Initial release of testing framework modules
