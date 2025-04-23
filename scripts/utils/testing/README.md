# Testing Utilities

## Overview

This directory contains comprehensive testing utilities for the Cloud Infrastructure Platform. These utilities provide a structured framework for running tests, collecting results, and generating reports in various formats.

## Key Scripts

- **`array_utils.sh`**: Utilities for array manipulation in tests
- **`file_helpers.sh`**: File operations and validations for tests
- **`string_utils.sh`**: String processing and validation functions
- **`test_common_functions.sh`**: Tests for the common functions library
- **`test_helpers.sh`**: Common helper functions used by testing utilities
- **`test_utils.sh`**: Main testing framework for running tests and generating reports
- **`timing_utils.sh`**: Performance measurement and timing functions

## Directory Structure

/scripts/utils/testing/
├── array_utils.sh          # Array manipulation utilities
├── file_helpers.sh         # File operation utilities
├── README.md               # This documentation
├── string_utils.sh         # String processing utilities
├── templates/              # Report templates
│   ├── html_report.html    # HTML report template
│   ├── junit.xml           # JUnit XML report template
│   └── text_report.txt     # Text report template
├── test_common_functions.sh # Tests for common functions
├── test_helpers.sh         # Common testing helper functions
└── test_utils.sh           # Main testing framework

## Configuration

The testing framework supports multiple configuration options:

- **Test Directory**: Where to find test files (`-dir`)
- **Test Pattern**: Filename pattern for test files (`-pattern`)
- **Output Format**: Report format - text, json, or junit/xml (`-format`)
- **Parallel Execution**: Number of parallel test jobs (`-parallel`)
- **Timeout**: Maximum test execution time in seconds (`-timeout`)

## Best Practices

- Organize tests into logical groups using `begin_test_group` and `end_test_group`
- Keep tests focused on a single functionality
- Use descriptive test names
- Leverage existing assertions (`assert_equals`, `assert_contains`, etc.)
- Register coverage for files being tested using `register_coverage`
- Set appropriate timeouts for potentially slow operations

## Security Considerations

- Never include credentials or sensitive information in test scripts
- Use environment variables for any required secrets
- Be careful with generated test data to avoid information disclosure
- Sanitize test outputs before logging or reporting

## Common Features

- Multiple report formats (text, JSON, JUnit/XML)
- Parallel test execution
- Flexible test discovery
- Comprehensive assertion library
- Test coverage tracking
- Mock functionality for unit testing

## Usage

```bash
# Source the test utilities in your test file
source "$(dirname "$0")/../utils/testing/test_utils.sh"

# Create a test group
begin_test_group "API Functions"

# Run individual tests
run_test "API Connection" "curl -s -o /dev/null -w '%{http_code}' <http://api.example.com/health> | grep -q 200"
run_test "Data Validation" "validate_response_data response.json"

# End the test group
end_test_group

# Run a test file
./scripts/utils/testing/test_utils.sh --dir ./tests/api --pattern "*_api_test.sh" --format junit --output junit-report.xml

```

## Assertion Examples

```bash
# Array assertions
assert_array_contains "${my_array[@]}" "expected_value" "Array should contain the value"
assert_array_size "${my_array[@]}" 3 "Array should have 3 elements"

# Basic assertions
assert_equals "$actual" "$expected" "Values should be equal"
assert_not_equals "$actual" "$forbidden" "Values should differ"
assert_contains "$haystack" "$needle" "String should contain substring"
assert_not_contains "$haystack" "$needle" "String should not contain substring"

# Exit code assertions
assert_success "some_command arg1 arg2" "Command should succeed"
assert_failure "invalid_command" "Command should fail"

# File assertions
assert_file_exists "/path/to/file" "File should exist"
assert_file_not_empty "/path/to/file" "File should have content"
assert_file_contains "/path/to/file" "expected content" "File should contain text"

# Numeric assertions
assert_greater_than "$value" "$minimum" "Value should exceed minimum"
assert_less_than "$value" "$maximum" "Value should be below maximum"

# String assertions
assert_string_matches "$value" "^[0-9]+$" "Value should contain only numbers"
assert_string_starts_with "$value" "prefix" "Value should start with prefix"

```

## Utility Functions

```bash
# Array utilities
array_contains "${array[@]}" "value"
array_join "${array[@]}" ","

# File operations
create_test_file "path/to/file" "content" "permissions"
compare_files "file1" "file2"
get_file_hash "path/to/file"

# String utilities
sanitize_string "$input"
to_lowercase "$string"
trim_whitespace "$string"

# Timing functions
measure_execution_time "command_to_measure"
wait_until_ready "service_check_command" 30

```

## Extending the Utilities

When adding new functionality:

1. Add new assertions to the appropriate module
2. Follow the established naming conventions
3. Include comprehensive documentation
4. Add unit tests for the new functionality
5. Update this README with examples

## Related Docs

- Test Writing Guide
- Continuous Integration Setup
- Mocking Best Practices
