```markdown
# Testing Utilities

## Overview
This directory contains comprehensive testing utilities for the Cloud Infrastructure Platform. These utilities provide a structured framework for running tests, collecting results, and generating reports in various formats.

## Key Scripts
- **`test_utils.sh`**: Main testing framework for running tests and generating reports
- **`test_helpers.sh`**: Common helper functions used by testing utilities

## Directory Structure
/scripts/utils/testing/
├── test_utils.sh           # Main testing framework
├── test_helpers.sh         # Common testing helper functions
├── README.md               # This documentation
└── templates/              # Report templates
    ├── junit.xml           # JUnit XML report template
    ├── html_report.html    # HTML report template
    └── text_report.txt     # Text report template

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
test_utils.sh --dir ./tests/api --pattern "*_api_test.sh" --format junit --output junit-report.xml

```

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

## Common Features

- Multiple report formats (text, JSON, JUnit/XML)
- Parallel test execution
- Flexible test discovery
- Comprehensive assertion library
- Test coverage tracking
- Mock functionality for unit testing
